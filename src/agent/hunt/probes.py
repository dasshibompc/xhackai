"""Deterministic probe tools: one hypothesis in, evidence out.

Each probe is a plain function (usable directly by the validator and tests) and
has a Tool wrapper (callable by LLM hunter sessions). All network access goes
through the EnforcingClient; payloads are minimal and non-destructive.
"""
from __future__ import annotations

import urllib.parse
from typing import Any

import httpx

from ..db import Database
from ..errors import AgentError
from ..scope.client import EnforcingClient
from ..tools import Tool, ToolResult
from .payloads import (
    REDIRECT_PAYLOADS,
    SSRF_BODY_MARKERS,
    SSRF_PAYLOADS,
    XSS_PROBES,
    find_error_signatures,
    fresh_marker,
)


def _inject(url: str, param: str, value: str) -> str:
    """Set `param` to `value` on `url`, preserving other query parameters."""
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, v) for k, v in q if k != param] + [(param, value)]
    return urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urllib.parse.urlencode(q), parts.fragment,
    ))


def probe_reflection(client: EnforcingClient, url: str, param: str,
                     extra_payloads: list[str] | None = None) -> dict[str, Any]:
    """Marker-reflection probe (XSS/SSTI). Deterministic: unique marker per run."""
    marker = fresh_marker()
    payloads = [p.replace("{marker}", marker) for p in XSS_PROBES]
    if extra_payloads:
        payloads += [p.replace("{marker}", marker) for p in extra_payloads]

    baseline_url = _inject(url, param, "baselineprobe")
    try:
        base = client.get(baseline_url)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"baseline request failed: {exc}"}
    if marker in base.text:
        return {"ok": False, "error": "marker collides with baseline page"}

    reflected: list[dict[str, Any]] = []
    for payload in payloads:
        try:
            resp = client.get(_inject(url, param, payload))
        except Exception:  # noqa: BLE001 — one bad request must not kill the probe
            continue
        raw = marker in resp.text
        if raw:
            reflected.append({
                "payload": payload,
                "context": "raw",  # unfiltered reflection — highest signal
            })
        elif "49" in resp.text and payload == "{{7*7}}":
            reflected.append({"payload": payload, "context": "ssti-eval"})
    return {
        "ok": True,
        "vulnerable": bool(reflected),
        "marker": marker,
        "param": param,
        "reflections": reflected,
        "note": "raw reflection confirms injection point; browser-context analysis needed for XSS impact",
    }


def probe_sqli(client: EnforcingClient, url: str, param: str,
               method: str = "GET") -> dict[str, Any]:
    """Error-based / boolean-differential SQLi probe (GET query or POST form)."""

    def send(value: str) -> httpx.Response:
        if method.upper() == "POST":
            return client.post(url, data={param: value})
        return client.get(_inject(url, param, value))

    evidence_errors: list[str] = []
    responses: dict[str, int] = {}
    for payload, purpose in [
        ("1 AND 1=1", "true"), ("1 AND 1=2", "false"),
    ]:
        try:
            resp = send(payload)
            responses[purpose] = len(resp.text)
            evidence_errors += find_error_signatures(resp.text)
        except Exception:  # noqa: BLE001
            return {"ok": False, "error": "request failed during boolean pair"}
    try:
        err_resp = send("'")
        evidence_errors += find_error_signatures(err_resp.text)
    except Exception:  # noqa: BLE001
        pass
    differential = (
        len(responses) == 2 and abs(responses["true"] - responses["false"]) > 50
    )
    return {
        "ok": True,
        "vulnerable": bool(evidence_errors) or differential,
        "signal": "sql-error-signature" if evidence_errors else (
            "boolean-differential" if differential else "none"
        ),
        "signatures_found": sorted(set(evidence_errors)),
        "response_lengths": responses,
        "param": param,
    }


def probe_redirect(client: EnforcingClient, url: str, param: str) -> dict[str, Any]:
    """Open redirect probe: Location header must leave the origin authority."""
    origin = urllib.parse.urlsplit(url).netloc
    hits: list[dict[str, Any]] = []
    for payload in REDIRECT_PAYLOADS:
        try:
            resp = client.get(_inject(url, param, payload))
        except Exception:  # noqa: BLE001
            continue
        loc = resp.headers.get("location", "")
        if not loc:
            continue
        target = urllib.parse.urlsplit(loc)
        if target.netloc and target.netloc != origin.split(":")[0]:
            hits.append({"payload": payload, "location": loc})
    return {"ok": True, "vulnerable": bool(hits), "redirects": hits, "param": param}


def probe_ssrf(client: EnforcingClient, url: str, param: str,
               oob_domain: str | None = None, port: int = 80) -> dict[str, Any]:
    """SSRF probe. Evidence = known body markers OR a control differential
    (internal URL returns content while a control URL fails)."""
    baseline_body: str | None = None
    try:
        baseline = client.get(_inject(url, param, "http://ssrf-control.invalid/"))
        baseline_body = baseline.text
    except Exception:  # noqa: BLE001
        pass
    hits: list[dict[str, Any]] = []
    for template, label in SSRF_PAYLOADS:
        target = template.replace("{port}", str(port))
        try:
            resp = client.get(_inject(url, param, target))
        except Exception:  # noqa: BLE001
            continue
        body_markers = [m for m in SSRF_BODY_MARKERS if m in resp.text]
        differential = (
            baseline_body is not None and resp.status_code == 200
            and bool(resp.text.strip()) and resp.text != baseline_body
        )
        if body_markers or differential:
            hits.append({"payload": target, "label": label,
                         "body_markers": body_markers,
                         "differential": differential})
    oob_hit = None
    if oob_domain:
        try:
            resp = client.get(_inject(url, param, f"https://{oob_domain}/"))
            if resp.status_code < 400:
                oob_hit = {"payload": f"https://{oob_domain}/",
                           "note": "server fetched OOB URL (HTTP-level; verify callback in interactsh)"}
        except Exception:  # noqa: BLE001
            pass
    return {"ok": True, "vulnerable": bool(hits or oob_hit),
            "internal_hits": hits, "oob": oob_hit, "param": param}


def probe_idor(client: EnforcingClient, url_template: str,
               id_a: str, id_b: str, headers_b: dict[str, str] | None = None) -> dict[str, Any]:
    """IDOR probe: object A fetched with (no auth | user B context) must differ
    from 403/404 and match A's known content marker."""
    url_a = url_template.format(id=id_a)
    url_b = url_template.format(id=id_b)
    try:
        resp = client.get(url_b, headers=headers_b)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"request failed: {exc}"}
    if resp.status_code in (401, 403, 404):
        return {"ok": True, "vulnerable": False,
                "note": f"access denied to foreign object ({resp.status_code})"}
    try:
        resp_a = client.get(url_a, headers=headers_b)
        same_as_own = resp_a.status_code == resp.status_code and len(resp_a.text) == len(resp.text)
    except Exception:  # noqa: BLE001
        same_as_own = False
    return {
        "ok": True,
        "vulnerable": True,
        "note": "foreign object returned without denial — confirm ownership semantics",
        "status": resp.status_code,
        "foreign_url": url_b,
        "behaves_like_own_object": same_as_own,
    }


# --------------------------------------------------------------------- tools

class ProbeTool(Tool):
    """Base for LLM-callable probes. Subclasses set probe_name + fn."""

    probe_name: str = ""
    needs_client = True

    def __init__(self, client: EnforcingClient, db: Database) -> None:
        self.client = client
        self.db = db

    def _store(self, url: str, param: str, evidence: dict[str, Any]) -> ToolResult:
        if not evidence.get("ok"):
            return ToolResult(False, f"probe failed: {evidence.get('error')}")
        if not evidence.get("vulnerable"):
            # precision-first: negative results are history, not candidates
            return ToolResult(True, "not vulnerable — no finding recorded")
        fid = self.db.add_finding(
            vuln_type=self.probe_name, url=url, parameter=param,
            evidence=evidence, confidence=0.7, status="candidate",
        )
        return ToolResult(True, f"evidence stored as finding #{fid} "
                                f"(candidate — awaits adversarial validation)")


class XssProbeTool(ProbeTool):
    name = "probe_xss"
    description = ("Test whether a URL parameter reflects injected markup raw "
                   "(XSS/SSTI). Args: url, param.")
    probe_name = "Reflected XSS/SSTI (probe)"

    def run(self, url: str, param: str) -> ToolResult:
        try:
            ev = probe_reflection(self.client, url, param)
        except AgentError as exc:
            return ToolResult(False, str(exc))
        return self._store(url, param, ev)


class SqliProbeTool(ProbeTool):
    name = "probe_sqli"
    description = ("Test a URL parameter for SQL injection via error signatures "
                   "and boolean differential. Args: url, param [, method=GET|POST].")
    probe_name = "SQL Injection (probe)"

    def run(self, url: str, param: str, method: str = "GET") -> ToolResult:
        try:
            ev = probe_sqli(self.client, url, param, method=method.upper())
        except AgentError as exc:
            return ToolResult(False, str(exc))
        ev["method"] = method.upper()
        return self._store(url, param, ev)


class RedirectProbeTool(ProbeTool):
    name = "probe_redirect"
    description = ("Test whether a URL parameter allows redirecting off-site. "
                   "Args: url, param.")
    probe_name = "Open Redirect (probe)"

    def run(self, url: str, param: str) -> ToolResult:
        try:
            ev = probe_redirect(self.client, url, param)
        except AgentError as exc:
            return ToolResult(False, str(exc))
        return self._store(url, param, ev)


class SsrfProbeTool(ProbeTool):
    name = "probe_ssrf"
    description = ("Test whether a URL parameter makes the server fetch attacker-"
                   "controlled URLs (internal + OOB). Args: url, param "
                   "[, oob_domain from interactsh_payloads] [, port].")
    probe_name = "SSRF (probe)"

    def run(self, url: str, param: str, oob_domain: str | None = None,
            port: int = 80) -> ToolResult:
        try:
            ev = probe_ssrf(self.client, url, param, oob_domain=oob_domain, port=int(port))
        except AgentError as exc:
            return ToolResult(False, str(exc))
        ev["port"] = int(port)
        return self._store(url, param, ev)


class IdorProbeTool(ProbeTool):
    name = "probe_idor"
    description = ("Test whether an object URL like https://host/api/user/{id} "
                   "returns another user's object without denial. Args: "
                   "url_template, id_a, id_b.")
    probe_name = "IDOR (probe)"

    def run(self, url_template: str, id_a: str, id_b: str) -> ToolResult:
        try:
            ev = probe_idor(self.client, url_template, id_a, id_b)
        except AgentError as exc:
            return ToolResult(False, str(exc))
        return self._store(url_template, "id", ev)


def build_probe_tools(client: EnforcingClient, db: Database) -> dict[str, Tool]:
    tools = [XssProbeTool(client, db), SqliProbeTool(client, db),
             RedirectProbeTool(client, db), SsrfProbeTool(client, db),
             IdorProbeTool(client, db)]
    return {t.name: t for t in tools}
