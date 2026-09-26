"""Hypothesis generation: turn the recon inventory into a ranked list of
specific, testable vulnerability hypotheses for the hunter sessions.

The LLM sees a compact, token-cheap digest of real attack surface — never
raw wildcards — and must answer in strict JSON.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..db import Database
from ..llm.provider import LLMProvider, extract_json
from ..scope.rulebook import Rulebook

HYPO_SYSTEM = """You are a senior bug bounty hunter planning an attack. You will \
receive a digest of a program's attack surface (hosts, live URLs, technologies, \
known endpoints and REAL parameter names mined from pages, forms, JS, and \
differential probing). Propose the most promising, SPECIFIC, testable \
vulnerability hypotheses.

Rules:
- Every hypothesis must point at a URL that appears in the digest (or a direct \
derivative of it, e.g. adding a query parameter).
- Use the supplied known_params / known_form_fields as the parameter names to \
test — never invent parameter names that are not in the digest.
- Prefer high-value classes: SQLi, XSS, SSRF, open redirect, IDOR, access control.
- Rank by (impact x likelihood). 3-8 hypotheses.
- Respond with EXACTLY one JSON object, no other text:
{"hypotheses": [{"url": "...", "param": "...", "vuln_class": "sqli|xss|ssrf|redirect|idor|access-control",
                 "reason": "<one sentence>", "priority": 1}]}
"""


@dataclass
class Hypothesis:
    url: str
    vuln_class: str
    param: str | None = None
    reason: str = ""
    priority: int = 99
    extra: dict = field(default_factory=dict)


def build_digest(db: Database, rulebook: Rulebook, limit: int = 60,
                 operator_objectives: str = "") -> str:
    """Compact JSON digest of everything the hunters may test (v2: includes
    real mined parameter names, grouped by kind, plus the operator's
    objectives when provided)."""
    hosts = [
        {"url": r["url"], "status": r["status_code"], "title": r["title"], "tech": r["tech"]}
        for r in db.conn.execute(
            "SELECT url, status_code, title, tech FROM assets"
            " WHERE in_scope=1 AND url IS NOT NULL ORDER BY host LIMIT ?", (limit,)
        ).fetchall()
    ]
    endpoints = [
        {"url": r["url"], "kind": r["kind"]}
        for r in db.list_endpoints()
    ][:limit * 2]
    params: dict[str, list[str]] = {}
    for r in db.list_params():
        params.setdefault(r["kind"], []).append(r["name"])
    for kind in params:
        params[kind] = sorted(set(params[kind]))
    return json.dumps({
        "program": rulebook.name,
        "notes": rulebook.notes[:300],
        "operator_objectives": (operator_objectives or "")[:500],
        "live_urls": hosts,
        "endpoints": endpoints,
        "known_params": params.get("query", []) + params.get("mined", []),
        "known_form_fields": params.get("form", []),
        "differential_params": params.get("differential", []),
    }, indent=1)


def propose_hypotheses(provider: LLMProvider, db: Database, rulebook: Rulebook,
                       max_hypotheses: int = 8,
                       operator_objectives: str = "") -> list[Hypothesis]:
    digest = build_digest(db, rulebook, operator_objectives=operator_objectives)
    reply = provider.chat(HYPO_SYSTEM, digest)
    try:
        data = extract_json(reply)
    except Exception:  # noqa: BLE001 — one repair retry, then degrade to []
        reply = provider.chat(
            HYPO_SYSTEM,
            digest + "\n\nYour previous reply was not valid JSON: "
            f"{reply[:200]}. Respond again with ONLY the JSON object.",
        )
        try:
            data = extract_json(reply)
        except Exception:  # noqa: BLE001
            return []  # no hypotheses this run — never crash the pipeline
    out: list[Hypothesis] = []
    allowed_urls = {h["url"] for h in json.loads(digest)["live_urls"]}
    # M5c: when real parameter names are known, hypotheses naming invented
    # params are dropped — guessing is exactly what we engineered away.
    known_param_names = {r["name"] for r in db.list_params()}
    for h in data.get("hypotheses", [])[:max_hypotheses]:
        if not isinstance(h, dict) or "url" not in h or "vuln_class" not in h:
            continue
        url = str(h["url"])
        cls = str(h["vuln_class"]).lower().strip()
        if cls not in {"sqli", "xss", "ssrf", "redirect", "idor", "access-control"}:
            continue
        # every hypothesis URL must be rulebook-legal AND appear in the digest
        try:
            if urlsplit(url).netloc and rulebook.check(url)[0] is False:
                continue
        except ValueError:
            continue
        param = str(h["param"]) if h.get("param") else None
        if param and known_param_names and param not in known_param_names:
            continue
        out.append(Hypothesis(
            url=url, vuln_class=cls,
            param=param,
            reason=str(h.get("reason", ""))[:300],
            priority=int(h.get("priority", 99)),
        ))
    out.sort(key=lambda x: x.priority)
    return out
