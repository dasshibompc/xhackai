"""The adversarial validator: the component that decides what deserves a human's
attention. Two stages:

1. DETERMINISTIC: re-run the matching probe on the recorded evidence. A finding
   that no longer reproduces is dead — no LLM needed.
2. ADVERSARIAL: a fresh LLM context argues AGAINST the finding (false positive?
   expected behavior? honeypot? misleading signal?). Its objections and the
   original evidence go to the human when confidence survives.

The agent has no path to "submitted" — the validator only promotes findings to
`validated` for human review.
"""
from __future__ import annotations

import json
from typing import Any

import os

from ..db import Database
from ..errors import AgentError
from ..llm.provider import LLMProvider, extract_json
from ..scope.client import EnforcingClient
from ..scope.rulebook import Rulebook
from .prompts import VALIDATOR_SYSTEM

# Precision-first default: a finding needs strong adversarial agreement to be
# surfaced for submission. Lower it (e.g. 0.6) to trade FP risk for recall.
MIN_VALIDATE_CONFIDENCE = float(os.environ.get("AGENT_VALIDATE_MIN_CONFIDENCE", "0.75"))

# probe function lookup happens lazily to avoid a circular import with probes
_PROBE_MAP = {
    "Reflected XSS/SSTI (probe)": ("xss", ("url", "param")),
    "SQL Injection (probe)": ("sqli", ("url", "param")),
    "Open Redirect (probe)": ("redirect", ("url", "param")),
    "SSRF (probe)": ("ssrf", ("url", "param")),
}


def _rerun_probe(finding_row, client: EnforcingClient) -> dict[str, Any]:
    from ..hunt.payloads import fresh_marker  # noqa: F401 — marker logic lives in probes
    from ..hunt.probes import probe_reflection, probe_redirect, probe_sqli, probe_ssrf

    evidence = json.loads(finding_row["evidence"]) if isinstance(finding_row["evidence"], str) else dict(finding_row["evidence"])
    url = finding_row["url"]
    param = finding_row["parameter"] or ""
    map_entry = _PROBE_MAP.get(finding_row["vuln_type"])
    if map_entry is None:
        return {"ok": False, "error": "no deterministic probe for this type"}
    cls, _fields = map_entry
    method = str(evidence.get("method", "GET")).upper()
    port = int(evidence.get("port", 80))
    try:
        if cls == "xss":
            return probe_reflection(client, url, param)
        if cls == "sqli":
            return probe_sqli(client, url, param, method=method)
        if cls == "redirect":
            return probe_redirect(client, url, param)
        if cls == "ssrf":
            return probe_ssrf(client, url, param, port=port)
    except AgentError as exc:
        return {"ok": False, "error": f"scope/agent error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"probe error: {exc}"}
    return {"ok": False, "error": "unreachable"}


class Validator:
    def _list_candidates(self, db: Database):
        return [r for r in db.list_findings() if r["status"] == "candidate"]

    def validate_all(self, db: Database, provider: LLMProvider,
                     client: EnforcingClient, rulebook: Rulebook) -> dict:
        stats = {"verified": 0, "replicated": 0, "failed_repro": 0,
                 "debated": 0, "upgraded": 0, "downgraded": 0, "rejected": 0}
        for row in self._list_candidates(db):
            fid = row["id"]
            # ---- stage 1: deterministic reproduction (types without a probe
            # become 'unverifiable' — they stay visible for human review)
            repro = _rerun_probe(row, client)
            if not repro.get("ok"):
                db.conn.execute(
                    "UPDATE findings SET status='unverifiable', confidence=confidence*0.5 WHERE id=?",
                    (fid,),
                )
                db.conn.commit()
                stats["failed_repro"] += 1
                continue
            stats["replicated"] += 1
            evidence = json.loads(row["evidence"]) if isinstance(row["evidence"], str) else dict(row["evidence"])
            evidence["revalidation"] = repro
            # ---- stage 2: adversarial debate (any failure degrades to
            # needs-review, never crashes the run)
            verdict: dict[str, Any] = {}
            debate_payload = json.dumps({
                "vuln_type": row["vuln_type"], "url": row["url"],
                "param": row["parameter"], "evidence": evidence,
            }, indent=1)[:6000]
            try:
                reply = provider.chat(VALIDATOR_SYSTEM, debate_payload)
                try:
                    verdict = extract_json(reply)
                except Exception:  # noqa: BLE001 — one repair retry for malformed JSON
                    reply = provider.chat(
                        VALIDATOR_SYSTEM,
                        debate_payload + "\n\nYour previous reply was not valid JSON: "
                        f"{reply[:200]}. Reply again with ONLY the JSON object.",
                    )
                    verdict = extract_json(reply)
                stats["debated"] += 1
            except Exception as exc:  # noqa: BLE001
                verdict = {"is_vulnerability": "uncertain", "confidence": 0.4,
                           "reasoning": f"validator LLM unavailable: {str(exc)[:200]}"}
            # the debate transcript is part of the evidence the human reviews
            evidence["debate"] = {
                k: verdict.get(k) for k in
                ("is_vulnerability", "confidence", "objections",
                 "what_would_convince_me", "reasoning")
                if verdict.get(k) is not None
            }
            confidence = float(verdict.get("confidence", 0.5))
            is_vuln = str(verdict.get("is_vulnerability", "uncertain")).lower()
            if is_vuln == "yes" and confidence >= MIN_VALIDATE_CONFIDENCE:
                new_status, new_conf = "validated", max(MIN_VALIDATE_CONFIDENCE, confidence)
                stats["upgraded"] += 1
            elif is_vuln == "no" and confidence >= 0.7:
                new_status, new_conf = "rejected", confidence
                stats["rejected"] += 1
            else:
                new_status, new_conf = "needs-review", min(max(confidence, 0.3),
                                                             MIN_VALIDATE_CONFIDENCE - 0.01)
                stats["downgraded"] += 1
            db.conn.execute(
                "UPDATE findings SET status=?, confidence=?, evidence=? WHERE id=?",
                (new_status, new_conf, json.dumps(evidence), fid),
            )
            db.conn.commit()
            stats["verified"] += 1
        return stats
