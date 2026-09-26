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
from ..oob.interactsh import FakeInteractshManager, InteractshManager
from ..scope.auth import AuthError, AuthSpec
from ..scope.client import EnforcingClient
from ..scope.rulebook import Rulebook
from .prompts import VALIDATOR_SYSTEM
from ..hunt.lessons import tag_rejection  # M5e: rejections become hunt memory

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

# M4: access-matrix findings are re-verified by re-running the full matrix
_MATRIX_TYPES = {
    "IDOR (cross-account matrix)",
    "Access control (probable IDOR matrix)",
}

# M5d: chain findings are re-verified by re-executing the whole chain spec
_CHAIN_TYPES = {"Access control (chained)"}


def _rerun_chain_probe(finding_row, client: EnforcingClient, db: Database,
                       rulebook: Rulebook | None) -> dict[str, Any]:
    """Stage-1 re-verification for chain findings: re-execute the stored spec.
    Note: create steps run again (one extra object per validation) — recorded
    in the evidence bundle for the human."""
    from ..hunt.chains import ChainRunner
    evidence = db.evidence_of(finding_row) if db is not None else (
        json.loads(finding_row["evidence"]) if isinstance(finding_row["evidence"], str) else dict(finding_row["evidence"]))
    spec = evidence.get("chain")
    if not isinstance(spec, dict) or not spec.get("steps"):
        return {"ok": False, "error": "chain evidence missing runnable spec"}
    if getattr(client, "auth", None) is None:
        auth_spec = AuthSpec(getattr(rulebook, "auth", None) if rulebook else None)
        if not auth_spec.accounts:
            return {"ok": False, "error": "no auth accounts configured for chain re-run"}
        from ..scope.auth import enable_auth
        enable_auth(client, auth_spec)
    try:
        result = ChainRunner(client, db).run(spec)
    except AgentError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"chain error: {exc}"}
    out = result.as_dict()
    out["ok"] = True
    return out


def _rerun_matrix_probe(finding_row, client: EnforcingClient, db: Database,
                        rulebook: Rulebook | None) -> dict[str, Any]:
    """Stage-1 re-verification for access-matrix findings: re-run the matrix."""
    from ..hunt.access import AccessMatrix  # lazy: hunt imports validate-safe modules only
    evidence = db.evidence_of(finding_row) if db is not None else (
        json.loads(finding_row["evidence"]) if isinstance(finding_row["evidence"], str) else dict(finding_row["evidence"]))
    template = str(evidence.get("url_template") or finding_row["url"])
    ids = evidence.get("ids")
    id_param = str(evidence.get("id_param") or "id")
    if not isinstance(ids, dict) or not ids:
        return {"ok": False, "error": "matrix evidence missing account->id mapping"}
    auth_spec = AuthSpec(getattr(rulebook, "auth", None) if rulebook else None)
    if not auth_spec.accounts:
        return {"ok": False, "error": "no auth: accounts configured in rulebook"}
    try:
        matrix = AccessMatrix(client, db, auth_spec)
        result = matrix.run(template, ids={str(k): str(v) for k, v in ids.items()},
                            id_param=id_param)
    except AuthError as exc:
        return {"ok": False, "error": f"auth: {exc}"}
    except AgentError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"matrix error: {exc}"}
    out = result.as_dict()
    out["ok"] = True
    return out


def _rerun_probe(finding_row, client: EnforcingClient, db: Database | None = None,
                 rulebook: Rulebook | None = None,
                 oob: "InteractshManager | FakeInteractshManager | None" = None) -> dict[str, Any]:
    from ..hunt.payloads import fresh_marker  # noqa: F401 — marker logic lives in probes
    from ..hunt.probes import probe_reflection, probe_redirect, probe_sqli, probe_ssrf

    evidence = db.evidence_of(finding_row) if db is not None else (
        json.loads(finding_row["evidence"]) if isinstance(finding_row["evidence"], str) else dict(finding_row["evidence"]))
    url = finding_row["url"]
    param = finding_row["parameter"] or ""
    if finding_row["vuln_type"] in _MATRIX_TYPES:
        return _rerun_matrix_probe(finding_row, client, db, rulebook)
    if finding_row["vuln_type"] in _CHAIN_TYPES:
        if db is None:
            return {"ok": False, "error": "chain re-run needs the database"}
        return _rerun_chain_probe(finding_row, client, db, rulebook)
    if finding_row["vuln_type"] == "Stored XSS / URI scheme (probe)":
        # re-POST the payloads and re-check the recorded render pages
        from ..hunt.probes import probe_reflection_stored
        check_urls = [c.get("url") for c in evidence.get("href_hits", [])]
        check_urls += evidence.get("persisted_on", [])
        if not check_urls:
            return {"ok": False, "error": "stored-XSS evidence lists no render pages"}
        try:
            return probe_reflection_stored(
                client, finding_row["url"], param, check_urls,
                method=str(evidence.get("method", "POST")).upper())
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"stored probe error: {exc}"}
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
            # with an OOB manager, blind SQLi gets a callback-based second look
            if oob is not None:
                from ..hunt.probes import probe_sqli_oob
                oob_ev = probe_sqli_oob(client, url, param, oob, method=method)
                if oob_ev.get("vulnerable"):
                    return oob_ev
            return probe_sqli(client, url, param, method=method)
        if cls == "redirect":
            return probe_redirect(client, url, param)
        if cls == "ssrf":
            return probe_ssrf(client, url, param, port=port, oob=oob)
    except AgentError as exc:
        return {"ok": False, "error": f"scope/agent error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"probe error: {exc}"}
    return {"ok": False, "error": "unreachable"}


class Validator:
    def _list_candidates(self, db: Database):
        return [r for r in db.list_findings() if r["status"] == "candidate"]

    def validate_all(self, db: Database, provider: LLMProvider,
                     client: EnforcingClient, rulebook: Rulebook,
                     oob: "InteractshManager | FakeInteractshManager | None" = None) -> dict:
        stats = {"verified": 0, "replicated": 0, "failed_repro": 0,
                 "debated": 0, "upgraded": 0, "downgraded": 0, "rejected": 0}
        for row in self._list_candidates(db):
            fid = row["id"]
            # ---- stage 1: deterministic reproduction (types without a probe
            # become 'unverifiable' — they stay visible for human review)
            repro = _rerun_probe(row, client, db, rulebook, oob=oob)
            if not repro.get("ok"):
                db.conn.execute(
                    "UPDATE findings SET status='unverifiable', confidence=confidence*0.5 WHERE id=?",
                    (fid,),
                )
                db.conn.commit()
                stats["failed_repro"] += 1
                continue
            stats["replicated"] += 1
            evidence = db.evidence_of(row)
            # M4/M5d: matrix/chain re-runs classify the target. A clean
            # contradiction with the original verdict is decided HERE,
            # deterministically — the debate must not rescue a finding whose
            # reproduction now says the opposite.
            if "classification" in repro and not repro.get("vulnerable"):
                cls = str(repro.get("classification", "inconclusive"))
                merged = {**evidence, "revalidation": repro,
                          "rejection_reason": f"deterministic re-run classified '{cls}'"}
                if cls in ("denied", "secure"):
                    db.conn.execute(
                        "UPDATE findings SET status='rejected', evidence=? WHERE id=?",
                        (json.dumps(merged), fid),
                    )
                    db.conn.commit()
                    tag_rejection(db, row, f"deterministic re-run classified '{cls}'",
                                  source="validator-repro")
                    stats["rejected"] += 1
                    continue
                if cls == "inconclusive":
                    db.conn.execute(
                        "UPDATE findings SET status='unverifiable',"
                        " confidence=confidence*0.5, evidence=? WHERE id=?",
                        (json.dumps(merged), fid),
                    )
                    db.conn.commit()
                    stats["failed_repro"] += 1
                    continue
            evidence["revalidation"] = repro
            # ---- stage 2: adversarial debate (any failure degrades to
            # needs-review, never crashes the run)
            verdict: dict[str, Any] = {}
            debate_payload = json.dumps({
                "vuln_type": row["vuln_type"], "url": row["url"],
                "param": row["parameter"], "evidence": evidence,
            }, indent=1)[:6000]
            # M5a: evidence strings can embed attacker-controlled page content;
            # sanitize + fence so poisoned evidence cannot argue its own case.
            from ..scope.guard import sanitize_for_prompt
            debate_payload = sanitize_for_prompt(debate_payload)
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
                tag_rejection(db, row, str(verdict.get("reasoning", "debate rejected"))[:300],
                              source="validator-debate")
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
