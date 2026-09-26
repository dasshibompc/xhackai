"""Vulnerability template scanning via nuclei.

Active tool: targets must already be in scope. Each discovered issue becomes a
`candidate` finding in the database — the validator (M3) decides what survives.
"""
from __future__ import annotations

from ..db import Database
from ..errors import OutOfScopeError
from ..scope.rulebook import Rulebook
from .runner import NUCLEI, ToolRunner, parse_json_lines

# nuclei severity -> our 0..1 confidence prior (validated later by the validator)
CONFIDENCE_BY_SEVERITY = {
    "critical": 0.9,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4,
    "info": 0.2,
    "unknown": 0.3,
}


def run_nuclei(runner: ToolRunner, rulebook: Rulebook, db: Database,
               targets: list[str], timeout: float = 900.0,
               severities: str = "low,medium,high,critical") -> dict:
    """Scan explicit, already-validated URLs. Returns counts; writes findings."""
    checked: list[str] = []
    for t in targets:
        allowed, _ = rulebook.check(t)  # every target re-verified at launch time
        if not allowed:
            raise OutOfScopeError(f"nuclei target failed scope re-check: {t}")
        checked.append(t)
    if not checked:
        return {"findings": 0, "targets": 0}

    out = runner.run(
        NUCLEI,
        ["-json", "-silent", "-no-color", "-severity", severities,
         "-timeout", "10", "-retries", "1", "-rl", "60"],
        stdin_text="\n".join(checked),
        timeout=timeout,
        docker_mounts=["-v", "nuclei-templates:/root/nuclei-templates"],
    )
    count = 0
    for rec in parse_json_lines(out):
        matched_at = str(rec.get("matched-at") or rec.get("host") or "")
        if not matched_at:
            continue
        allowed, _reason = rulebook.check(matched_at)  # defensive: report URL must also be in scope
        if not allowed:
            continue
        info = rec.get("info") or {}
        severity = str(info.get("severity", "unknown")).lower()
        db.add_finding(
            vuln_type=str(info.get("name") or rec.get("template-id") or "nuclei-finding"),
            url=matched_at,
            evidence={
                "source": "nuclei",
                "template_id": rec.get("template-id"),
                "severity": severity,
                "matcher_status": rec.get("matcher-status"),
                "extracted": rec.get("extracted-results"),
                "curl": rec.get("curl-command"),
                "description": str(info.get("description") or "")[:500],
            },
            confidence=CONFIDENCE_BY_SEVERITY.get(severity, 0.3),
            status="candidate",
        )
        count += 1
    return {"findings": count, "targets": len(checked)}
