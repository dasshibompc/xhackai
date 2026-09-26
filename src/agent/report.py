"""Markdown report generation for validated findings.

Reports are DRAFTS. They contain everything a human needs to review and submit:
summary, CVSS-style severity, reproduction steps from the evidence, the
validator's objections (so the human sees both sides), and remediation.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .db import Database

# rough CVSS v3.1 base-score anchors per class (human refines on review)
SEVERITY_BY_CLASS = {
    "SQL Injection": ("Critical", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SSRF": ("High", 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Reflected XSS": ("Medium", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Open Redirect": ("Low", 4.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "IDOR": ("High", 8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
}


def _classify(vuln_type: str) -> tuple[str, float, str] | None:
    for key, sev in SEVERITY_BY_CLASS.items():
        if key.lower() in vuln_type.lower():
            return sev
    return None


def generate_report(finding_row, db: Database) -> str:
    evidence = json.loads(finding_row["evidence"]) if isinstance(finding_row["evidence"], str) else dict(finding_row["evidence"])
    sev = _classify(finding_row["vuln_type"]) or ("Medium", 5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
    reval = evidence.get("revalidation") or {}
    lines = [
        f"# {finding_row['vuln_type']} — {finding_row['url']}",
        "",
        f"**Status:** {finding_row['status']}  |  **Confidence:** {finding_row['confidence']:.2f}  |  "
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Summary",
        "",
        f"A {sev[0].lower()}-severity {finding_row['vuln_type']} was identified on "
        f"`{finding_row['url']}`"
        + (f" via the `{finding_row['parameter']}` parameter." if finding_row["parameter"] else "."),
        "",
        f"- **CVSS v3.1 (base, estimated):** {sev[1]} ({sev[2]})",
        f"- **Deterministic re-verification:** {'passed' if reval.get('ok') and reval.get('vulnerable') else 'see evidence'}",
        "",
        "## Evidence",
        "",
        "```json",
        json.dumps(evidence, indent=2)[:3500],
        "```",
        "",
    ]
    if reval.get("reflections"):
        lines += ["## Reproduction (XSS reflection)", ""]
        for r in reval["reflections"]:
            lines.append(f"- payload `{r['payload']}` reflected raw in response")
        lines.append("")
    if reval.get("redirects"):
        lines += ["## Reproduction (open redirect)", ""]
        for r in reval["redirects"]:
            lines.append(f"- `{finding_row['parameter']}={r['payload']}` → `Location: {r['location']}`")
        lines.append("")
    if reval.get("signatures_found"):
        lines += ["## SQL error signatures observed", "",
                  ", ".join(f"`{s}`" for s in reval["signatures_found"]), ""]
    lines += [
        "## Impact",
        "",
        _impact_text(finding_row["vuln_type"]),
        "## Remediation",
        "",
        _remediation_text(finding_row["vuln_type"]),
        "## Notes for the reviewer (human)",
        "",
        "- This report is machine-drafted. Verify every claim before submitting.",
        "- Re-check program scope and policy: this asset must be listed in-scope.",
        "- Attach screenshots/token markers from your own re-test before submission.",
    ]
    return "\n".join(lines)


def _impact_text(vuln_type: str) -> str:
    low = vuln_type.lower()
    if "sql" in low:
        return "An attacker could read or modify database contents, potentially including user credentials and personal data."
    if "ssrf" in low:
        return "An attacker could make the server issue requests to internal services, potentially reaching cloud metadata or internal APIs."
    if "xss" in low:
        return "An attacker could execute JavaScript in a victim's browser session, enabling session theft and actions on behalf of the user."
    if "redirect" in low:
        return "An attacker could abuse trusted domains for phishing and potentially steal OAuth tokens via redirect_uri confusion."
    if "idor" in low:
        return "An attacker could access objects belonging to other users by manipulating object references."
    return "Impact assessment requires human review."


def _remediation_text(vuln_type: str) -> str:
    low = vuln_type.lower()
    if "sql" in low:
        return "Use parameterized queries / prepared statements for all database access."
    if "ssrf" in low:
        return "Validate and allow-list outbound URLs; block link-local and private ranges; never fetch user-supplied hosts directly."
    if "xss" in low:
        return "Contextually encode user input on output; add Content Security Policy; avoid raw HTML insertion."
    if "redirect" in low:
        return "Validate redirect targets against an allow-list of trusted destinations; reject absolute URLs to untrusted hosts."
    if "idor" in low:
        return "Enforce object-level authorization on every request; use non-guessable identifiers as defense in depth."
    return "Remediation guidance requires human review."


def write_reports(db: Database, out_dir: str = "reports", statuses: tuple[str, ...] = ("validated", "needs-review", "unverifiable")) -> list[Path]:
    out_path = Path(out_dir)
    out_path.mkdir(exist_ok=True)
    written = []
    for row in db.list_findings():
        if row["status"] not in statuses:
            continue
        md = generate_report(row, db)
        p = out_path / f"finding-{row['id']:03d}-{_slug(row['vuln_type'])}.md"
        p.write_text(md, encoding="utf-8")
        written.append(p)
    return written


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")[:40]
