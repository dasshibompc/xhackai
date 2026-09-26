"""Endpoint/parameter/secret discovery via xnLinkFinder (xnl-h4ck3r).

Runs xnLinkFinder in file-crawl mode against the JS URLs discovered by katana
(passive analysis of files already fetched — it does NOT crawl itself in this
mode). Its -sf scope filter is mandatory for domain input; we additionally
re-verify every output URL against our own rulebook.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..db import Database
from ..scope.rulebook import Rulebook
from .runner import XNLINKFINDER, ToolRunner, ToolUnavailable


def run_xnlinkfinder(runner: ToolRunner, rulebook: Rulebook, db: Database,
                     js_urls: list[str], timeout: float = 900.0) -> dict:
    if not js_urls:
        return {"links": 0, "params": 0, "secrets": 0, "inputs": 0}
    if runner.modes.get(XNLINKFINDER.name) is None:
        raise ToolUnavailable("xnLinkFinder not available — pip install xnLinkFinder")

    with tempfile.TemporaryDirectory() as tmp:
        input_file = Path(tmp) / "js_urls.txt"
        input_file.write_text("\n".join(js_urls) + "\n", encoding="utf-8")
        out_links = Path(tmp) / "links.txt"
        out_params = Path(tmp) / "params.txt"
        out_secrets = Path(tmp) / "secrets.json"

        # file input => no crawling; -r limit 0; no scope filter needed for files
        runner.run(
            XNLINKFINDER,
            ["-i", str(input_file), "-o", str(out_links), "-op", str(out_params),
             "-os", str(out_secrets), "-ow", "-r", "0", "-nb", "-t", "10"],
            timeout=timeout,
        )

        links = out_links.read_text(encoding="utf-8") if out_links.exists() else ""
        params = out_params.read_text(encoding="utf-8") if out_params.exists() else ""
        secrets = out_secrets.read_text(encoding="utf-8") if out_secrets.exists() else "{}"

    import json

    def _absolutize(raw: str) -> str | None:
        raw = raw.strip()
        if not raw:
            return None
        if raw.startswith(("http://", "https://")):
            url = raw.split(" ")[0]
        else:
            # relative endpoint found inside a JS file — anchor to that file's host
            from urllib.parse import urljoin
            url = urljoin(js_urls[0], raw).split(" ")[0]
        return url

    link_count = param_count = secret_count = 0
    for line in links.splitlines():
        url = _absolutize(line)
        if not url:
            continue
        allowed, _ = rulebook.check(url)
        if not allowed:
            continue
        if db.add_endpoint(url, "endpoint", source="xnlinkfinder"):
            link_count += 1
    for line in params.splitlines():
        p = line.strip()
        if p and len(p) <= 64:
            allowed, _ = rulebook.check(f"https://{rulebook.candidate_domains()[0]}/?{p}=1")
            if allowed:
                if db.add_endpoint(f"param:{p}", "param", source="xnlinkfinder",
                                   host=rulebook.candidate_domains()[0]):
                    param_count += 1
    try:
        secrets_data = json.loads(secrets)
    except json.JSONDecodeError:
        secrets_data = {}
    for _typ, entries in (secrets_data.items() if isinstance(secrets_data, dict) else []):
        if isinstance(entries, list):
            secret_count += len(entries)

    # secrets are stored as findings for human review — never auto-submitted
    if secret_count:
        db.add_finding(
            vuln_type="Exposed secrets in JS (xnLinkFinder)",
            url=js_urls[0],
            evidence={"secrets_json": secrets[:4000], "js_scanned": len(js_urls)},
            confidence=0.5,
            status="candidate",
        )
    return {"links": link_count, "params": param_count,
            "secrets": secret_count, "inputs": len(js_urls)}
