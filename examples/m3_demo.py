"""M3 end-to-end demo (no LLM key needed): boots the vulnerable lab app,
runs the deterministic probe tools, validates findings with a stubbed
adversarial reviewer, and writes draft reports.

Run:  python examples/m3_demo.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lab_app import LabHandler  # noqa: E402

from agent.db import Database  # noqa: E402
from agent.hunt.probes import (  # noqa: E402
    IdorProbeTool,
    RedirectProbeTool,
    SqliProbeTool,
    SsrfProbeTool,
    XssProbeTool,
)
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.report import write_reports  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402
from agent.validate.validator import Validator  # noqa: E402

PORT = 8769
BASE = f"http://127.0.0.1:{PORT}"


class AgreeableReviewer(LLMProvider):
    """Stub adversarial reviewer: concedes when evidence reproduces."""

    def chat(self, system, user, temperature=0.2):
        evidence = json.loads(user)
        solid = bool(evidence.get("evidence", {}).get("revalidation", {}).get("vulnerable"))
        return json.dumps({
            "is_vulnerability": "yes" if solid else "no",
            "confidence": 0.85 if solid else 0.9,
            "objections": [] if solid else ["evidence did not reproduce"],
            "reasoning": "deterministic reproduction succeeded" if solid else "no reproduction",
        })


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LabHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.4)

    tmp = Path(tempfile.mkdtemp())
    (tmp / "rb.yaml").write_text(
        "name: m3-demo\n"
        "rate_limit:\n  requests_per_second: 50\n"
        "automation_policy: allowed\n"
        "scope:\n  - host: 127.0.0.1\n    allow_private: true\n",
        encoding="utf-8",
    )
    rulebook = Rulebook.load(tmp / "rb.yaml")
    db = Database(tmp / "demo.db")
    client = EnforcingClient(rulebook, db)

    print(f"[1] probing lab app at {BASE}")
    probes = [
        ("XSS",  XssProbeTool(client, db),       {"url": f"{BASE}/search", "param": "q"}),
        ("SQLi", SqliProbeTool(client, db),      {"url": f"{BASE}/login", "param": "username", "method": "POST"}),
        ("RED",  RedirectProbeTool(client, db),  {"url": f"{BASE}/redirect", "param": "url"}),
        ("SSRF", SsrfProbeTool(client, db),      {"url": f"{BASE}/fetch", "param": "url", "port": PORT}),
        ("IDOR", IdorProbeTool(client, db),      {"url_template": f"{BASE}/api/user/{{id}}", "id_a": "1", "id_b": "2"}),
    ]
    for label, tool, kwargs in probes:
        res = tool.run(**kwargs)
        print(f"    {label}: {res.output}")

    print("[2] adversarial validation")
    stats = Validator().validate_all(db, AgreeableReviewer(), client, rulebook)
    print(f"    {stats}")

    print("[3] writing draft reports")
    written = write_reports(db, out_dir=str(tmp / "reports"))
    for p in written:
        print(f"    {p.name}")

    findings = db.list_findings()
    validated = [f for f in findings if f["status"] == "validated"]
    print(f"\nM3 DEMO {'PASSED' if validated else 'FAILED'} — "
          f"{len(findings)} candidates -> {len(validated)} validated, reports in {tmp / 'reports'}")
    server.shutdown()
    return 0 if validated else 1


if __name__ == "__main__":
    raise SystemExit(main())
