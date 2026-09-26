"""End-to-end smoke test: boots the vulnerable lab app in-process, then verifies
the scope layer allows in-scope requests, blocks out-of-scope ones, logs both to
the hash-chained audit log, and validates the chain.

Run: uv run python examples/smoke_test.py
No LLM key required.
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from lab_app import LabHandler  # noqa: E402

from agent.db import Database  # noqa: E402
from agent.errors import OutOfScopeError  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402

from http.server import ThreadingHTTPServer  # noqa: E402

PORT = 8766
BASE = f"http://127.0.0.1:{PORT}"


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LabHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.5)

    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "smoke.db")
    rb_path = os.path.join(tmp, "rulebook.yaml")
    with open(rb_path, "w", encoding="utf-8") as f:
        f.write(
            "name: smoke-lab\n"
            "rate_limit:\n  requests_per_second: 50\n"
            "automation_policy: allowed\n"
            "scope:\n  - host: 127.0.0.1\n    allow_private: true\n"
        )
    rulebook = Rulebook.load(rb_path)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)

    failures = []

    # 1. in-scope request works
    try:
        r = client.get(f"{BASE}/search?q=<script>alert(1)</script>")
        reflected = "<script>alert(1)</script>" in r.text
        print(f"[ok] in-scope request -> {r.status_code}; XSS reflected in body: {reflected}")
        if r.status_code != 200:
            failures.append("in-scope request failed")
    except Exception as exc:
        print(f"[FAIL] in-scope request raised {exc}")
        failures.append("in-scope blocked")

    # 2. out-of-scope request blocked
    try:
        client.get("http://evil.example/")
        print("[FAIL] out-of-scope request was NOT blocked")
        failures.append("oos allowed")
    except OutOfScopeError as exc:
        print(f"[ok] out-of-scope blocked: {str(exc)[:80]}")

    # 3. lookalike host blocked (example.com.attacker.tld style)
    try:
        client.get(f"http://127.0.0.1.evil.test:{PORT}/")
        print("[FAIL] lookalike host NOT blocked")
        failures.append("lookalike allowed")
    except OutOfScopeError:
        print("[ok] lookalike host blocked")

    # 4. private host without opt-in blocked
    try:
        client.get("http://10.1.2.3/")
        print("[FAIL] private IP NOT blocked")
        failures.append("private allowed")
    except OutOfScopeError:
        print("[ok] non-opted private IP blocked")

    # 5. audit chain valid and counts decisions
    ok, n = db.verify_audit_chain()
    decisions = [row["decision"] for row in db.conn.execute("SELECT decision FROM audit_log")]
    print(f"[{'ok' if ok else 'FAIL'}] audit chain valid={ok}, entries={n}, decisions={decisions}")
    if not ok or decisions.count("blocked") < 3 or decisions.count("allowed") < 1:
        failures.append("audit log wrong")

    server.shutdown()
    print("\nSMOKE TEST " + ("PASSED" if not failures else f"FAILED: {failures}"))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
