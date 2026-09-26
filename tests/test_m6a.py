"""M6a tests: stored XSS / URI-scheme probe (anchor-href pattern) against the
lab's /comments board. Provider faked.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from lab_app import LabHandler  # noqa: E402

from agent.db import Database  # noqa: E402
from agent.hunt.probes import probe_reflection_stored  # noqa: E402
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402
from agent.validate.validator import Validator  # noqa: E402

PORT = 8779
BASE = f"http://127.0.0.1:{PORT}"


@pytest.fixture(scope="module")
def lab_server():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LabHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.4)
    yield server
    server.shutdown()


@pytest.fixture()
def env(tmp_path, lab_server):
    rb_path = tmp_path / "rb.yaml"
    rb_path.write_text(yaml.safe_dump({
        "name": "lab",
        "rate_limit": {"requests_per_second": 50},
        "automation_policy": "allowed",
        "scope": [{"host": "127.0.0.1", "allow_private": True}],
    }), encoding="utf-8")
    rulebook = Rulebook.load(rb_path)
    db = Database(tmp_path / "test.db")
    client = EnforcingClient(rulebook, db)
    return rulebook, db, client


class TestStoredXssProbe:
    def test_javascript_scheme_persists_in_href(self, env):
        _rb, _db, client = env
        res = probe_reflection_stored(
            client, f"{BASE}/comments", "website",
            check_urls=[f"{BASE}/comments"])
        assert res["ok"] and res["vulnerable"] is True
        assert res["href_hits"], "javascript: URI must land in href"
        assert res["persisted_on"] == [f"{BASE}/comments"]

    def test_no_injection_no_hit(self, env):
        _rb, _db, client = env
        # param that is NOT rendered into href: message is HTML-escaped? No —
        # the lab renders everything verbatim; use a non-stored endpoint
        res = probe_reflection_stored(
            client, f"{BASE}/admin", "website",
            check_urls=[f"{BASE}/comments"])
        # /admin returns 403 -> nothing stored
        assert res["ok"] and res["vulnerable"] is False

    def test_tool_stores_finding(self, env):
        _rb, db, client = env
        from agent.hunt.probes import StoredXssProbeTool
        res = StoredXssProbeTool(client, db).run(
            inject_url=f"{BASE}/comments", param="website",
            check_urls=f"{BASE}/comments")
        assert res.ok and "finding #" in res.output
        row = db.list_findings()[0]
        assert row["vuln_type"] == "Stored XSS / URI scheme (probe)"

    def test_validator_reverifies_stored_finding(self, env):
        rb, db, client = env
        from agent.hunt.probes import StoredXssProbeTool
        StoredXssProbeTool(client, db).run(
            inject_url=f"{BASE}/comments", param="website",
            check_urls=f"{BASE}/comments")

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"is_vulnerability": "yes", "confidence": 0.9,
                                   "objections": [], "reasoning": "persisted"})

        stats = Validator().validate_all(db, FakeProvider(), client, rb)
        row = db.list_findings()[0]
        assert row["status"] == "validated"
        reval = json.loads(row["evidence"])["revalidation"]
        assert reval["vulnerable"] is True

    def test_guard_does_not_flag_own_probe_requests(self, env):
        """The payload embeds a javascript: URL — the M5a guard must not treat
        the probe's own activity as page-borne injection steering."""
        _rb, db, client = env
        before = len(db.list_tamper_events())
        probe_reflection_stored(client, f"{BASE}/comments", "website",
                                check_urls=[f"{BASE}/comments"])
        # tamper events only fire on summarize(); probes don't summarize, but
        # an LLM hunter fetching /comments after this WOULD — ensure the page
        # itself (no operator content) is not flagged
        resp = client.get(f"{BASE}/comments")
        client.summarize(resp)
        new_events = [e for e in db.list_tamper_events()]
        page_only_events = [e for e in new_events
                            if e["url"].endswith("/comments")]
        assert not page_only_events or all(
            "finding-manipulation" not in (e["categories"] or "")
            for e in page_only_events)
