"""M3 tests: deterministic probes against the real local lab app (in-process
server), hypothesis generation guards, validator logic, and report generation.
No LLM key required — provider interactions are faked.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest
import yaml
from http.server import ThreadingHTTPServer

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from lab_app import LabHandler  # noqa: E402

from agent.db import Database  # noqa: E402
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.report import generate_report, write_reports  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402
from agent.validate.validator import Validator  # noqa: E402
from agent.hunt.probes import (  # noqa: E402
    probe_idor,
    probe_redirect,
    probe_reflection,
    probe_sqli,
    probe_ssrf,
)

PORT = 8767
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


class TestProbesAgainstLab:
    def test_xss_probe_detects_reflection(self, env):
        _rb, _db, client = env
        res = probe_reflection(client, f"{BASE}/search", "q")
        assert res["ok"] and res["vulnerable"] is True
        assert res["reflections"], "raw reflection expected from lab app"

    def test_sqli_probe_detects_error_signature(self, env):
        _rb, _db, client = env
        res = probe_sqli(client, f"{BASE}/login", "username", method="POST")
        assert res["ok"] and res["vulnerable"] is True
        assert res["signatures_found"], "lab app returns sqlite error text"

    def test_redirect_probe_detects_open_redirect(self, env):
        _rb, _db, client = env
        res = probe_redirect(client, f"{BASE}/redirect", "url")
        assert res["ok"] and res["vulnerable"] is True
        assert res["redirects"][0]["location"].startswith("https://oob-example.invalid")

    def test_ssrf_probe_hits_loopback(self, env):
        _rb, _db, client = env
        # /fetch fetches attacker URL; use it against the app itself (loopback)
        res = probe_ssrf(client, f"{BASE}/fetch", "url", port=PORT)
        assert res["ok"] and res["vulnerable"] is True

    def test_idor_probe_detects_foreign_object_access(self, env):
        _rb, _db, client = env
        res = probe_idor(client, f"{BASE}/api/user/{{id}}", "1", "2")
        assert res["ok"] and res["vulnerable"] is True
        assert res["status"] == 200

    def test_probe_findings_stored_in_scope(self, env):
        _rb, db, client = env
        from agent.hunt.probes import RedirectProbeTool
        RedirectProbeTool(client, db).run(url=f"{BASE}/redirect", param="url")
        rows = db.list_findings()
        assert rows and rows[0]["status"] == "candidate"

    def test_out_of_scope_url_blocked_even_for_probes(self, tmp_path):
        rb_path = tmp_path / "rb.yaml"
        rb_path.write_text(yaml.safe_dump({
            "name": "strict", "scope": [{"host": "example.com"}],
        }), encoding="utf-8")
        rulebook = Rulebook.load(rb_path)
        db = Database(tmp_path / "x.db")
        client = EnforcingClient(rulebook, db)
        from agent.errors import OutOfScopeError
        with pytest.raises(OutOfScopeError):
            probe_reflection(client, "https://evil.com/search", "q")


class TestHypotheses:
    def test_proposal_filters_out_of_scope_urls(self, env, monkeypatch):
        _rb, db, _client = env
        from agent.hunt.hypotheses import propose_hypotheses

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"hypotheses": [
                    {"url": f"{BASE}/search?q=1", "param": "q", "vuln_class": "xss",
                     "reason": "reflection likely", "priority": 1},
                    {"url": "https://evil.com/x", "param": "q", "vuln_class": "xss",
                     "reason": "should be dropped", "priority": 2},
                    {"url": f"{BASE}/fetch", "param": "url", "vuln_class": "ssrf",
                     "reason": "fetch param", "priority": 3},
                ]})

        # note: evil.com is not in scope entries -> must be filtered
        hyps = propose_hypotheses(FakeProvider(), db, _rb)
        urls = [h.url for h in hyps]
        assert "https://evil.com/x" not in urls
        assert any(h.vuln_class == "ssrf" for h in hyps)

    def test_unknown_class_dropped(self, env, monkeypatch):
        _rb, db, _client = env
        from agent.hunt.hypotheses import propose_hypotheses

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"hypotheses": [
                    {"url": f"{BASE}/search", "vuln_class": "quantum-injection",
                     "reason": "made up", "priority": 1},
                ]})

        assert propose_hypotheses(FakeProvider(), db, _rb) == []


class TestValidator:
    def test_validated_xss_finding_survives_pipeline(self, env):
        rb, db, client = env
        # record a real finding through the Tool wrapper (the agent's code path)
        from agent.hunt.probes import RedirectProbeTool
        RedirectProbeTool(client, db).run(url=f"{BASE}/redirect", param="url")
        fid = db.list_findings()[0]["id"]

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                # the adversarial model CONCEDES — evidence is solid
                return json.dumps({"is_vulnerability": "yes", "confidence": 0.85,
                                   "objections": [], "reasoning": "reproducible"})

        stats = Validator().validate_all(db, FakeProvider(), client, rb)
        row = db.conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        assert row["status"] == "validated" and row["confidence"] >= 0.6
        assert stats["upgraded"] == 1

    def test_rejected_finding_when_llm_disagrees(self, env):
        rb, db, client = env
        from agent.hunt.probes import XssProbeTool
        XssProbeTool(client, db).run(url=f"{BASE}/search", param="q")
        fid = db.list_findings()[0]["id"]

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"is_vulnerability": "no", "confidence": 0.95,
                                   "objections": ["marker echo is not in an executable context"],
                                   "reasoning": "no impact shown"})

        Validator().validate_all(db, FakeProvider(), client, rb)
        row = db.conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        assert row["status"] == "rejected"

    def test_unverifiable_type_is_marked(self, env):
        rb, db, client = env
        db.add_finding("mystery-bug", f"{BASE}/", evidence={"x": 1}, confidence=0.5)
        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"is_vulnerability": "uncertain", "confidence": 0.5})
        Validator().validate_all(db, FakeProvider(), client, rb)
        row = db.list_findings()[0]
        assert row["status"] == "unverifiable"


class TestReports:
    def test_report_contains_key_sections(self, env):
        rb, db, client = env
        from agent.hunt.probes import RedirectProbeTool
        RedirectProbeTool(client, db).run(url=f"{BASE}/redirect", param="url")
        fid = db.list_findings()[0]["id"]
        db.conn.execute("UPDATE findings SET status='validated', confidence=0.8 WHERE id=?", (fid,))
        db.conn.commit()
        row = [r for r in db.list_findings() if r["id"] == fid][0]
        md = generate_report(row, db)
        for section in ("# ", "## Summary", "## Evidence", "## Impact", "## Remediation", "human"):
            assert section in md
        assert "CVSS" in md

    def test_write_reports_only_writes_reviewable(self, env, tmp_path):
        _rb, db, _client = env
        db.add_finding("Open Redirect (probe)", f"{BASE}/redirect", evidence={"vulnerable": True},
                       confidence=0.7, status="validated")
        db.add_finding("Open Redirect (probe)", f"{BASE}/redirect2", evidence={"vulnerable": True},
                       confidence=0.2, status="rejected")
        written = write_reports(db, out_dir=str(tmp_path / "reports"))
        assert len(written) == 1  # rejected findings get no report
