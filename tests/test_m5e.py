"""M5e tests: the feedback loop — signatures, lesson store, validator
tagging, hypothesis filtering, prompt injection, and trap regressions.
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
from agent.hunt.hypotheses import Hypothesis, propose_hypotheses  # noqa: E402
from agent.hunt.lessons import (  # noqa: E402
    filter_hypotheses,
    lessons_block,
    signature_of,
    tag_rejection,
)
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402
from agent.validate.validator import Validator  # noqa: E402

PORT = 8775
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


class TestSignatures:
    def test_ids_fold_to_placeholder(self):
        a = signature_of("SQL Injection (probe)", f"{BASE}/api/note/5001", "id")
        b = signature_of("SQL Injection (probe)", f"{BASE}/api/note/5002", "id")
        assert a == b
        assert "<id>" in a

    def test_different_paths_differ(self):
        a = signature_of("x", f"{BASE}/api/note/1")
        b = signature_of("x", f"{BASE}/api/user/1")
        assert a != b

    def test_params_distinguish(self):
        a = signature_of("x", f"{BASE}/search", "q")
        b = signature_of("x", f"{BASE}/search", "page")
        assert a != b

    def test_case_and_query_insensitive(self):
        a = signature_of("XSS", f"{BASE}/Search?x=1", "Q")
        b = signature_of("xss", f"{BASE}/search", "q")
        assert a == b


class TestLessonStore:
    def test_add_then_reinforce(self, env):
        _rb, db, _client = env
        sig = signature_of("x", f"{BASE}/a")
        db.add_lesson(sig, "first", "validator-debate")
        db.add_lesson(sig, "second time", "validator-debate")
        rows = db.list_lessons()
        assert len(rows) == 1
        assert rows[0]["weight"] == 2
        assert rows[0]["lesson"] == "first"  # original lesson text preserved

    def test_tag_rejection_from_row(self, env):
        _rb, db, _client = env
        db.add_finding("SQL Injection (probe)", f"{BASE}/login", evidence={},
                       parameter="username", status="rejected")
        row = db.list_findings()[0]
        tag_rejection(db, row, "error signatures were app banner text")
        rows = db.list_lessons()
        assert len(rows) == 1
        assert "login" in rows[0]["signature"]
        assert "do not re-chase" in rows[0]["lesson"]


class TestValidatorTagging:
    def test_debate_rejection_creates_lesson(self, env):
        rb, db, client = env
        from agent.hunt.probes import XssProbeTool
        XssProbeTool(client, db).run(url=f"{BASE}/search", param="q")

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"is_vulnerability": "no", "confidence": 0.95,
                                   "objections": ["marker not executable"],
                                   "reasoning": "reflection without context impact"})

        stats = Validator().validate_all(db, FakeProvider(), client, rb)
        assert stats["rejected"] == 1
        rows = db.list_lessons()
        assert len(rows) == 1
        assert "search" in rows[0]["signature"]
        assert rows[0]["source"] == "validator-debate"

    def test_repro_contradiction_creates_lesson(self, env, monkeypatch):
        rb, db, client = env
        # give the rulebook accounts so the chain can actually re-run, then
        # point its single request at a route that always denies (403) —
        # the re-run classification will be 'denied' vs original 'chained'
        monkeypatch.setenv("LAB_ALICE_USERNAME", "alice")
        monkeypatch.setenv("LAB_ALICE_PASSWORD", "123456")
        rb_path_data = {
            "name": "lab",
            "rate_limit": {"requests_per_second": 50},
            "automation_policy": "allowed",
            "scope": [{"host": "127.0.0.1", "allow_private": True}],
            "auth": {"accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                                    "login_url": f"{BASE}/login-session"}]},
        }
        new_rb = tmp_rulebook(rb_path_data)
        rb = Rulebook.load(new_rb)
        from agent.scope.auth import AuthSpec, enable_auth
        enable_auth(client, AuthSpec(rb.auth))
        db.add_finding("Access control (chained)", f"{BASE}/admin",
                       evidence={"chain": {"steps": [
                           {"action": "request", "name": "s1", "account": "alice",
                            "method": "GET", "url": f"{BASE}/admin",
                            "status": [200]}]}},
                       parameter="chain", confidence=0.8)
        db.conn.execute("UPDATE findings SET status='candidate'")
        db.conn.commit()
        stats = Validator().validate_all(db, LLMProvider(), client, rb)
        assert stats["rejected"] == 1
        rows = db.list_lessons()
        assert rows and "admin" in rows[0]["signature"]
        assert rows[0]["source"] == "validator-repro"


def tmp_rulebook(data: dict) -> Path:
    """Write a temporary rulebook for this test module; returns path."""
    import yaml as _yaml
    p = Path(__file__).parent / "tmp_rb_m5e.yaml"
    p.write_text(_yaml.safe_dump(data), encoding="utf-8")
    return p


class TestHypothesisFiltering:
    def test_matching_hypothesis_dropped(self, env):
        _rb, db, _client = env
        db.add_lesson(signature_of("Reflected XSS/SSTI (probe)", f"{BASE}/search", "q"),
                      "rejected last run", "validator-debate")
        hyps = [Hypothesis(url=f"{BASE}/search", vuln_class="xss", param="q"),
                Hypothesis(url=f"{BASE}/search", vuln_class="xss", param="page"),
                Hypothesis(url=f"{BASE}/fetch", vuln_class="ssrf", param="url")]
        kept, dropped = filter_hypotheses(hyps, db)
        assert [h.param for h in kept] == ["page", "url"]
        assert len(dropped) == 1

    def test_class_mismatch_does_not_block(self, env):
        _rb, db, _client = env
        db.add_lesson(signature_of("Reflected XSS/SSTI (probe)", f"{BASE}/search", "q"),
                      "xss rejected", "validator-debate")
        hyps = [Hypothesis(url=f"{BASE}/search", vuln_class="sqli", param="q")]
        kept, dropped = filter_hypotheses(hyps, db)
        assert len(kept) == 1 and not dropped

    def test_multi_class_hypothesis_matches(self, env):
        _rb, db, _client = env
        db.add_lesson(signature_of("sql injection", f"{BASE}/login", "username"),
                      "sqli rejected", "validator-debate")
        hyps = [Hypothesis(url=f"{BASE}/login", vuln_class="access-control",
                           param="username")]
        # class match is substring-based; 'access-control' does not contain
        # 'sql injection' and vice versa -> NOT blocked
        kept, dropped = filter_hypotheses(hyps, db)
        assert len(kept) == 1

    def test_hunter_run_skips_dropped(self, env, monkeypatch):
        rb, db, client = env
        db.add_lesson(signature_of("reflected xss", f"{BASE}/search", "q"),
                      "rejected", "validator-debate")
        db.conn.execute(
            "INSERT OR IGNORE INTO assets (host, first_seen, last_seen, in_scope,"
            " url) VALUES ('127.0.0.1', 0, 0, 1, ?)", (f"{BASE}/",))
        db.conn.commit()

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"hypotheses": [
                    {"url": f"{BASE}/search", "param": "q", "vuln_class": "xss",
                     "reason": "re-chase attempt", "priority": 1},
                ]})

        from agent.hunt.session import MultiClassHunter
        hunter = MultiClassHunter(FakeProvider(), client, db, rb, max_steps=1)
        result = hunter.run(classes=["xss"])
        assert result["dropped_as_rejected"] == 1
        assert "xss" not in result["sessions"]  # no session run at all


class TestPromptInjection:
    def test_lessons_block_in_objective(self, env, monkeypatch):
        rb, db, client = env
        db.add_lesson(signature_of("reflected xss", f"{BASE}/search", "q"),
                      "rejected previously", "validator-debate")
        db.conn.execute(
            "INSERT OR IGNORE INTO assets (host, first_seen, last_seen, in_scope,"
            " url) VALUES ('127.0.0.1', 0, 0, 1, ?)", (f"{BASE}/",))
        db.conn.commit()
        captured = {}

        from agent.hunt.session import HunterSession

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                captured["objective"] = user
                return json.dumps({"thought": "nothing to do",
                                   "action": {"tool": "finish",
                                              "args": {"summary": "done"}}})

        session = HunterSession(FakeProvider(), client, db, rb, max_steps=1)
        session.hunt("xss", [Hypothesis(url=f"{BASE}/console", vuln_class="xss",
                                        param="render")])
        assert "KNOWN REJECTIONS" in captured["objective"]
        assert "search" in captured["objective"]

    def test_empty_when_no_lessons(self, env):
        _rb, db, _client = env
        assert lessons_block(db) == ""


class TestTrapRegression:
    def test_fired_trap_creates_lesson(self, env, monkeypatch):
        import agent.bench_scenarios as bs
        rb, db, client = env
        monkeypatch.setattr(bs, "BASE", BASE)
        spec = None  # no auth: matrix cases will skip cleanly

        from agent.benchmarks import run_benchmark_suite

        # 'idor-matrix-alice-bob' with no auth returns vulnerable=False, i.e.
        # a MISS for a vuln case (fine); we only need a trap that FIRES.
        # Craft one directly: a fake trap whose executor stores a finding.
        from agent.benchmarks import BenchCase

        def _bad_trap(client, db, auth_spec):
            from agent.hunt.probes import RedirectProbeTool
            RedirectProbeTool(client, db).run(url=f"{BASE}/redirect", param="url")
            return False, "trap fired by design", {}

        trap = BenchCase(name="self-firing-trap", description="unit-test canary",
                         finding_type="Open Redirect (probe)",
                         url=f"{BASE}/redirect", param="url",
                         run=_bad_trap, trap=True)
        results = run_benchmark_suite([trap], client, db, spec)
        assert results["results"][0].detected is True  # trap fired
        rows = db.list_lessons()
        assert any("self-firing-trap" in r["lesson"] for r in rows)
