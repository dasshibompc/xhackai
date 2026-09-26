"""Tests for the scope layer, audit log, and agent protocol. No network needed."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agent.db import Database
from agent.errors import OutOfScopeError
from agent.scope.client import EnforcingClient
from agent.scope.rulebook import Rulebook


@pytest.fixture()
def rulebook(tmp_path: Path) -> Rulebook:
    data = {
        "name": "test",
        "rate_limit": {"requests_per_second": 100},
        "automation_policy": "allowed",
        "scope": [
            {"host": "example.com"},
            {"host": "*.example.com"},
            {"host": "127.0.0.1", "allow_private": True},
        ],
        "out_of_scope": ["admin.example.com"],
    }
    p = tmp_path / "rulebook.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return Rulebook.load(p)


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "test.db")


class TestScopeMatching:
    def test_exact_host_allowed(self, rulebook: Rulebook):
        assert rulebook.check("https://example.com/page")[0] is True

    def test_wildcard_subdomain_allowed(self, rulebook: Rulebook):
        assert rulebook.check("https://api.example.com/x")[0] is True

    def test_base_of_wildcard_allowed(self, rulebook: Rulebook):
        assert rulebook.check("https://example.com")[0] is True

    def test_unrelated_host_blocked(self, rulebook: Rulebook):
        allowed, _ = rulebook.check("https://evil.com/x")
        assert allowed is False

    def test_lookalike_host_blocked(self, rulebook: Rulebook):
        allowed, _ = rulebook.check("https://example.com.evil.com/x")
        assert allowed is False

    def test_out_of_scope_entry_beats_wildcard(self, rulebook: Rulebook):
        allowed, _ = rulebook.check("https://admin.example.com/x")
        assert allowed is False

    def test_private_blocked_without_optin(self, rulebook: Rulebook, db: Database):
        client = EnforcingClient(rulebook, db)
        with pytest.raises(OutOfScopeError):
            client.request("GET", "http://10.0.0.5/x")  # not in scope entries

    def test_private_allowed_with_optin(self, rulebook: Rulebook, db: Database):
        client = EnforcingClient(rulebook, db)
        # 127.0.0.1 is in scope with allow_private — nothing runs (no server), but
        # it must NOT be blocked by the scope layer.
        try:
            client.request("GET", "http://127.0.0.1:1/x")
        except OutOfScopeError:
            pytest.fail("opted-in loopback host was blocked by scope layer")
        except Exception:
            pass  # connection refused is fine — no server listening

    def test_fail_closed_on_garbage(self, rulebook: Rulebook):
        allowed, _ = rulebook.check("not a url")
        assert allowed is False


class TestAuditLog:
    def test_chain_valid(self, db: Database):
        for i in range(5):
            db.log_audit("GET", f"http://example.com/{i}", "allowed", status_code=200)
        ok, n = db.verify_audit_chain()
        assert ok and n == 5

    def test_tamper_detected(self, db: Database):
        db.log_audit("GET", "http://example.com/1", "allowed")
        db.log_audit("POST", "http://example.com/2", "blocked")
        ok, _ = db.verify_audit_chain()
        assert ok
        # simulate tampering
        db.conn.execute("UPDATE audit_log SET decision='allowed' WHERE id=2")
        ok, _ = db.verify_audit_chain()
        assert not ok

    def test_blocked_requests_are_logged(self, rulebook: Rulebook, db: Database):
        client = EnforcingClient(rulebook, db)
        with pytest.raises(OutOfScopeError):
            client.request("GET", "https://evil.com/x")
        rows = db.list_findings()  # ensure db usable
        assert rows == []
        ok, n = db.verify_audit_chain()
        assert ok and n == 1


class TestAgentProtocol:
    def test_action_parse(self):
        from agent.loop import AgentLoop
        from agent.llm.provider import extract_json

        reply = '{"thought": "test XSS", "action": {"tool": "http_request", "args": {"url": "http://x"}}}'
        thought, tool, args = AgentLoop._parse_action(None, reply)  # type: ignore[arg-type]
        assert tool == "http_request" and args == {"url": "http://x"}

    def test_extract_json_from_fenced(self):
        from agent.llm.provider import extract_json

        text = "Sure!\n```json\n{\"tool\": \"finish\"}\n```"
        assert extract_json(text) == {"tool": "finish"}

    def test_agent_loop_runs_tool_and_finishes(self, rulebook: Rulebook, db: Database, monkeypatch):
        """End-to-end loop with a fake provider: fetch, save finding, finish."""
        from agent.llm.provider import LLMProvider
        from agent.loop import AgentLoop
        from agent.scope.client import EnforcingClient
        from agent.tools import GrepTool, HttpRequestTool, SaveFindingTool

        client = EnforcingClient(rulebook, db)
        http_tool = HttpRequestTool(client)
        tools = {
            "http_request": http_tool,
            "grep_response": GrepTool(http_tool),
            "save_finding": SaveFindingTool(db),
        }

        script = [
            json.dumps({"thought": "fetch home", "action": {"tool": "http_request",
                        "args": {"url": "http://127.0.0.1:9/"}}}),
            json.dumps({"thought": "record", "action": {"tool": "save_finding",
                        "args": {"vuln_type": "xss", "url": "http://127.0.0.1:9/", "evidence": "e", "confidence": 0.9}}}),
            json.dumps({"thought": "done", "action": {"tool": "finish",
                        "args": {"summary": "found one"}}}),
        ]
        calls = {"n": 0}

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                r = script[min(calls["n"], len(script) - 1)]
                calls["n"] += 1
                return r

        loop = AgentLoop(FakeProvider(), tools, db, max_steps=5)
        summary = loop.run("test the lab app")
        assert summary == "found one"
        findings = db.list_findings()
        assert len(findings) == 1 and findings[0]["vuln_type"] == "xss"
        assert findings[0]["status"] == "candidate"
