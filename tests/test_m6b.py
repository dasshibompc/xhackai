"""M6b tests: filter mapping (which markup survives) and loop budget note."""
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
from agent.hunt.probes import probe_filter_map  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402

PORT = 8780
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


class TestFilterMap:
    def test_unfiltered_page_allows_everything(self, env):
        _rb, _db, client = env
        res = probe_filter_map(client, f"{BASE}/search", "q")
        assert res["ok"]
        # the lab reflects raw — everything survives
        assert "svg" in res["allowed_tags"]
        assert "onbegin" in res["allowed_handlers"]
        assert res["blocked_tags"] == [] and res["blocked_handlers"] == []

    def test_requests_accounted(self, env):
        _rb, _db, client = env
        res = probe_filter_map(client, f"{BASE}/search", "q")
        assert res["requests"] == 1 + len(res["allowed_tags"]) + len(res["blocked_tags"]) \
            + len(res["allowed_handlers"]) + len(res["blocked_handlers"])


class TestLoopBudget:
    def test_wrapup_note_in_history(self, env, monkeypatch):
        rb, db, client = env
        from agent.loop import AgentLoop
        from agent.tools import HttpRequestTool
        captured = {}

        class FakeProvider:
            def chat(self, system, user, temperature=0.2):
                captured["user"] = user
                if "ONE STEP REMAINS" not in user:
                    return json.dumps({"thought": "keep going", "action": {
                        "tool": "http_request", "args": {"url": f"{BASE}/"}}})
                return json.dumps({"thought": "wrapping", "action": {
                    "tool": "finish", "args": {"summary": "wrapped up cleanly"}}})

        monkeypatch.setattr("agent.loop.LLMProvider", FakeProvider)
        tools = {"http_request": HttpRequestTool(client)}
        loop = AgentLoop(FakeProvider(), tools, db, max_steps=2)
        summary = loop.run("test")
        assert summary == "wrapped up cleanly"
        assert "ONE STEP REMAINS" in captured["user"]
