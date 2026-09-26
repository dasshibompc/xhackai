"""Tests for the `callback` one-command pipeline (simple syntax)."""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from lab_app import LabHandler  # noqa: E402

from agent.db import Database  # noqa: E402
from agent.hunt.hypotheses import build_digest  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402

PORT = 8776
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
def tmp_cwd(tmp_path, monkeypatch):
    """Run from a temp dir so agent.db/reports don't pollute the repo."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestRulebookFromUrl:
    def test_generated_rulebook_allows_target(self, tmp_path):
        data = {
            "name": "callback-127.0.0.1",
            "rate_limit": {"requests_per_second": 10},
            "automation_policy": "allowed",
            "scope": [{"host": "127.0.0.1", "allow_private": True}],
        }
        import yaml
        p = tmp_path / "rb.yaml"
        p.write_text(yaml.safe_dump(data), encoding="utf-8")
        rb = Rulebook.load(p)
        assert rb.check(f"{BASE}/anything")[0] is True
        assert rb.check("https://evil.com/")[0] is False


class TestDigestObjectives:
    def test_objectives_appear_in_digest(self, env_db):
        rb, db = env_db
        digest = json.loads(build_digest(db, rb, operator_objectives="find xss only"))
        assert digest["operator_objectives"] == "find xss only"


@pytest.fixture()
def env_db(tmp_path):
    data = {
        "name": "lab",
        "rate_limit": {"requests_per_second": 50},
        "automation_policy": "allowed",
        "scope": [{"host": "127.0.0.1", "allow_private": True}],
    }
    import yaml
    p = tmp_path / "rb.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return Rulebook.load(p), Database(tmp_path / "t.db")


class TestCliCallback:
    def test_help_lists_simple_flags(self):
        from typer.testing import CliRunner
        from agent.cli import app
        result = CliRunner().invoke(app, ["callback", "--help"])
        assert result.exit_code == 0
        for flag in ("--objectives", "--notes", "--url", "--port", "--rate-limit"):
            assert flag in result.output, f"missing {flag}"

    def test_invalid_url_rejected(self, tmp_cwd):
        from typer.testing import CliRunner
        from agent.cli import app
        result = CliRunner().invoke(app, ["callback", "--url", "not-a-url"])
        assert result.exit_code == 1

    def test_pipeline_against_lab_no_llm_key_required(self, tmp_cwd, monkeypatch):
        """Full pipeline run; provider faked at the LLM boundary."""
        from typer.testing import CliRunner
        from agent import cli as cli_mod
        from agent.cli import app

        class FakeProvider(cli_mod.LLMProvider):
            def chat(self, system, user, temperature=0.2):
                # hypothesis proposal sees the digest; hunters immediately finish
                if "hypotheses" in system or "Respond with EXACTLY one JSON" in system:
                    return json.dumps({"hypotheses": [
                        {"url": f"{BASE}/search", "param": "q", "vuln_class": "xss",
                         "reason": "search param", "priority": 1},
                    ]})
                return json.dumps({"thought": "done", "action": {
                    "tool": "finish", "args": {"summary": "ok"}}})

        monkeypatch.setattr(cli_mod, "LLMProvider", FakeProvider)
        # skip the OOB channel in tests
        monkeypatch.setattr(cli_mod, "_make_oob", lambda enabled: None)

        result = CliRunner().invoke(app, [
            "callback",
            "--url", BASE,
            "--objectives", "look for reflected xss",
            "--notes", "unit-test lab run",
            "--rate-limit", "50",
        ])
        assert result.exit_code == 0, result.output
        assert "All findings are drafts" in result.output
        # the lab's open redirect is deterministic evidence — pipeline found it
        # (or at minimum the run completed with the approval-gate banner)
        out_dir = tmp_cwd / "reports"
        assert out_dir.exists(), "report stage must run"
