"""M5d tests: exploit chains — ChainRunner primitives, the cross-account
create-read template, ChainTool evidence storage, and validator re-execution,
all against the real lab app (in-process). Provider faked.
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
from agent.hunt.chains import (  # noqa: E402
    ChainRunner,
    ChainTool,
    build_cross_account_create_read,
)
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.scope.auth import AuthSpec, enable_auth  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402
from agent.validate.validator import Validator  # noqa: E402

PORT = 8774
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
def accounts_env(monkeypatch):
    monkeypatch.setenv("LAB_ALICE_USERNAME", "alice")
    monkeypatch.setenv("LAB_ALICE_PASSWORD", "123456")
    monkeypatch.setenv("LAB_BOB_USERNAME", "bob")
    monkeypatch.setenv("LAB_BOB_PASSWORD", "abcdef")


@pytest.fixture()
def env(tmp_path, lab_server, accounts_env):
    rb_path = tmp_path / "rb.yaml"
    rb_path.write_text(yaml.safe_dump({
        "name": "lab-m4",
        "rate_limit": {"requests_per_second": 50},
        "automation_policy": "allowed",
        "scope": [{"host": "127.0.0.1", "allow_private": True}],
        "auth": {
            "session_mode": "cookie",
            "login_success_status": 200,
            "accounts": [
                {"name": "alice", "env_prefix": "LAB_ALICE",
                 "login_url": f"{BASE}/login-session"},
                {"name": "bob", "env_prefix": "LAB_BOB",
                 "login_url": f"{BASE}/login-session"},
            ],
        },
    }), encoding="utf-8")
    rulebook = Rulebook.load(rb_path)
    db = Database(tmp_path / "test.db")
    client = EnforcingClient(rulebook, db)
    enable_auth(client, AuthSpec(rulebook.auth))
    return rulebook, db, client


def _vuln_spec() -> dict:
    return build_cross_account_create_read(
        base_url=BASE, create_path="/api/notes",
        read_path_template="/api/note/{id}?debug=vuln",
        body={"title": "m5d-{{marker}}"},
    )


def _safe_spec() -> dict:
    return build_cross_account_create_read(
        base_url=BASE, create_path="/api/notes",
        read_path_template="/api/note/{id}",  # no debug=vuln: properly denied
    )


class TestChainRunner:
    def test_vuln_chain_succeeds_and_proves_ownership(self, env):
        _rb, _db, client = env
        result = ChainRunner(client, Database(":memory:")).run(_vuln_spec())
        assert result.vulnerable is True
        assert result.classification == "idor-chain"
        assert result.ctx["seen_owner"] == "alice"
        assert result.ctx["created_id"]
        # evidence: 3 steps, each with status/snippets
        assert [s["name"] for s in result.steps] == [
            "create_as_a", "read_as_b", "owner_is_a"]
        assert result.steps[1]["status"] == 200

    def test_safe_chain_denied_classifies_secure(self, env):
        _rb, _db, client = env
        result = ChainRunner(client, Database(":memory:")).run(_safe_spec())
        assert result.vulnerable is False
        assert result.classification == "denied"
        assert result.steps[1]["status"] == 403

    def test_spec_is_json_serializable(self, env):
        _rb, _db, client = env
        spec = _vuln_spec()
        result = ChainRunner(client, Database(":memory:")).run(spec)
        # round-trip: the validator must be able to re-run the stored spec
        result2 = ChainRunner(client, Database(":memory:")).run(
            json.loads(json.dumps(spec)))
        assert result2.vulnerable is True
        assert result2.ctx["seen_owner"] == "alice"

    def test_unknown_action_aborts(self, env):
        _rb, _db, client = env
        spec = {"steps": [{"action": "teleport", "name": "x"}]}
        result = ChainRunner(client, Database(":memory:")).run(spec)
        assert result.vulnerable is False
        assert result.classification == "inconclusive"

    def test_fails_without_auth_harness(self, tmp_path):
        rb_path = tmp_path / "rb.yaml"
        rb_path.write_text(yaml.safe_dump({
            "name": "lab", "scope": [{"host": "127.0.0.1", "allow_private": True}],
        }), encoding="utf-8")
        client = EnforcingClient(Rulebook.load(rb_path), Database(tmp_path / "x.db"))
        with pytest.raises(Exception):
            ChainRunner(client, Database(":memory:"))


class TestChainTool:
    def test_tool_stores_finding_with_evidence_bundle(self, env):
        _rb, db, client = env
        res = ChainTool(client, db).run(
            template="cross-account-create-read", base_url=BASE,
            create_path="/api/notes", read_path_template="/api/note/{id}?debug=vuln",
            body={"title": "tool-note"},
        )
        assert res.ok and "finding #" in res.output
        row = db.list_findings()[0]
        assert row["vuln_type"] == "Access control (chained)"
        ev = json.loads(row["evidence"])
        assert ev["chain"]["template"] == "cross-account-create-read"
        assert ev["vulnerable"] is True
        assert ev["classification"] == "idor-chain"
        assert "side_effects" in ev["chain"]

    def test_tool_safe_target_records_nothing(self, env):
        _rb, db, client = env
        res = ChainTool(client, db).run(
            template="cross-account-create-read", base_url=BASE,
            create_path="/api/notes", read_path_template="/api/note/{id}",
        )
        assert res.ok and "no finding recorded" in res.output
        assert db.list_findings() == []

    def test_unknown_template_rejected(self, env):
        _rb, db, client = env
        res = ChainTool(client, db).run(template="turn_into_frog", base_url=BASE,
                                        create_path="/x", read_path_template="/y")
        assert res.ok is False


class TestChainValidation:
    def test_validator_reexecutes_chain(self, env):
        rb, db, client = env
        ChainTool(client, db).run(
            template="cross-account-create-read", base_url=BASE,
            create_path="/api/notes", read_path_template="/api/note/{id}?debug=vuln",
        )
        fid = db.list_findings()[0]["id"]

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"is_vulnerability": "yes", "confidence": 0.9,
                                   "objections": [], "reasoning": "chain re-executed"})

        stats = Validator().validate_all(db, FakeProvider(), client, rb)
        row = [r for r in db.list_findings() if r["id"] == fid][0]
        assert row["status"] == "validated"
        ev = json.loads(row["evidence"])
        assert ev["revalidation"]["ok"] is True
        assert ev["revalidation"]["classification"] == "idor-chain"
        assert ev["revalidation"]["ctx"]["seen_owner"] == "alice"

    def test_validator_chain_fails_without_accounts(self, env, monkeypatch):
        rb, db, client = env
        ChainTool(client, db).run(
            template="cross-account-create-read", base_url=BASE,
            create_path="/api/notes", read_path_template="/api/note/{id}?debug=vuln",
        )
        # simulate lost credentials at validation time — a fresh CLI process
        # has no cached session, so clear the harness cache too
        monkeypatch.delenv("LAB_ALICE_PASSWORD", raising=False)
        client.auth.invalidate_all()
        Validator().validate_all(db, LLMProvider(), client, rb)
        row = db.list_findings()[0]
        assert row["status"] == "unverifiable"
