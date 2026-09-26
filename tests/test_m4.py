"""M4 tests: auth harness, multi-account access matrix, matrix re-validation,
and the benchmark scoring engine — against the real lab app (in-process).
No LLM key required; validator interactions are faked.
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
from agent.errors import AgentError, OutOfScopeError  # noqa: E402
from agent.hunt.access import AccessMatrix, AccessMatrixTool  # noqa: E402
from agent.hunt.probes import IdorProbeTool, RedirectProbeTool  # noqa: E402
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.scope.auth import AuthError, AuthSpec, SessionManager, enable_auth  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402
from agent.validate.validator import Validator  # noqa: E402

PORT = 8769
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
def env(tmp_path, lab_server, accounts_env, monkeypatch):
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
    return rulebook, db, client


class TestAuthSpec:
    def test_parse_and_env_resolution(self, accounts_env):
        spec = AuthSpec({"accounts": [
            {"name": "alice", "env_prefix": "LAB_ALICE",
             "login_url": f"{BASE}/login-session"},
        ]})
        material = spec.resolve("alice")
        assert material["data"] == {"username": "alice", "password": "123456"}
        assert material["login_url"].endswith("/login-session")
        assert spec.has_credentials("alice") is True

    def test_missing_env_raises(self, monkeypatch):
        monkeypatch.delenv("LAB_MISSING_USERNAME", raising=False)
        monkeypatch.delenv("LAB_MISSING_PASSWORD", raising=False)
        spec = AuthSpec({"accounts": [{"name": "ghost", "env_prefix": "LAB_MISSING",
                                       "login_url": f"{BASE}/login-session"}]})
        with pytest.raises(AuthError):
            spec.resolve("ghost")
        assert spec.has_credentials("ghost") is False
        assert spec.missing_env_vars()["ghost"] == [
            "LAB_MISSING_USERNAME", "LAB_MISSING_PASSWORD"]

    def test_unknown_account(self):
        spec = AuthSpec({})
        with pytest.raises(AuthError):
            spec.resolve("nobody")

    def test_header_mode_with_env_placeholder(self, monkeypatch):
        monkeypatch.setenv("LAB_SVC_KEY", "key123")
        spec = AuthSpec({
            "session_mode": "header",
            "accounts": [{"name": "svc", "env_prefix": "LAB_SVC",
                          "headers": {"X-API-Key": "{LAB_SVC_KEY}"}}],
        })
        material = spec.resolve("svc")
        assert material["headers"] == {"X-API-Key": "key123"}
        assert spec.recommended_env_names("svc") == "LAB_SVC_KEY"

    def test_header_placeholder_missing_env(self):
        spec = AuthSpec({"accounts": [{"name": "svc", "env_prefix": "LAB_SVC",
                                       "headers": {"X-API-Key": "{LAB_SVC_KEY}"}}]})
        with pytest.raises(AuthError):
            spec.resolve("svc")

    def test_load_from_missing_file_gives_empty_spec(self, tmp_path):
        spec = AuthSpec.load(tmp_path / "nope.yaml")
        assert spec.accounts == {}


class TestSessions:
    def test_cookie_login_and_identity(self, env):
        _rb, _db, client = env
        spec = AuthSpec({
            "session_mode": "cookie",
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        sm = SessionManager(client, spec)
        sess = sm.get_session("alice")
        assert sess["cookies"].get("sid"), "lab app must set a sid cookie"

    def test_bad_password_raises(self, env, monkeypatch):
        _rb, _db, client = env
        monkeypatch.setenv("LAB_ALICE_PASSWORD", "wrong")
        spec = AuthSpec({
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        with pytest.raises(AuthError):
            SessionManager(client, spec).get_session("alice")

    def test_cache_reuse_and_invalidation(self, env):
        _rb, _db, client = env
        spec = AuthSpec({
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        sm = SessionManager(client, spec)
        first = sm.get_session("alice")
        assert sm.get_session("alice") is first  # cached, no re-login
        sm.invalidate("alice")
        second = sm.get_session("alice", fresh=True)
        assert second["cookies"]["sid"] != first["cookies"]["sid"]


class TestClientAccount:
    def test_account_request_carries_session(self, env):
        _rb, _db, client = env
        spec = AuthSpec({
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        enable_auth(client, spec)
        resp = client.get(f"{BASE}/api/me", account="alice")
        assert resp.status_code == 200
        assert "alice" in resp.text

    def test_unauthenticated_is_401(self, env):
        _rb, _db, client = env
        resp = client.get(f"{BASE}/api/me")
        assert resp.status_code == 401

    def test_account_without_harness_raises(self, env):
        _rb, _db, client = env
        with pytest.raises(AgentError):
            client.get(f"{BASE}/api/me", account="alice")

    def test_scope_checked_before_auth(self, env):
        _rb, db, client = env
        spec = AuthSpec({
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        enable_auth(client, spec)
        with pytest.raises(OutOfScopeError):
            client.get("https://evil.com/api/me", account="alice")

    def test_audit_log_records_account(self, env):
        rb, db, client = env
        spec = AuthSpec({
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        enable_auth(client, spec)
        client.get(f"{BASE}/api/me", account="alice")
        rows = db.conn.execute(
            "SELECT reason FROM audit_log WHERE reason LIKE 'account=%'"
        ).fetchall()
        assert any("account=alice" in r["reason"] for r in rows)


class TestAccessMatrix:
    def test_vuln_mode_matrix_classifies_idor(self, env):
        _rb, _db, client = env
        spec = AuthSpec({
            "accounts": [
                {"name": "alice", "env_prefix": "LAB_ALICE",
                 "login_url": f"{BASE}/login-session"},
                {"name": "bob", "env_prefix": "LAB_BOB",
                 "login_url": f"{BASE}/login-session"},
            ],
        })
        matrix = AccessMatrix(client, Database(":memory:"), spec)
        result = matrix.run(f"{BASE}/api/invoice/{{id}}?debug=vuln",
                            ids={"alice": "101", "bob": "102"})
        assert result.vulnerable is True
        assert result.classification == "idor"
        bob_reads_alice = [c for c in result.cells
                           if c.actor == "bob" and c.object_owner == "alice"]
        assert bob_reads_alice and bob_reads_alice[0].status == 200
        assert bob_reads_alice[0].body_marker_seen is True  # "alice" in body

    def test_safe_mode_matrix_classifies_secure(self, env):
        _rb, _db, client = env
        spec = AuthSpec({
            "accounts": [
                {"name": "alice", "env_prefix": "LAB_ALICE",
                 "login_url": f"{BASE}/login-session"},
                {"name": "bob", "env_prefix": "LAB_BOB",
                 "login_url": f"{BASE}/login-session"},
            ],
        })
        matrix = AccessMatrix(client, Database(":memory:"), spec)
        result = matrix.run(f"{BASE}/api/invoice/{{id}}",
                            ids={"alice": "101", "bob": "102"})
        assert result.vulnerable is False
        assert result.classification == "secure"

    def test_single_account_is_inconclusive(self, env):
        _rb, _db, client = env
        spec = AuthSpec({
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        matrix = AccessMatrix(client, Database(":memory:"), spec)
        result = matrix.run(f"{BASE}/api/invoice/{{id}}?debug=vuln",
                            ids={"alice": "101"})
        assert result.vulnerable is False
        assert result.classification == "inconclusive"

    def test_template_without_placeholder_raises(self, env):
        _rb, _db, client = env
        spec = AuthSpec({
            "accounts": [{"name": "alice", "env_prefix": "LAB_ALICE",
                          "login_url": f"{BASE}/login-session"}],
        })
        matrix = AccessMatrix(client, Database(":memory:"), spec)
        with pytest.raises(AgentError):
            matrix.run(f"{BASE}/api/invoice/101", ids={"alice": "101"})

    def test_tool_stores_finding_only_when_vulnerable(self, env):
        _rb, db, client = env
        spec = AuthSpec({
            "accounts": [
                {"name": "alice", "env_prefix": "LAB_ALICE",
                 "login_url": f"{BASE}/login-session"},
                {"name": "bob", "env_prefix": "LAB_BOB",
                 "login_url": f"{BASE}/login-session"},
            ],
        })
        tool = AccessMatrixTool(client, db, spec)
        res = tool.run(url_template=f"{BASE}/api/invoice/{{id}}?debug=vuln",
                       ids='{"alice": "101", "bob": "102"}')
        assert res.ok and "finding #" in res.output
        row = db.list_findings()[0]
        assert row["vuln_type"] == "IDOR (cross-account matrix)"
        evidence = json.loads(row["evidence"])
        assert evidence["ids"] == {"alice": "101", "bob": "102"}
        assert evidence["id_param"] == "id"

        res2 = tool.run(url_template=f"{BASE}/api/invoice/{{id}}",
                        ids={"alice": "101", "bob": "102"})
        assert res2.ok and "no finding recorded" in res2.output
        assert len(db.list_findings()) == 1


class TestMatrixValidation:
    def test_matrix_finding_revalidates(self, env):
        rb, db, client = env
        spec = AuthSpec(rb.auth)
        AccessMatrixTool(client, db, spec).run(
            url_template=f"{BASE}/api/invoice/{{id}}?debug=vuln",
            ids={"alice": "101", "bob": "102"})

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"is_vulnerability": "yes", "confidence": 0.9,
                                   "objections": [], "reasoning": "matrix reproduces"})

        stats = Validator().validate_all(db, FakeProvider(), client, rb)
        row = db.list_findings()[0]
        assert row["status"] == "validated"
        reval = json.loads(row["evidence"])["revalidation"]
        assert reval["ok"] and reval["classification"] == "idor"
        assert stats["upgraded"] == 1

    def test_matrix_finding_without_ids_becomes_unverifiable(self, env):
        rb, db, client = env
        db.add_finding("IDOR (cross-account matrix)", f"{BASE}/api/invoice/101",
                       evidence={"url_template": f"{BASE}/api/invoice/{{id}}"},
                       confidence=0.6)
        Validator().validate_all(db, LLMProvider(), client, rb)
        row = db.list_findings()[0]
        assert row["status"] == "unverifiable"


class TestBenchmarks:
    def test_full_lab_suite_scores_perfect(self, env, monkeypatch):
        import agent.bench_scenarios as bs
        rb, db, client = env
        monkeypatch.setattr(bs, "BASE", BASE)  # tests run the lab on PORT
        spec = AuthSpec(rb.auth)
        from agent.benchmarks import run_benchmark_suite
        results = run_benchmark_suite(bs.BENCH_SUITES, client, db, spec)
        s = results["summary"]
        assert s["detections"] == "3/3", s
        assert s["traps_avoided"] == "3/3", s
        assert s["score"] == 1.0

    def test_results_appended_to_tracker(self, env, monkeypatch, tmp_path):
        import agent.bench_scenarios as bs
        rb, db, client = env
        monkeypatch.setattr(bs, "BASE", BASE)
        spec = AuthSpec(rb.auth)
        from agent.benchmarks import run_benchmark_suite, save_benchmarks
        results = run_benchmark_suite(bs.BENCH_SUITES, client, db, spec)
        md_path = save_benchmarks(results, out_dir=tmp_path / "benchmarks")
        text = md_path.read_text(encoding="utf-8")
        assert "## Run" in text and "idor-matrix-alice-bob" in text
        assert (tmp_path / "benchmarks" / "last-run.json").exists()


class TestCli:
    def test_auth_status_lists_accounts(self, env, tmp_path):
        from typer.testing import CliRunner
        from agent.cli import app
        rb, _db, _client = env
        result = CliRunner().invoke(app, ["auth-status", str(tmp_path / "rb.yaml")])
        assert result.exit_code == 0
        assert "alice" in result.output and "bob" in result.output
        assert "ready" in result.output

    def test_access_matrix_command_stores_finding(self, env, tmp_path):
        from typer.testing import CliRunner
        from agent.cli import app
        rb, _db, _client = env
        result = CliRunner().invoke(app, [
            "access-matrix", str(tmp_path / "rb.yaml"),
            f"{BASE}/api/invoice/{{id}}?debug=vuln",
            '{"alice": "101", "bob": "102"}',
            "--db-path", str(tmp_path / "cli.db"),
        ])
        assert result.exit_code == 0, result.output
        assert "idor" in result.output
        db = Database(tmp_path / "cli.db")
        assert db.list_findings(), "CLI matrix must store the candidate finding"

    def test_bench_command_runs_and_writes_tracker(self, env, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        import agent.bench_scenarios as bs
        monkeypatch.setattr(bs, "BASE", BASE)
        monkeypatch.chdir(tmp_path)  # benchmarks/ tracker lands in tmp
        from agent.cli import app
        rb, _db, _client = env
        result = CliRunner().invoke(app, [
            "bench", str(tmp_path / "rb.yaml"),
            "--db-path", str(tmp_path / "bench.db"),
        ])
        assert result.exit_code == 0, result.output
        assert "score" in result.output
        assert (tmp_path / "benchmarks" / "results.md").exists()

    def test_old_probes_still_work_alongside(self, env):
        _rb, db, client = env
        RedirectProbeTool(client, db).run(url=f"{BASE}/redirect", param="url")
        IdorProbeTool(client, db).run(url_template=f"{BASE}/api/invoice/{{id}}",
                                      id_a="101", id_b="102")
        # redirect stores a finding; probe_idor sees 401 denial and stores none
        assert len(db.list_findings()) == 1
