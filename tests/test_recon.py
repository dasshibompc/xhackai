"""M2 recon tests using a fake ToolRunner — no external binaries or network."""
from __future__ import annotations

import pytest
import yaml

from agent.db import Database
from agent.errors import OutOfScopeError
from agent.db import Database as _DB  # noqa: F401
from agent.recon.httpx_probe import run_httpx
from agent.recon.inventory import Inventory
from agent.recon.katana import run_katana
from agent.recon.nuclei_scan import run_nuclei
from agent.recon.runner import (
    KATANA,
    NUCLEI,
    SUBFASTER,
    ToolUnavailable,
    gather_environment,
    parse_json_lines,
)
from agent.recon.subfaster import run_subfaster
from agent.scope.client import host_resolves_private
from agent.scope.rulebook import Rulebook


@pytest.fixture()
def rulebook(tmp_path):
    data = {
        "name": "test-prog",
        "rate_limit": {"requests_per_second": 100},
        "automation_policy": "allowed",
        "scope": [{"host": "*.example.com"}, {"host": "example.com"}],
    }
    p = tmp_path / "rulebook.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return Rulebook.load(p)


@pytest.fixture()
def db(tmp_path):
    return Database(tmp_path / "test.db")


@pytest.fixture()
def inventory(rulebook, db):
    return Inventory(db, rulebook)


class FakeRunner:
    """Scripted stand-in for ToolRunner: maps tool name -> canned stdout."""

    modes: dict = {}

    def __init__(self, outputs=None, fail=None):
        self.outputs = outputs or {}
        self.fail = fail or set()
        self.calls = []

    def run(self, spec, args, stdin_text=None, timeout=300.0, docker_mounts=None):
        self.calls.append((spec.name, args, stdin_text))
        if spec.name in self.fail:
            raise ToolUnavailable(f"{spec.name} unavailable (fake)")
        return self.outputs.get(spec.name, "")


class TestParseJsonLines:
    def test_parses_valid_lines(self):
        text = '{"a": 1}\nnot json\n{"b": 2}\n\n'
        assert parse_json_lines(text) == [{"a": 1}, {"b": 2}]

    def test_empty(self):
        assert parse_json_lines("") == []


class TestInventoryScopeGate:
    def test_in_scope_host_added(self, inventory):
        aid, in_scope = inventory.add_host("api.example.com", source="test")
        assert in_scope is True and aid > 0

    def test_out_of_scope_rejected_but_recorded(self, inventory, db):
        with pytest.raises(OutOfScopeError):
            inventory.add_host("evil.com", source="test")
        row = db.conn.execute("SELECT * FROM assets WHERE host='evil.com'").fetchone()
        assert row is not None and row["in_scope"] == 0
        ev = db.conn.execute("SELECT kind FROM asset_events").fetchone()
        assert ev["kind"] == "new"

    def test_wildcard_base_in_scope(self, inventory):
        _, in_scope = inventory.add_host("example.com", source="test")
        assert in_scope

    def test_duplicate_host_not_duplicated(self, inventory):
        inventory.add_host("a.example.com", source="t1")
        inventory.add_host("a.example.com", source="t2")
        rows = inventory.db.conn.execute("SELECT COUNT(*) c FROM assets").fetchone()
        assert rows["c"] == 1

    def test_probe_result_attached(self, inventory):
        aid, _ = inventory.add_host("api.example.com", source="test")
        inventory.probe_result("api.example.com", "https://api.example.com/", 200, "API Home", ["nginx"])
        row = inventory.db.conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        assert row["status_code"] == 200 and row["title"] == "API Home"

    def test_summary_counts(self, inventory):
        inventory.add_host("api.example.com", source="test")
        try:
            inventory.add_host("evil.com", source="test")
        except OutOfScopeError:
            pass
        s = inventory.summary()
        assert s["total"] == 2 and s["in_scope"] == 1 and s["new"] == 2


class TestSubfasterWrapper:
    def test_discovers_and_filters(self, rulebook, inventory, db):
        runner = FakeRunner(outputs={
            SUBFASTER.name: "\n".join([
                "api.example.com",
                "admin.example.com",
                "evil.com",
                "",
            ])
        })
        res = run_subfaster(runner, rulebook, inventory, "example.com")
        assert sorted(res.in_scope) == ["admin.example.com", "api.example.com"]
        assert res.out_of_scope == ["evil.com"]
        assert res.new_assets == 2

    def test_prohibited_policy_refuses(self, tmp_path, db, inventory):
        p = tmp_path / "rb.yaml"
        p.write_text(yaml.safe_dump({
            "name": "no-auto",
            "automation_policy": "prohibited",
            "scope": [{"host": "example.com"}],
        }), encoding="utf-8")
        rb = Rulebook.load(p)
        with pytest.raises(OutOfScopeError):
            run_subfaster(FakeRunner(), rb, inventory, "example.com")

    def test_domain_validated_before_launch(self, rulebook, inventory):
        runner = FakeRunner()
        with pytest.raises(OutOfScopeError):
            run_subfaster(runner, rulebook, inventory, "not-in-scope.test")
        assert runner.calls == []  # tool never launched


class TestHttpxProbe:
    def test_probes_in_scope_only(self, rulebook, inventory):
        inventory.add_host("api.example.com", source="test")
        inventory.add_host("example.com", source="test")
        try:
            inventory.add_host("evil.com", source="test")
        except OutOfScopeError:
            pass
        runner = FakeRunner(outputs={
            "httpx": "\n".join([
                '{"host": "api.example.com", "url": "https://api.example.com/", '
                '"status_code": 200, "title": "API", "tech": ["nginx"]}',
            ])
        })
        res = run_httpx(runner, inventory)
        assert res["probed"] == ["api.example.com"]
        (tool, args, stdin) = runner.calls[0]
        assert "evil.com" not in (stdin or "")  # never handed to the tool
        assert "api.example.com" in (stdin or "")

    def test_docker_mode_skips_loopback(self, tmp_path, db):
        p = tmp_path / "rb.yaml"
        p.write_text(yaml.safe_dump({
            "name": "lab",
            "rate_limit": {"requests_per_second": 100},
            "scope": [{"host": "127.0.0.1", "allow_private": True}],
        }), encoding="utf-8")
        inventory = Inventory(db, Rulebook.load(p))
        inventory.add_host("127.0.0.1", source="test")
        runner = FakeRunner(outputs={"httpx": ""})
        res = run_httpx(runner, inventory, docker_mode=True)
        assert res["skipped_private"] == ["127.0.0.1"]
        assert res["count"] == 0


class TestNucleiScan:
    def test_findings_recorded_with_confidence(self, rulebook, db):
        runner = FakeRunner(outputs={
            NUCLEI.name: '{"template-id": "xss-reflected", "matched-at": '
                         '"https://api.example.com/?q=x", "matcher-status": true, '
                         '"info": {"name": "Reflected XSS", "severity": "high", '
                         '"description": "d"}}'
        })
        res = run_nuclei(runner, rulebook, db, ["https://api.example.com/"])
        assert res["findings"] == 1
        f = db.list_findings()[0]
        assert f["vuln_type"] == "Reflected XSS" and f["status"] == "candidate"
        assert f["confidence"] == 0.8

    def test_out_of_scope_target_refuses_to_launch(self, rulebook, db):
        runner = FakeRunner()
        with pytest.raises(OutOfScopeError):
            run_nuclei(runner, rulebook, db, ["https://evil.com/"])
        assert runner.calls == []

    def test_no_targets_short_circuit(self, rulebook, db):
        assert run_nuclei(FakeRunner(), rulebook, db, []) == {"findings": 0, "targets": 0}

    def test_severity_confidence_mapping(self):
        from agent.recon.nuclei_scan import CONFIDENCE_BY_SEVERITY
        assert CONFIDENCE_BY_SEVERITY["critical"] == 0.9
        assert CONFIDENCE_BY_SEVERITY["info"] == 0.2


class TestKatanaWrapper:
    def test_crawls_and_filters_urls(self, rulebook, db):
        runner = FakeRunner(outputs={
            KATANA.name: "\n".join([
                "https://api.example.com/app.js",
                "https://api.example.com/page",
                "https://cdn.third-party.org/evil.js",
                "not-a-url-line",
            ])
        })
        res = run_katana(runner, rulebook, db, ["https://api.example.com/"])
        assert res["js"] == 1 and res["links"] == 1  # CDN URL filtered out
        kinds = {r["kind"] for r in db.list_endpoints()}
        assert kinds == {"js", "link"}

    def test_oos_target_refuses_to_launch(self, rulebook, db):
        runner = FakeRunner()
        with pytest.raises(OutOfScopeError):
            run_katana(runner, rulebook, db, ["https://evil.com/"])
        assert runner.calls == []

    def test_no_targets_short_circuit(self, rulebook, db):
        assert run_katana(FakeRunner(), rulebook, db, []) == {"js": 0, "links": 0, "targets": 0}


class TestScopeClientHelpers:
    def test_host_resolves_private_loopback(self):
        assert host_resolves_private("127.0.0.1") is True

    def test_host_resolves_private_public(self):
        # example.com must NOT resolve into private space
        assert host_resolves_private("example.com") is False


class TestDoctor:
    def test_gather_environment_missing_runner(self):
        rows = gather_environment(runner=None, docker_binary="", daemon_ok=False,
                                  api_key_set=False)
        by = {r["component"]: r for r in rows}
        assert by["docker"]["status"] == "missing"
        assert by["subfaster"]["status"] == "MISSING"
        assert "AGENT_LLM_API_KEY" in by

    def test_gather_environment_with_modes(self):
        class R:
            modes = {"subfaster": "binary", "httpx": "docker", "nuclei": None,
                     "katana": "binary", "xnLinkFinder": None}

        rows = gather_environment(runner=R(), docker_binary="/usr/bin/docker",
                                  daemon_ok=True, api_key_set=True)
        by = {r["component"]: r for r in rows}
        assert by["subfaster"]["status"] == "local binary"
        assert by["httpx"]["status"] == "docker image"
        assert by["nuclei"]["status"] == "MISSING"
        assert by["AGENT_LLM_API_KEY"]["status"] == "set"
