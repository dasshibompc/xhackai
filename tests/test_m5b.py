"""M5b tests: OOB callback loop — interactsh parsing, correlation semantics,
OOB-aware probes, LLM OOB tools, and validator integration. Fully offline:
the fake manager feeds interactions with no binary or network.
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
from agent.hunt.probes import probe_ssrf, probe_sqli_oob  # noqa: E402
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.oob.interactsh import (  # noqa: E402
    FakeInteractshManager,
    parse_interaction_line,
    parse_payload_store,
    unique_id_of,
    valid_payload,
)
from agent.oob.tools import build_oob_tools  # noqa: E402
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402
from agent.validate.validator import Validator  # noqa: E402

PORT = 8772
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


class TestParsing:
    def test_unique_id(self):
        assert unique_id_of("abc123def456.oast.live") == "abc123def456"
        assert unique_id_of("no-dots") == ""

    def test_valid_payload(self):
        assert valid_payload("abc123def456.oast.live") is True
        assert valid_payload("short.oast.live") is False
        assert valid_payload("not a payload") is False
        assert valid_payload("") is False

    def test_parse_payload_store(self):
        text = ("dartval900rjij5bhk3gpr3ah46hf5g6a.oast.live\n"
                "noise line without domain\n"
                "dartval900rjij5bhk3gmah8jcyedc9bp.oast.live\n"
                "dartval900rjij5bhk3gpr3ah46hf5g6a.oast.live\n")  # dup
        out = parse_payload_store(text)
        assert out == ["dartval900rjij5bhk3gpr3ah46hf5g6a.oast.live",
                       "dartval900rjij5bhk3gmah8jcyedc9bp.oast.live"]

    def test_parse_interaction_line(self):
        good = json.dumps({"protocol": "dns", "unique-id": "abc123def456",
                           "timestamp": "2026-09-26T12:00:00Z"})
        assert parse_interaction_line(good)["unique-id"] == "abc123def456"
        assert parse_interaction_line("[INF] banner") is None
        assert parse_interaction_line("{not json") is None
        assert parse_interaction_line('{"no": "uid"}') is None


class TestFakeManager:
    def test_reserve_is_exclusive(self):
        m = FakeInteractshManager(payloads=["p1aaaaaaaaaa.oast.fake",
                                           "p2bbbbbbbbbb.oast.fake"])
        a = m.reserve("probe-a")
        b = m.reserve("probe-b")
        assert a != b and m.reserve("probe-c") is None

    def test_poll_correlates_by_probe(self):
        m = FakeInteractshManager()
        p1 = m.reserve("probe-1")
        p2 = m.reserve("probe-2")
        m.inject(p1, protocol="dns")
        assert len(m.poll("probe-1")) == 1
        assert m.poll("probe-2") == []
        assert m.poll("unknown-probe") == []

    def test_unknown_interactions(self):
        m = FakeInteractshManager()
        p = m.reserve("probe-1")
        m.inject(p)
        m.inject("stranger99999999.oast.fake")
        assert len(m.unknown_interactions()) == 1


class TestSsrfProbeOob:
    def test_confirmed_callback_makes_finding(self, env):
        _rb, db, client = env
        oob = FakeInteractshManager()
        # The lab's /fetch will request our (unresolvable) callback host;
        # simulate the target-side callback firing ~1.5s into the wait window
        # against the payload the probe is about to reserve (pool order is
        # deterministic).
        first_payload = oob.payloads[0]
        threading.Timer(1.5, oob.inject, args=(first_payload,),
                        kwargs={"protocol": "http"}).start()
        res = probe_ssrf(client, f"{BASE}/fetch", "url", oob=oob, wait_seconds=6)
        assert res["ok"] and res["vulnerable"] is True
        assert res["oob"]["confirmed"] is True
        assert res["oob"]["interactions"] >= 1

    def test_no_callback_not_vulnerable(self, env):
        _rb, _db, client = env
        oob = FakeInteractshManager()
        res = probe_ssrf(client, f"{BASE}/fetch", "url", oob=oob, wait_seconds=2)
        # lab /fetch DOES fetch internal URLs -> internal differential may hit,
        # but the OOB block itself must be unconfirmed
        assert res["oob"]["confirmed"] is False

    def test_pool_exhaustion_degrades(self, env):
        _rb, _db, client = env
        oob = FakeInteractshManager(payloads=[])
        res = probe_ssrf(client, f"{BASE}/fetch", "url", oob=oob, wait_seconds=1)
        assert res["ok"] and res["oob"] is None


class TestSqliOob:
    def test_callback_confirms_blind_sqli(self, env):
        _rb, _db, client = env
        oob = FakeInteractshManager()
        # probe_sqli_oob reserves payloads[0] first thing; schedule the
        # target-side DNS callback against that exact payload
        threading.Timer(0.5, oob.inject, args=(oob.payloads[0],),
                        kwargs={"protocol": "dns"}).start()
        res = probe_sqli_oob(client, f"{BASE}/login", "username", oob,
                             method="POST", wait_seconds=4)
        assert res["ok"] and res["vulnerable"] is True
        assert res["signal"] == "oob-dns-callback"

    def test_no_callback_is_not_vulnerable(self, env):
        _rb, _db, client = env
        oob = FakeInteractshManager()
        res = probe_sqli_oob(client, f"{BASE}/login", "username", oob,
                             method="POST", wait_seconds=1)
        assert res["ok"] and res["vulnerable"] is False


class TestOobTools:
    def test_register_and_check_flow(self):
        oob = FakeInteractshManager()
        tools = build_oob_tools(oob)
        reg = tools["oob_register"].run(purpose="ssrf-test")
        data = json.loads(reg.output)
        assert data["payload"].endswith(".oast.fake")
        chk = tools["oob_check"].run(probe_id=data["probe_id"], wait_seconds=1)
        assert json.loads(chk.output)["confirmed"] is False

    def test_no_manager_returns_empty_tools(self):
        assert build_oob_tools(None) == {}

    def test_register_without_manager_fails_cleanly(self):
        from agent.oob.tools import OobRegisterTool
        res = OobRegisterTool(None).run(purpose="x")
        assert res.ok is False


class TestValidatorOob:
    def test_ssrf_finding_validates_with_oob(self, env):
        rb, db, client = env
        from agent.hunt.probes import SsrfProbeTool

        # every reserve() fires a target-side callback 0.3s later — this same
        # manager instance serves both the hunt and the validator re-run
        class AutoOob(FakeInteractshManager):
            def reserve(self, probe_id):
                p = super().reserve(probe_id)
                if p:
                    threading.Timer(0.3, self.inject, args=(p,),
                                    kwargs={"protocol": "http"}).start()
                return p

        oob = AutoOob()
        SsrfProbeTool(client, db, oob=oob).run(url=f"{BASE}/fetch", param="url")
        row = db.list_findings()[0]
        assert row["status"] == "candidate"

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                return json.dumps({"is_vulnerability": "yes", "confidence": 0.9,
                                   "objections": [], "reasoning": "oob callback reproduced"})

        stats = Validator().validate_all(db, FakeProvider(), client, rb, oob=oob)
        row = db.list_findings()[0]
        assert row["status"] == "validated"
        reval = json.loads(row["evidence"])["revalidation"]
        assert reval["oob"]["confirmed"] is True
