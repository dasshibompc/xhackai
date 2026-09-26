"""M5c tests: coverage engine — parameter mining, hidden-param differential
discovery, digest v2, and hypothesis generation over real params.
Offline except localhost lab; provider faked.
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
from agent.hunt.hypotheses import build_digest, propose_hypotheses  # noqa: E402
from agent.llm.provider import LLMProvider  # noqa: E402
from agent.recon.params import (  # noqa: E402
    discover_hidden_params,
    mine_params,
    parse_html_params,
)
from agent.scope.client import EnforcingClient  # noqa: E402
from agent.scope.rulebook import Rulebook  # noqa: E402

PORT = 8773
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


class TestHtmlParsing:
    def test_form_fields_extracted(self):
        html = ('<form><input name="email"><select name="plan">'
                '<textarea name="msg"></textarea><input></form>')
        forms, queries = parse_html_params(html)
        assert forms == {"email", "plan", "msg"}
        assert queries == set()

    def test_link_query_params_extracted(self):
        html = '<a href="/x?page=2&sort=desc&ignore">next</a>'
        forms, queries = parse_html_params(html)
        # `ignore` is a blank-valued flag param — still a real name
        assert queries == {"page", "sort", "ignore"}
        assert forms == set()

    def test_malformed_html_does_not_crash(self):
        forms, queries = parse_html_params("<form><input name='a' <b>broken")
        assert isinstance(forms, set)


class TestMining:
    def test_mines_forms_and_links_into_params_table(self, env):
        rb, db, client = env
        db.add_endpoint(f"{BASE}/contact", "link", source="test")
        db.conn.execute(
            "INSERT OR IGNORE INTO assets (host, first_seen, last_seen, in_scope,"
            " url) VALUES ('127.0.0.1', 0, 0, 1, ?)", (f"{BASE}/",))
        db.conn.commit()
        stats = mine_params(client, db, rb)
        assert stats["pages"] >= 1
        names = {r["name"] for r in db.list_params()}
        assert {"fullname", "email", "message", "department"} <= names
        kinds = {r["name"]: r["kind"] for r in db.list_params()}
        assert kinds["fullname"] == "form"
        assert kinds["q"] == "query"  # from the /search tip link

    def test_host_page_limit_respected(self, env):
        rb, db, client = env
        db.conn.execute(
            "INSERT OR IGNORE INTO assets (host, first_seen, last_seen, in_scope,"
            " url) VALUES ('127.0.0.1', 0, 0, 1, ?)", (f"{BASE}/",))
        db.conn.commit()
        stats = mine_params(client, db, rb, max_pages=1)
        assert stats["pages"] <= 1


class TestHiddenParams:
    def test_finds_render_param_on_console(self, env):
        rb, db, client = env
        res = discover_hidden_params(client, db, f"{BASE}/console",
                                     candidates=["render", "view", "mode", "lang"],
                                     max_requests=30)
        assert res["ok"]
        found = {f["name"] for f in res["found"]}
        assert "render" in found
        rows = db.list_params(kind="differential")
        assert any(r["name"] == "render" for r in rows)

    def test_clean_page_yields_nothing(self, env):
        rb, db, client = env
        res = discover_hidden_params(client, db, f"{BASE}/",
                                     candidates=["render", "debug", "mode"],
                                     max_requests=30)
        assert res["ok"] and res["found"] == []

    def test_budget_is_respected(self, env):
        rb, db, client = env
        res = discover_hidden_params(client, db, f"{BASE}/console",
                                     candidates=["a", "b", "c", "d", "e"],
                                     max_requests=5)  # 1 baseline + 2 per param
        assert res["ok"]
        assert res["requests_spent"] <= 5

    def test_out_of_scope_url_blocked(self, env):
        rb, db, client = env
        from agent.errors import OutOfScopeError
        with pytest.raises(OutOfScopeError):
            discover_hidden_params(client, db, "https://evil.com/console")


class TestDigestV2:
    def test_digest_contains_param_sections(self, env):
        rb, db, client = env
        db.add_param("render", "127.0.0.1", "differential", source="bruteforce")
        db.add_param("email", "127.0.0.1", "form", source="mining")
        db.add_param("q", "127.0.0.1", "query", source="mining")
        digest = json.loads(build_digest(db, rb))
        assert digest["differential_params"] == ["render"]
        assert digest["known_form_fields"] == ["email"]
        assert "q" in digest["known_params"]

    def test_hypothesis_params_must_exist_in_digest(self, env, monkeypatch):
        rb, db, _client = env
        db.add_param("render", "127.0.0.1", "differential", source="bruteforce")
        db.conn.execute(
            "INSERT OR IGNORE INTO assets (host, first_seen, last_seen, in_scope,"
            " url) VALUES ('127.0.0.1', 0, 0, 1, ?)", (f"{BASE}/console",))
        db.conn.commit()

        class FakeProvider(LLMProvider):
            def chat(self, system, user, temperature=0.2):
                # the model invents a param that is NOT in the digest
                return json.dumps({"hypotheses": [
                    {"url": f"{BASE}/console", "param": "render",
                     "vuln_class": "xss", "reason": "real param", "priority": 1},
                    {"url": f"{BASE}/console", "param": "totally_invented",
                     "vuln_class": "xss", "reason": "guessed", "priority": 2},
                ]})

        # note: build_digest holds the digest; the filter below checks scope,
        # class validity, and (new in M5c) param-name plausibility
        hyps = propose_hypotheses(FakeProvider(), db, rb)
        params_in_digest = set()
        digest = json.loads(build_digest(db, rb))
        params_in_digest.update(digest["known_params"])
        params_in_digest.update(digest["known_form_fields"])
        params_in_digest.update(digest["differential_params"])
        tested = [h for h in hyps if h.param]
        assert tested, "real-param hypothesis should survive filtering"
        assert all(h.param in params_in_digest for h in tested), \
            "guessed params must not survive into hunts"
