"""PortSwigger benchmark harness tests — uses the local lab as a stand-in
for a lab instance; provider faked at the LLM boundary.
"""
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

PORT = 8777
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
def bench_env(tmp_path, monkeypatch, lab_server):
    """Isolate benchmarks/ output and fake the LLM."""
    import yaml as _yaml
    from agent import cli as cli_mod
    from agent import psbench as ps
    from agent.llm.provider import LLMProvider
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ps, "RESULTS_DIR", tmp_path / "benchmarks")
    monkeypatch.setattr(ps, "RESULTS_MD", tmp_path / "benchmarks" / "psbench-results.md")

    hunter_steps = {"n": 0}

    class FakeProvider(LLMProvider):
        def chat(self, system, user, temperature=0.2):
            if "is_vulnerability" in system:  # validator debate
                return json.dumps({"is_vulnerability": "yes", "confidence": 0.9,
                                   "objections": [], "reasoning": "reproducible"})
            if "vuln_class" in system:  # hypothesis planner
                return json.dumps({"hypotheses": [
                    {"url": f"{BASE}/redirect", "param": "url",
                     "vuln_class": "redirect", "reason": "redirect param",
                     "priority": 1},
                ]})
            # hunter session: probe the lab's redirect, then finish
            hunter_steps["n"] += 1
            if hunter_steps["n"] % 2 == 1:
                return json.dumps({"thought": "probe it", "action": {
                    "tool": "probe_redirect",
                    "args": {"url": f"{BASE}/redirect", "param": "url"}}})
            return json.dumps({"thought": "done", "action": {
                "tool": "finish", "args": {"summary": "ok"}}})

    monkeypatch.setattr(cli_mod, "_make_oob", lambda enabled: None)
    # patch the source class AND every from-import binding site (function-scoped
    # imports like psbench's resolve through agent.llm.provider at call time)
    monkeypatch.setattr("agent.llm.provider.LLMProvider", FakeProvider)
    import agent.hunt.hypotheses as _hyp
    import agent.hunt.session as _sess
    import agent.validate.validator as _val
    import agent.loop as _loop
    monkeypatch.setattr(_hyp, "LLMProvider", FakeProvider)
    monkeypatch.setattr(_sess, "LLMProvider", FakeProvider)
    monkeypatch.setattr(_val, "LLMProvider", FakeProvider)
    monkeypatch.setattr(_loop, "LLMProvider", FakeProvider)
    yield tmp_path


class TestPipeline:
    def test_full_run_records_scoreable_run(self, bench_env):
        from agent.psbench import run_lab_pipeline
        run = run_lab_pipeline(url=BASE, lab_class="redirect",
                               db_path=str(bench_env / "run.db"))
        assert run.status == "completed"
        assert run.validated >= 1, "lab open redirect must validate"
        assert (bench_env / "benchmarks" / "psbench-runs.jsonl").exists()
        assert (bench_env / "benchmarks" / "psbench-results.md").exists()

    def test_scoring_and_gate_math(self, bench_env):
        from agent.psbench import gate_status, run_lab_pipeline, score_run
        for i in range(3):
            run_lab_pipeline(url=BASE, lab_class="redirect",
                             db_path=str(bench_env / f"run{i}.db"))
        # human scores: 2 solved 1 unsolved; agrees on 2 of 3
        score_run(1, solved=True, agrees=True)
        score_run(2, solved=True, agrees=True)
        score_run(3, solved=False, agrees=False)
        s = gate_status()
        assert s["scored"] == 3
        assert abs(s["solve_rate"] - 2 / 3) < 0.01
        assert abs(s["precision"] - 2 / 3) < 0.01
        assert s["gate"] is False  # only 3 scored; gate needs >=10
        assert "more scored runs" in s["reason"]

    def test_gate_pass_condition(self, bench_env):
        from agent.psbench import gate_status, run_lab_pipeline, score_run
        for i in range(10):
            run_lab_pipeline(url=BASE, lab_class="redirect",
                             db_path=str(bench_env / f"g{i}.db"))
        for i in range(1, 11):
            score_run(i, solved=(i <= 9), agrees=(i <= 9))
        s = gate_status()
        assert s["scored"] == 10
        assert s["solve_rate"] == 0.9
        assert s["precision"] == 0.9
        assert s["gate"] is True

    def test_broken_target_records_error_run(self, bench_env):
        from agent.psbench import run_lab_pipeline
        run = run_lab_pipeline(url="http://127.0.0.1:1/", lab_class="redirect",
                               db_path=str(bench_env / "dead.db"))
        # pipeline must not crash; run is recorded (error or zero findings)
        assert run.status in ("completed", "error")
