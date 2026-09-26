"""PortSwigger benchmark harness (M5 exit gate).

Runs the agent's full pipeline autonomously against one PortSwigger lab
instance — the human launches the lab in a browser, pastes the instance URL,
and later confirms whether the lab banner shows "solved". Everything between
is the agent: seed scope -> probe -> mine -> hunt (targeted class) -> validate
-> record a scored run.

Scoring model (per docs/PORTSWIGGER.md):
- a run is SCORED only when the human confirms the banner state
  (solved / unsolved) afterwards; the harness records everything else.
- precision is computed over runs the human has scored:
  precision = validated findings the human agrees with / validated findings.
- gate: >=80% solve rate over >=10 runs AND >=85% precision.

The human inputs are intentionally minimal: launch lab, paste URL, later type
`solved`/`unsolved`. This matches the operator model agreed for the project
(fully autonomous agent; humans flag interesting findings and verify PoCs).
"""
from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .db import Database
from .scope.client import EnforcingClient
from .scope.client import host_resolves_private
from .scope.rulebook import Rulebook

RESULTS_DIR = Path("benchmarks")
RESULTS_MD = RESULTS_DIR / "psbench-results.md"
# gate numbers agreed for the M5 exit gate (stricter than the old PLAN ones)
GATE_MIN_RUNS = 10
GATE_MIN_SOLVE = 0.80
GATE_MIN_PRECISION = 0.85


@dataclass
class BenchRun:
    url: str
    lab_class: str
    objectives: str
    db_path: str
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    status: str = "error"  # completed | error
    error: str = ""
    findings: list[dict] = field(default_factory=list)  # id/type/status/confidence
    validated: int = 0
    needs_review: int = 0
    rejected: int = 0
    unverifiable: int = 0
    human_solved: bool | None = None   # set later via `ps-bench-score`
    human_agrees: bool | None = None   # precision input (validated findings only)

    def row(self) -> dict[str, Any]:
        return {
            "url": self.url, "lab_class": self.lab_class,
            "objectives": self.objectives, "db_path": self.db_path,
            "started": self.started, "finished": self.finished,
            "status": self.status, "error": self.error[:200],
            "findings": self.findings,
            "human_solved": self.human_solved, "human_agrees": self.human_agrees,
        }


def _rulebook_for(url: str, lab_class: str, notes: str) -> Path:
    host = urlsplit(url).hostname or ""
    if not host:
        raise ValueError(f"cannot derive host from {url!r}")
    # local stand-ins (loopback) need the private opt-in; real lab hosts are
    # public so this flag is inert for them
    scope_entry: dict[str, Any] = {"host": host}
    if host_resolves_private(host):
        scope_entry["allow_private"] = True
    data = {
        "name": f"ps-{lab_class}-{host[:24]}",
        "notes": (notes or f"PortSwigger {lab_class} lab instance (ephemeral)")[:300],
        "rate_limit": {"requests_per_second": 5},  # be gentle: shared hardware
        "automation_policy": "allowed",
        "scope": [scope_entry],
    }
    fh = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    import yaml
    yaml.safe_dump(data, fh)
    fh.close()
    return Path(fh.name)


def run_lab_pipeline(url: str, lab_class: str, objectives: str = "",
                     db_path: str | None = None, console: Any = None,
                     max_steps: int = 10) -> BenchRun:
    """The full autonomous pipeline for one lab instance.

    Does NOT touch the network outside the lab host: the generated rulebook
    scopes to exactly the instance host, and every request flows through the
    EnforcingClient as usual.
    """
    from .hunt.session import MultiClassHunter
    from .llm.provider import LLMProvider
    from .recon.params import mine_params
    from .recon.inventory import Inventory
    from .report import write_reports
    from .validate.validator import Validator

    log = console.print if console else (lambda *a, **k: None)
    db_path = db_path or f"psbench-{int(time.time())}.db"
    run = BenchRun(url=url, lab_class=lab_class,
                   objectives=objectives or f"find {lab_class}", db_path=db_path)
    rb_path = _rulebook_for(url, lab_class, "")
    rulebook = Rulebook.load(rb_path)
    log(f"[bold]lab:[/bold] {url}  [bold]class:[/bold] {lab_class}  "
        f"[bold]scope:[/bold] {urlsplit(url).hostname}")

    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    inv = Inventory(db, rulebook)

    try:
        # 1) seed scope with the instance host
        host = urlsplit(url).hostname
        inv.add_host(host, "psbench")
        status, title = 0, ""
        try:
            resp = client.get(url)
            status = resp.status_code
            title = resp.text.split("<title>", 1)[-1].split("</title>", 1)[0][:120]
        except Exception as exc:  # noqa: BLE001
            log(f"[yellow]initial fetch failed: {exc}[/yellow]")
        inv.probe_result(host, url, status, title, [])
        log(f"[bold]target:[/bold] {url}  [bold]status:[/bold] {status or '?'}")

        # 2) cheap coverage pass
        mining = mine_params(client, db, rulebook, max_pages=10)
        log(f"[bold]mining:[/bold] {mining}")

        # 3) hunt the targeted class (OOB when available)
        provider = LLMProvider()
        oob = None
        try:
            from .cli import _make_oob
            oob = _make_oob(enabled=True)
        except Exception:  # noqa: BLE001
            oob = None
        try:
            hunter = MultiClassHunter(provider, client, db, rulebook,
                                      max_steps=max_steps, oob=oob)
            hunt_result = hunter.run(classes=[lab_class])
            log(f"[bold]hypotheses:[/bold] {hunt_result['hypotheses']}  "
                f"[bold]dropped:[/bold] {hunt_result.get('dropped_as_rejected', 0)}")
            for cls, summaries in hunt_result["sessions"].items():
                log(f"[bold green]{cls}[/bold green]: {summaries[-1]}")

            # 4) validate
            stats = Validator().validate_all(db, provider, client, rulebook, oob=oob)
            log(f"[bold]validation:[/bold] {stats}")
        finally:
            if oob is not None:
                oob.stop()

        # 5) reports + run record
        write_reports(db, "reports")
        run.status = "completed"
    except Exception as exc:  # noqa: BLE001 — a failed run is data too
        run.status = "error"
        run.error = str(exc)[:400]
        log(f"[red]run error: {exc}[/red]")

    run.finished = time.time()
    run.findings = [
        {"id": f["id"], "type": f["vuln_type"], "status": f["status"],
         "confidence": f["confidence"]}
        for f in db.list_findings()
    ]
    run.validated = sum(1 for f in run.findings if f["status"] == "validated")
    run.needs_review = sum(1 for f in run.findings if f["status"] == "needs-review")
    run.rejected = sum(1 for f in run.findings if f["status"] == "rejected")
    run.unverifiable = sum(1 for f in run.findings if f["status"] == "unverifiable")
    _append_run(run)
    return run


def _append_run(run: BenchRun) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    jsonl = RESULTS_DIR / "psbench-runs.jsonl"
    with jsonl.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(run.row()) + "\n")
    md = RESULTS_MD
    lines = [] if not md.exists() else ["", ""]
    lines = [
        "",
        f"## {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} — "
        f"{run.lab_class} — {run.url}",
        "",
        f"- status: {run.status}" + (f" ({run.error})" if run.error else ""),
        f"- findings: {run.validated} validated / {run.needs_review} needs-review / "
        f"{run.rejected} rejected / {run.unverifiable} unverifiable",
        "- scored: pending human confirmation",
        "",
    ]
    with md.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return md


def score_run(seq: int | None = None, solved: bool | None = None,
              agrees: bool | None = None, results_file: Path | None = None) -> dict:
    """Attach human scoring to run #seq (1-based, most recent last)."""
    results_file = results_file or (RESULTS_DIR / "psbench-runs.jsonl")
    rows = [json.loads(l) for l in results_file.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    if not rows:
        raise ValueError("no recorded runs to score")
    if seq is None:
        seq = len(rows)
    row = rows[seq - 1]
    if solved is not None:
        row["human_solved"] = bool(solved)
    if agrees is not None:
        row["human_agrees"] = bool(agrees)
    rows[seq - 1] = row
    results_file.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return row


def gate_status(results_file: Path | None = None) -> dict:
    """Compute solve rate + precision over scored runs; compare to the gate."""
    results_file = results_file or (RESULTS_DIR / "psbench-runs.jsonl")
    if not results_file.exists():
        return {"runs": 0, "scored": 0, "gate": False,
                "reason": "no recorded runs"}
    rows = [json.loads(l) for l in results_file.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    scored = [r for r in rows if r.get("human_solved") is not None]
    solved = sum(1 for r in scored if r["human_solved"])
    # precision over validated findings in scored runs where human_agrees set
    prec_runs = [r for r in scored if r.get("human_agrees") is not None]
    agree = sum(1 for r in prec_runs if r["human_agrees"])
    solve_rate = (solved / len(scored)) if scored else 0.0
    precision = (agree / len(prec_runs)) if prec_runs else 0.0
    enough = len(scored) >= GATE_MIN_RUNS
    gate = bool(enough and solve_rate >= GATE_MIN_SOLVE
                and precision >= GATE_MIN_PRECISION)
    return {
        "runs": len(rows), "scored": len(scored),
        "solved": solved, "solve_rate": round(solve_rate, 3),
        "precision_runs": len(prec_runs), "precision": round(precision, 3),
        "gate_min_runs": GATE_MIN_RUNS, "gate_min_solve": GATE_MIN_SOLVE,
        "gate_min_precision": GATE_MIN_PRECISION,
        "gate": gate,
        "reason": "" if gate else (
            f"need {GATE_MIN_RUNS - len(scored)} more scored runs"
            if not enough else
            f"solve {solve_rate:.0%} < {GATE_MIN_SOLVE:.0%} or "
            f"precision {precision:.0%} < {GATE_MIN_PRECISION:.0%}"),
    }
