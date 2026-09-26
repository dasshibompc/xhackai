"""M4 benchmark suite: score the agent's hunting on a local vulnerable target.

Each benchmark defines seeded vulns + traps, runs a deterministic scenario,
and scores detections vs. traps avoided. Results append to
benchmarks/results.md (the tracker committed in PLAN.md section 11).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db import Database
from .errors import AgentError
from .scope.auth import AuthError, AuthSpec
from .scope.client import EnforcingClient

# Every run appends to this file next to the CLI working directory.
BENCH_DIR = Path("benchmarks")
RESULTS_MD = "results.md"


@dataclass
class BenchCase:
    """One benchmark case: a deterministic hunt scenario plus scoring."""
    name: str
    description: str
    finding_type: str  # expected vuln_type prefix of a correct detection
    url: str
    param: str | None
    # scenario-specific executor: returns (vulnerable_expected, notes, evidence)
    run: Any  # Callable[[EnforcingClient, Database, AuthSpec | None], tuple[bool, str, dict]]
    trap: bool = False  # trap cases must NOT yield a finding


@dataclass
class CaseResult:
    name: str
    trap: bool
    detected: bool
    classification: str = ""
    notes: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def score(self) -> float:
        if self.trap:
            return 1.0 if not self.detected else 0.0
        return 1.0 if self.detected else 0.0


def _seeded_finding_count(db: Database) -> int:
    rows = db.conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()
    return int(rows["n"])


def run_case(case: BenchCase, client: EnforcingClient, db: Database,
             auth_spec: AuthSpec | None) -> CaseResult:
    """Run one case via its scenario executor, then score the DB delta."""
    before = _seeded_finding_count(db)
    try:
        vulnerable_expected, notes, evidence = case.run(client, db, auth_spec)
    except (AuthError, AgentError) as exc:
        vulnerable_expected, notes, evidence = False, f"case error: {exc}", {}
    after = _seeded_finding_count(db)
    detected = after > before
    result = CaseResult(
        name=case.name, trap=case.trap, detected=detected,
        classification=("trap-avoided" if (case.trap and not detected)
                        else ("hit" if detected else "miss")),
        notes=notes, evidence=evidence,
    )
    if case.trap and detected:
        # M5e: a fired trap is a regression — store it as a lesson so the
        # next hunt avoids the pattern that produced it
        from .hunt.lessons import signature_of
        try:
            db.add_lesson(
                signature=signature_of(case.finding_type, case.url, case.param),
                lesson=f"benchmark trap '{case.name}' fired — {case.description}",
                source="bench-trap", host="",
            )
        except Exception:  # noqa: BLE001 — feedback never breaks scoring
            pass
    return result


def run_benchmark_suite(cases: list[BenchCase], client: EnforcingClient,
                        db: Database, auth_spec: AuthSpec | None = None,
                        only: list[str] | None = None) -> dict[str, Any]:
    """Run all (or a subset of) cases; aggregate precision-style metrics."""
    results: list[CaseResult] = []
    for case in cases:
        if only and case.name not in only:
            continue
        results.append(run_case(case, client, db, auth_spec))
    traps = [r for r in results if r.trap]
    hits = [r for r in results if not r.trap]
    trap_avoided = sum(1 for r in traps if not r.detected)
    detected = sum(1 for r in hits if r.detected)
    total = len(results)
    score = (sum(r.score for r in results) / total) if total else 0.0
    return {
        "results": results,
        "summary": {
            "cases": total,
            "detections": f"{detected}/{len(hits)}",
            "traps_avoided": f"{trap_avoided}/{len(traps)}",
            "score": round(score, 3),
        },
    }


def save_benchmarks(results: dict[str, Any], out_dir: Path = BENCH_DIR) -> Path:
    """Append a scored run to benchmarks/results.md and a JSON sidecar."""
    out_dir.mkdir(exist_ok=True)
    md_path = out_dir / RESULTS_MD
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    s = results["summary"]
    lines = [
        f"## Run — {ts}",
        "",
        f"- cases: {s['cases']}  |  detections: {s['detections']}  |  "
        f"traps avoided: {s['traps_avoided']}  |  score: {s['score']}",
        "",
        "| case | kind | result | notes |",
        "|------|------|--------|-------|",
    ]
    for r in results["results"]:
        kind = "trap" if r.trap else "vuln"
        outcome = ("avoided" if r.trap and not r.detected
                   else "TRIGGERED" if r.trap else
                   "hit" if r.detected else "miss")
        lines.append(f"| {r.name} | {kind} | {outcome} | {r.notes[:120]} |")
    lines.append("")
    with md_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    (out_dir / "last-run.json").write_text(
        json.dumps({
            "ts": ts,
            "summary": s,
            "cases": [{"name": r.name, "trap": r.trap, "detected": r.detected,
                       "classification": r.classification, "notes": r.notes}
                      for r in results["results"]],
        }, indent=1),
        encoding="utf-8",
    )
    return md_path


def print_results(results: dict[str, Any], console: Any) -> None:
    """Rich table output for the CLI."""
    from rich.table import Table

    table = Table(show_header=True)
    for col in ("case", "kind", "result", "notes"):
        table.add_column(col)
    for r in results["results"]:
        kind = "trap" if r.trap else "vuln"
        outcome = ("avoided" if r.trap and not r.detected
                   else "TRIGGERED" if r.trap else
                   "hit" if r.detected else "miss")
        table.add_row(r.name, kind, outcome, r.notes[:100])
    console.print(table)
    s = results["summary"]
    console.print(f"[bold]score:[/bold] {s['score']}  "
                  f"({s['detections']} detections, {s['traps_avoided']} traps avoided)")
