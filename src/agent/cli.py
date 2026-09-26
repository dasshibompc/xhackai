"""CLI entrypoint: hunt / recon / doctor / test-scope / findings / verify-audit."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .db import Database
from .hunt.access import AccessMatrix
from .hunt.session import MultiClassHunter
from .llm.provider import LLMProvider
from .loop import AgentLoop
from .recon.pipeline import ReconPipeline
from .recon.runner import ToolRunner, gather_environment
from .recon.tools_recon import build_recon_tools
from .report import write_reports
from .scope.auth import AuthSpec, enable_auth
from .scope.client import EnforcingClient
from .scope.rulebook import Rulebook
from .tools import GrepTool, HttpRequestTool, SaveFindingTool
from .validate.validator import Validator

app = typer.Typer(help="Scope-enforced autonomous bug bounty agent.")
console = Console()


def _load_program(program: Path) -> Rulebook:
    rulebook = Rulebook.load(program)
    if rulebook.automation_policy == "prohibited":
        console.print("[red]This program prohibits automated testing. Refusing to run.[/red]")
        raise typer.Exit(1)
    console.print(f"[bold]Program:[/bold] {rulebook.name}  [bold]Policy:[/bold] {rulebook.automation_policy}")
    return rulebook


def _auth_spec_for(rulebook: Rulebook) -> AuthSpec | None:
    """AuthSpec from a rulebook, or None when no accounts are configured."""
    if not rulebook.auth:
        return None
    return AuthSpec(rulebook.auth)


def _warn_accounts(spec: AuthSpec | None) -> None:
    """Report which test accounts are fully configured (env vars set)."""
    if spec is None or not spec.accounts:
        return
    for name, missing in spec.missing_env_vars().items():
        if missing:
            console.print(f"[yellow]account '{name}': missing env vars "
                          f"{', '.join(missing)} — requests will fail[/yellow]")
        else:
            console.print(f"[green]account '{name}': ready[/green]")


@app.command()
def doctor() -> None:
    """Check which recon tools are available and how to install missing ones."""
    runner = ToolRunner()
    for row in gather_environment(runner):
        status = row["status"]
        color = "green" if "MISSING" not in status and "NOT SET" not in status else (
            "yellow" if status in {"cli only", "NOT SET"} else "red"
        )
        line = f"[bold]{row['component']:<20}[/bold] [{color}]{status}[/]"
        if row["hint"]:
            line += f"  — {row['hint']}"
        console.print(line)


@app.command()
def recon(
    program: Path = typer.Argument(..., exists=True, help="Program rulebook YAML"),
    with_nuclei: bool = typer.Option(False, help="Also run a nuclei pass (slow)"),
    with_js: bool = typer.Option(False, help="Also crawl with katana and mine JS with xnLinkFinder"),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Run passive enum + live probing (optionally JS mining and nuclei)."""
    rulebook = _load_program(program)
    db = Database(db_path)
    runner = ToolRunner()
    pipeline = ReconPipeline(runner, db, rulebook, console)
    result = pipeline.run(with_nuclei=with_nuclei, with_js=with_js)

    table = Table(show_header=True)
    for col in ("in_scope", "host", "status", "title", "tech", "source"):
        table.add_column(col)
    for row in pipeline.inventory.render_table():
        table.add_row(*row)
    console.print(table)
    console.print(f"[bold]summary:[/bold] {result['inventory']}  "
                  f"[bold]errors:[/bold] {result['subfinder']['errors'] or 'none'}")


@app.command()
def hunt(
    program: Path = typer.Argument(..., exists=True),
    objective: str = typer.Option(..., help="Narrow objective for this run"),
    max_steps: int = typer.Option(15, help="Max agent steps (LLM calls)"),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Run the LLM agent (now with recon tools) against an authorized program."""
    rulebook = _load_program(program)
    db = Database(db_path)
    runner = ToolRunner()
    pipeline = ReconPipeline(runner, db, rulebook, console)
    client = EnforcingClient(rulebook, db)
    http_tool = HttpRequestTool(client)
    tools = {
        http_tool.name: http_tool,
        GrepTool(http_tool).name: GrepTool(http_tool),
        SaveFindingTool(db).name: SaveFindingTool(db),
    }
    tools.update(build_recon_tools(runner, pipeline))
    provider = LLMProvider()
    loop = AgentLoop(provider, tools, db, max_steps=max_steps)
    summary = loop.run(objective)
    console.print(f"\n[bold green]Session summary:[/bold green] {summary}")
    console.print("Findings are recorded as [italic]candidate[/italic] — review before any submission.")


@app.command()
def hunt_vulns(
    program: Path = typer.Argument(..., exists=True),
    classes: str = typer.Option("", help="Comma-separated vuln classes (default: all found)"),
    max_steps: int = typer.Option(12, help="Max steps per hunter session"),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Generate hypotheses from the inventory, then run per-class hunter sessions."""
    rulebook = _load_program(program)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    auth_spec = _auth_spec_for(rulebook)
    if auth_spec is not None and auth_spec.accounts:
        enable_auth(client, auth_spec)
        _warn_accounts(auth_spec)
    provider = LLMProvider()
    class_list = [c.strip().lower() for c in classes.split(",") if c.strip()] or None
    hunter = MultiClassHunter(provider, client, db, rulebook, max_steps=max_steps,
                              auth_spec=auth_spec)
    result = hunter.run(classes=class_list)
    console.print(f"[bold]hypotheses:[/bold] {result['hypotheses']}")
    for cls, summaries in result["sessions"].items():
        console.print(f"[bold green]{cls}[/bold green]: {summaries[-1]}")
    console.print("Findings recorded as [italic]candidate[/italic]. Run [bold]validate[/bold] next.")


@app.command()
def validate(
    program: Path = typer.Argument(..., exists=True),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Deterministically re-verify candidates, then run the adversarial debate."""
    rulebook = Rulebook.load(program)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    provider = LLMProvider()
    stats = Validator().validate_all(db, provider, client, rulebook)
    console.print(f"[bold]validation:[/bold] {stats}")
    console.print("Validated findings await [bold]human review[/bold] — the agent cannot submit.")


@app.command()
def report(
    db_path: str = typer.Option("agent.db"),
    out_dir: str = typer.Option("reports"),
) -> None:
    """Write markdown draft reports for validated / needs-review findings."""
    written = write_reports(Database(db_path), out_dir)
    for p in written:
        console.print(f"[green]wrote[/green] {p}")
    if not written:
        console.print("[yellow]no findings in validated/needs-review state[/yellow]")


@app.command()
def test_scope(
    program: Path = typer.Argument(..., exists=True),
    urls: list[str] = typer.Argument(..., help="URLs to check against scope"),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Dry-run the scope engine: does it allow or block each URL?"""
    rulebook = Rulebook.load(program)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    table = Table(show_header=True)
    table.add_column("URL")
    table.add_column("Decision")
    for url in urls:
        try:
            client.get(url)
            table.add_row(url, "[green]allowed[/green]")
        except Exception as exc:  # noqa: BLE001
            table.add_row(url, f"[red]blocked[/red] ({exc})")
    console.print(table)


@app.command()
def findings(db_path: str = typer.Option("agent.db")) -> None:
    """List recorded findings (all are unapproved candidates)."""
    db = Database(db_path)
    table = Table(show_header=True)
    for col in ("id", "type", "url", "confidence", "status"):
        table.add_column(col)
    for f in db.list_findings():
        table.add_row(str(f["id"]), f["vuln_type"], f["url"], str(f["confidence"]), f["status"])
    console.print(table)


@app.command()
def verify_audit(db_path: str = typer.Option("agent.db")) -> None:
    """Verify the hash-chained audit log has not been tampered with."""
    ok, n = Database(db_path).verify_audit_chain()
    console.print(f"[{'green' if ok else 'red'}]audit chain {'VALID' if ok else 'INVALID'}[/] ({n} entries)")


@app.command("auth-status")
def auth_status(
    program: Path = typer.Argument(..., exists=True),
) -> None:
    """Show configured test accounts and which env vars are missing."""
    rulebook = _load_program(program)
    spec = _auth_spec_for(rulebook)
    if spec is None or not spec.accounts:
        console.print("[yellow]no auth: section — unauthenticated testing only[/yellow]")
        raise typer.Exit(0)
    table = Table(show_header=True)
    for col in ("account", "mode", "env vars needed", "missing"):
        table.add_column(col)
    for name, missing in spec.missing_env_vars().items():
        mode = "cookie login" if spec.accounts[name].login_url else "header/token"
        table.add_row(
            name, mode, spec.recommended_env_names(name),
            "[green]none — ready[/green]" if not missing else "[red]" + ", ".join(missing) + "[/red]",
        )
    console.print(table)


@app.command("access-matrix")
def access_matrix(
    program: Path = typer.Argument(..., exists=True),
    url_template: str = typer.Argument(..., help="e.g. http://host/api/invoice/{id}"),
    ids: str = typer.Argument(..., help='JSON map account->object id'),
    id_param: str = typer.Option("id", help="Placeholder name in the template"),
    accounts: str = typer.Option("", help="Comma-separated account subset"),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Run the cross-account IDOR matrix (deterministic, no LLM)."""
    rulebook = _load_program(program)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    spec = _auth_spec_for(rulebook)
    if spec is None or not spec.accounts:
        console.print("[red]rulebook has no auth: accounts — cannot run the matrix[/red]")
        raise typer.Exit(1)
    enable_auth(client, spec)
    try:
        ids_map = json.loads(ids)
    except json.JSONDecodeError as exc:
        console.print(f"[red]ids is not valid JSON: {exc}[/red]")
        raise typer.Exit(1)
    if not isinstance(ids_map, dict) or not ids_map:
        console.print("[red]ids must map account -> object id[/red]")
        raise typer.Exit(1)
    account_list = [a.strip() for a in accounts.split(",") if a.strip()] or None
    matrix = AccessMatrix(client, db, spec, accounts=account_list)
    result = matrix.run(url_template, ids={str(k): str(v) for k, v in ids_map.items()},
                        id_param=id_param)
    table = Table(show_header=True)
    for col in ("actor", "object", "status", "len", "owner-marker", "vs-own"):
        table.add_column(col)
    for owner, b in result.baselines.items():
        table.add_row(f"{b.actor} (baseline)", owner, str(b.status),
                      str(b.body_len), str(b.body_marker_seen), "-")
    for c in result.cells:
        table.add_row(c.actor, c.object_owner, str(c.status), str(c.body_len),
                      str(c.body_marker_seen), str(c.differs_from_own_baseline))
    console.print(table)
    for note in result.notes:
        console.print(f"[italic]note:[/italic] {note}")
    console.print(f"[bold]classification:[/bold] {result.classification}")
    if result.vulnerable:
        fid = db.add_finding(
            vuln_type=("IDOR (cross-account matrix)" if result.classification == "idor"
                       else "Access control (probable IDOR matrix)"),
            url=url_template, parameter=id_param,
            evidence={**result.as_dict(), "ids": ids_map, "id_param": id_param},
            confidence=0.8 if result.classification == "idor" else 0.6,
        )
        console.print(f"[green]stored as candidate finding #{fid}[/green] — run [bold]validate[/bold] next")
    else:
        console.print("no finding recorded (precision-first)")


@app.command()
def bench(
    program: Path = typer.Argument(..., exists=True),
    suite: str = typer.Option("", help="Comma-separated case names (default: all)"),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Run the deterministic benchmark suite against a lab target and score it."""
    rulebook = _load_program(program)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    spec = _auth_spec_for(rulebook)
    if spec is not None and spec.accounts:
        enable_auth(client, spec)
    from .bench_scenarios import lab_bench_cases
    from .benchmarks import print_results, run_benchmark_suite, save_benchmarks
    only = [s.strip() for s in suite.split(",") if s.strip()] or None
    results = run_benchmark_suite(lab_bench_cases(), client, db, spec, only=only)
    print_results(results, console)
    path = save_benchmarks(results)
    console.print(f"[green]results appended to[/green] {path}")


def main() -> None:
    app()
