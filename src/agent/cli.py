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
from .recon.params import discover_hidden_params, mine_params
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


def _make_oob(enabled: bool):
    """Start an interactsh manager when available; degrade gracefully."""
    if not enabled:
        return None
    from .oob.interactsh import InteractshManager, InteractshError
    try:
        mgr = InteractshManager.start()
        console.print(f"[green]OOB channel up:[/green] {len(mgr.payloads)} callback payloads reserved")
        return mgr
    except InteractshError as exc:
        console.print(f"[yellow]OOB channel unavailable ({exc}) — blind vulns "
                      f"will stay unconfirmed[/yellow]")
        return None


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
    oob = _make_oob(enabled=True)
    hunter = MultiClassHunter(provider, client, db, rulebook, max_steps=max_steps,
                              auth_spec=auth_spec, oob=oob)
    result = hunter.run(classes=class_list)
    if oob is not None:
        oob.stop()
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
    oob = _make_oob(enabled=True)
    try:
        stats = Validator().validate_all(db, provider, client, rulebook, oob=oob)
    finally:
        if oob is not None:
            oob.stop()
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


@app.command("params")
def params_cmd(
    program: Path = typer.Argument(..., exists=True),
    url: str = typer.Option("", help="Also run hidden-param discovery on this URL"),
    max_requests: int = typer.Option(120, help="Request budget for discovery"),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Mine real parameters from pages/forms and (optionally) brute-force hidden ones."""
    rulebook = _load_program(program)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    stats = mine_params(client, db, rulebook)
    console.print(f"[bold]mining:[/bold] {stats}")
    if url:
        allowed, _ = rulebook.check(url)
        if not allowed:
            console.print("[red]url is out of scope — discovery skipped[/red]")
            raise typer.Exit(1)
        disc = discover_hidden_params(client, db, url, max_requests=max_requests)
        if disc.get("ok"):
            console.print(f"[bold]discovery:[/bold] spent {disc['requests_spent']} requests, "
                          f"found {[f['name'] for f in disc['found']]}")
        else:
            console.print(f"[red]discovery failed: {disc.get('error')}[/red]")
    table = Table(show_header=True)
    for col in ("host", "param", "kind", "source"):
        table.add_column(col)
    for r in db.list_params():
        table.add_row(r["host"], r["name"], r["kind"], r["source"])
    console.print(table)


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


@app.command("run-chain")
def run_chain(
    program: Path = typer.Argument(..., exists=True),
    template: str = typer.Option("cross-account-create-read"),
    base_url: str = typer.Option(..., help="e.g. http://host"),
    create_path: str = typer.Option(..., help="POST endpoint returning JSON with id"),
    read_path_template: str = typer.Option(..., help="e.g. /api/note/{id}?debug=vuln"),
    body: str = typer.Option("", help='JSON create body, e.g. \'{"title": "note"}\''),
    owner_field: str = typer.Option("owner"),
    id_field: str = typer.Option("id"),
    accounts: str = typer.Option("", help='JSON list of 2 account names'),
    db_path: str = typer.Option("agent.db"),
) -> None:
    """Run a prebuilt exploit chain (deterministic; no LLM)."""
    rulebook = _load_program(program)
    db = Database(db_path)
    client = EnforcingClient(rulebook, db)
    spec_auth = _auth_spec_for(rulebook)
    if spec_auth is None or not spec_auth.accounts:
        console.print("[red]rulebook has no auth: accounts — chains need sessions[/red]")
        raise typer.Exit(1)
    enable_auth(client, spec_auth)
    if accounts:
        try:
            accounts = json.loads(accounts)
        except json.JSONDecodeError as exc:
            console.print(f"[red]accounts is not valid JSON: {exc}[/red]")
            raise typer.Exit(1)
    from .hunt.chains import ChainTool
    tool = ChainTool(client, db)
    res = tool.run(template=template, base_url=base_url, create_path=create_path,
                   read_path_template=read_path_template,
                   body=(json.loads(body) if body else None),
                   owner_field=owner_field, id_field=id_field,
                   accounts=accounts)
    console.print(res.output)
    if not res.ok:
        raise typer.Exit(1)


@app.command("callback")
def callback_cmd(
    url: str = typer.Option(..., help="Target URL, e.g. http://127.0.0.1:8770"),
    objectives: str = typer.Option("", help="What you want found, e.g. 'xss and access control'"),
    notes: str = typer.Option("", help="Context for the report/digest, e.g. 'my local lab'"),
    port: int = typer.Option(0, help="Optional port override for the URL"),
    rate_limit: float = typer.Option(1.0, help="Requests per second (default 1.0)"),
) -> None:
    """One command, whole pipeline: probe -> mine -> hunt -> validate -> report.

    Generates a scope rulebook from --url automatically (loopback/private
    targets get allow_private with a loud warning — only point this at things
    you are authorized to test). Findings are DRAFTS; you approve everything.
    """
    import tempfile

    from urllib.parse import urlsplit, urlunsplit

    from .db import Database as _DB
    from .recon.inventory import Inventory
    from .recon.params import mine_params
    from .scope.client import host_resolves_private

    # ---- normalize the URL with the optional port
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        console.print("[red]--url must be an absolute http(s) URL[/red]")
        raise typer.Exit(1)
    host = parts.hostname
    netloc = host
    if port:
        netloc = f"{host}:{port}"
    elif parts.port:
        netloc = f"{host}:{parts.port}"
    target = urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))

    # ---- generate the rulebook from the URL
    private = host_resolves_private(host)
    scope_entries = [{"host": host, "allow_private": True}]
    if host in ("127.0.0.1", "localhost"):
        other = "localhost" if host == "127.0.0.1" else "127.0.0.1"
        scope_entries.append({"host": other, "allow_private": True})
    rb_data = {
        "name": f"callback-{host}",
        "notes": notes or f"operator target {target}",
        "rate_limit": {"requests_per_second": max(0.1, float(rate_limit))},
        "automation_policy": "allowed",
        "scope": scope_entries,
    }
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        import yaml as _yaml
        _yaml.safe_dump(rb_data, fh)
        rb_path = Path(fh.name)
    rulebook = Rulebook.load(rb_path)
    console.print(f"[bold]Program:[/bold] {rulebook.name}  "
                  f"[bold]rate:[/bold] {rate_limit} rps")
    if private:
        console.print("[yellow]WARNING: target resolves to a private/loopback "
                      "address — only proceed if you own/are authorized for it.[/yellow]")

    db = _DB("agent.db")
    client = EnforcingClient(rulebook, db)

    # ---- seed the inventory with the operator's URL (one live fetch)
    inv = Inventory(db, rulebook)
    try:
        inv.add_host(host, "operator")
    except Exception as exc:  # noqa: BLE001 — OOS is impossible here (we wrote the rulebook)
        console.print(f"[red]seed failed: {exc}[/red]")
        raise typer.Exit(1)
    status, title = 0, ""
    try:
        resp = client.get(target)
        status, title = resp.status_code, resp.text.split("<title>", 1)[-1].split("</title>", 1)[0][:120]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]target fetch failed ({exc}) — continuing[/yellow]")
    inv.probe_result(host, target, status, title, [])
    console.print(f"[bold]target:[/bold] {target}  [bold]status:[/bold] {status or '?'}")

    # ---- cheap coverage: mine real params from the reachable pages
    mining = mine_params(client, db, rulebook, max_pages=10)
    console.print(f"[bold]mining:[/bold] {mining}")

    # ---- hunt (LLM) with OOB when available
    provider = LLMProvider()
    oob = _make_oob(enabled=True)
    try:
        hunter = MultiClassHunter(provider, client, db, rulebook, max_steps=12,
                                  oob=oob, operator_objectives=objectives)
        hunt_result = hunter.run()
        console.print(f"[bold]hypotheses:[/bold] {hunt_result['hypotheses']}  "
                      f"[bold]dropped (known-rejected):[/bold] "
                      f"{hunt_result.get('dropped_as_rejected', 0)}")
        for cls, summaries in hunt_result["sessions"].items():
            console.print(f"[bold green]{cls}[/bold green]: {summaries[-1]}")

        # ---- validate
        stats = Validator().validate_all(db, provider, client, rulebook, oob=oob)
        console.print(f"[bold]validation:[/bold] {stats}")
    finally:
        if oob is not None:
            oob.stop()

    # ---- report
    written = write_reports(db, "reports")
    for p in written:
        console.print(f"[green]wrote[/green] {p}")

    # ---- final summary: everything awaits YOUR approval
    table = Table(show_header=True)
    for col in ("id", "type", "url", "confidence", "status"):
        table.add_column(col)
    for f in db.list_findings():
        table.add_row(str(f["id"]), f["vuln_type"], f["url"],
                      str(f["confidence"]), f["status"])
    console.print(table)
    tamper = len(db.list_tamper_events())
    if tamper:
        console.print(f"[yellow]{tamper} tamper event(s) logged — scanned pages "
                      f"tried to prompt-inject the agent (see tamper_events)[/yellow]")
    console.print("[bold]All findings are drafts. A human reviews and submits — "
                  "the agent cannot.[/bold]")


@app.command("ps-bench")
def ps_bench_cmd(
    url: str = typer.Option(..., help="Lab instance URL from your browser"),
    lab_class: str = typer.Option(..., help="xss | sqli | redirect | ssrf | idor | access"),
    objectives: str = typer.Option("", help="Optional operator objectives"),
    db_path: str = typer.Option("", help="Per-run DB path (default: timestamped)"),
    max_steps: int = typer.Option(10, help="Max steps per hunter session"),
) -> None:
    """Run the FULL pipeline autonomously against one PortSwigger lab instance.

    Human input is exactly: launch lab in browser -> paste URL here -> later
    confirm solved/unsolved with ps-bench-score. Everything else is the agent.
    """
    from .psbench import run_lab_pipeline
    run = run_lab_pipeline(url=url, lab_class=lab_class.lower().strip(),
                           objectives=objectives, db_path=db_path or None,
                           console=console, max_steps=max_steps)
    n = sum(1 for _ in (Path("benchmarks") / "psbench-runs.jsonl").open()) if \
        (Path("benchmarks") / "psbench-runs.jsonl").exists() else 0
    console.print(f"[bold]run #{n} recorded[/bold] — score it with: "
                  f"[bold]bounty-agent ps-bench-score {n} --solved/--unsolved "
                  f"--agrees/--disagrees[/bold]")


@app.command("ps-bench-score")
def ps_bench_score_cmd(
    seq: int = typer.Argument(..., help="Run number (from ps-bench output)"),
    solved: bool = typer.Option(False, "--solved", help="Lab banner says solved"),
    unsolved: bool = typer.Option(False, "--unsolved", help="Lab not solved"),
    agrees: bool = typer.Option(False, "--agrees", help="You agree with the validated finding(s)"),
    disagrees: bool = typer.Option(False, "--disagrees", help="Validated finding(s) wrong/FP"),
) -> None:
    """Attach YOUR scoring to a recorded run (the only human input in the gate)."""
    from .psbench import gate_status, score_run
    if solved == unsolved:
        console.print("[red]pass exactly one of --solved / --unsolved[/red]")
        raise typer.Exit(1)
    row = score_run(seq=seq, solved=solved,
                    agrees=(True if agrees else False if disagrees else None))
    console.print(f"[green]scored run #{seq}[/green]: "
                  f"solved={row['human_solved']} agrees={row['human_agrees']}")
    status = gate_status()
    console.print(f"[bold]gate:[/bold] {status['scored']}/{status['gate_min_runs']} "
                  f"scored runs, solve {status['solve_rate']:.0%}, "
                  f"precision {status['precision']:.0%} "
                  f"-> {'[green]PASS[/green]' if status['gate'] else status['reason']}")


@app.command("ps-gate")
def ps_gate_cmd() -> None:
    """Show PortSwigger gate readiness (solve rate + precision vs. targets)."""
    from .psbench import gate_status
    s = gate_status()
    for k, v in s.items():
        console.print(f"[bold]{k}:[/bold] {v}")


@app.command("lessons")
def lessons_cmd(
    db_path: str = typer.Option("agent.db"),
    host: str = typer.Option("", help="Filter by host"),
) -> None:
    """Show accumulated hunt memory (known rejections / trap regressions)."""
    db = Database(db_path)
    rows = db.list_lessons(host=host or None)
    if not rows:
        console.print("[yellow]no lessons recorded yet[/yellow]")
        raise typer.Exit(0)
    table = Table(show_header=True)
    for col in ("weight", "signature", "lesson", "source"):
        table.add_column(col)
    for r in rows:
        table.add_row(str(r["weight"]), r["signature"], r["lesson"][:60], r["source"])
    console.print(table)


def main() -> None:
    app()
