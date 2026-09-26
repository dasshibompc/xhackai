"""Recon pipeline: passive enum -> inventory -> active probe -> JS crawl ->
endpoint extraction -> (optional) nuclei.

Each stage is independently callable; run() chains them with per-stage error
capture so one broken tool degrades gracefully instead of killing the pass.
"""
from __future__ import annotations

import time

from rich.console import Console

from ..db import Database
from ..scope.rulebook import Rulebook
from .httpx_probe import run_httpx
from .inventory import Inventory
from .katana import run_katana
from .nuclei_scan import run_nuclei
from .runner import ToolRunner
from .subfaster import run_subfaster
from .xnlinkfinder import run_xnlinkfinder


class ReconPipeline:
    def __init__(self, runner: ToolRunner, db: Database, rulebook: Rulebook,
                 console: Console | None = None) -> None:
        self.runner = runner
        self.db = db
        self.rulebook = rulebook
        self.inventory = Inventory(db, rulebook)
        self.console = console or Console()

    def subdomain_pass(self) -> dict:
        summary: dict = {"domains": [], "in_scope": 0, "out_of_scope_ignored": 0, "errors": []}
        for domain in self.rulebook.candidate_domains():
            self.console.print(f"[bold]subfaster[/bold] <- {domain}")
            try:
                res = run_subfaster(self.runner, self.rulebook, self.inventory, domain)
                summary["domains"].append(domain)
                summary["in_scope"] += len(res.in_scope)
                summary["out_of_scope_ignored"] += len(res.out_of_scope)
            except Exception as exc:  # noqa: BLE001 — stage isolation
                summary["errors"].append(f"subfaster {domain}: {exc}")
        return summary

    def probe_pass(self) -> dict:
        self.console.print("[bold]httpx[/bold] probing in-scope hosts")
        try:
            return run_httpx(self.runner, self.inventory)
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc), "probed": [], "skipped_private": [], "count": 0}

    def js_pass(self, depth: int = 2) -> dict:
        """Crawl in-scope URLs with katana, then mine the discovered JS with xnLinkFinder."""
        urls = [
            r["url"]
            for r in self.db.conn.execute(
                "SELECT url FROM assets WHERE in_scope=1 AND url IS NOT NULL"
            ).fetchall()
        ]
        if not urls:
            self.console.print("[yellow]js pass skipped — probe pass produced no URLs yet[/yellow]")
            return {"katana": {"skipped": True}, "xnlinkfinder": {"skipped": True}}

        self.console.print(f"[bold]katana[/bold] crawling {len(urls)} URL(s)")
        try:
            katana_res = run_katana(self.runner, self.rulebook, self.db, urls, depth=depth)
        except Exception as exc:  # noqa: BLE001
            katana_res = {"error": str(exc), "js": 0, "links": 0}

        js_urls = [
            r["url"] for r in self.db.list_endpoints(kind="js")
        ]
        if js_urls:
            self.console.print(f"[bold]xnLinkFinder[/bold] mining {len(js_urls)} JS file(s)")
            try:
                xnl_res = run_xnlinkfinder(self.runner, self.rulebook, self.db, js_urls)
            except Exception as exc:  # noqa: BLE001
                xnl_res = {"error": str(exc), "links": 0, "params": 0, "secrets": 0}
        else:
            xnl_res = {"skipped": True, "reason": "no JS files discovered"}
        return {"katana": katana_res, "xnlinkfinder": xnl_res}

    def nuclei_pass(self) -> dict:
        urls = [
            r["url"]
            for r in self.db.conn.execute(
                "SELECT url FROM assets WHERE in_scope=1 AND url IS NOT NULL"
            ).fetchall()
        ]
        if not urls:
            self.console.print("[yellow]nuclei skipped — probe pass produced no URLs yet[/yellow]")
            return {"skipped": True, "findings": 0, "targets": 0}
        self.console.print(f"[bold]nuclei[/bold] scanning {len(urls)} URL(s)")
        try:
            return run_nuclei(self.runner, self.rulebook, self.db, urls)
        except Exception as exc:  # noqa: BLE001
            return {"findings": 0, "targets": len(urls), "error": str(exc)}

    def run(self, with_nuclei: bool = False, with_js: bool = False) -> dict:
        started = time.time()
        return {
            "subfaster": self.subdomain_pass(),
            "httpx": self.probe_pass(),
            "js": self.js_pass() if with_js else {"skipped": True},
            "nuclei": self.nuclei_pass() if with_nuclei else {"skipped": True},
            "inventory": self.inventory.summary(),
            "endpoints": len(self.db.list_endpoints()),
            "seconds": round(time.time() - started, 1),
        }
