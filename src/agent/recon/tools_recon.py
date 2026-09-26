"""LLM-facing recon tools: thin, scope-safe wrappers around the pipeline."""
from __future__ import annotations

from ..tools import Tool, ToolResult
from .katana import run_katana
from .pipeline import ReconPipeline
from .runner import ToolRunner
from .subfaster import run_subfaster
from .xnlinkfinder import run_xnlinkfinder


class SubfasterEnumTool(Tool):
    name = "subfaster_enum"
    description = (
        "Passive subdomain enumeration for one registrable domain already listed in "
        "the program rulebook (uses subfaster). Sends no traffic to the target. "
        "Discovered hosts are scope-filtered and added to the asset inventory; "
        "out-of-scope ones are ignored."
    )

    def __init__(self, runner: ToolRunner, pipeline: ReconPipeline) -> None:
        self.runner = runner
        self.pipeline = pipeline

    def run(self, domain: str) -> ToolResult:
        try:
            res = run_subfaster(self.runner, self.pipeline.rulebook,
                                self.pipeline.inventory, domain)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(False, f"subfaster failed: {exc}")
        return ToolResult(
            True,
            f"in_scope ({len(res.in_scope)}): {res.in_scope}\n"
            f"out_of_scope ignored: {len(res.out_of_scope)}\n"
            f"new inventory rows: {res.new_assets}",
        )


class ProbeHostsTool(Tool):
    name = "probe_hosts"
    description = (
        "Actively probe all in-scope inventory hosts with httpx (status code, title, "
        "tech). Private/loopback hosts are skipped in Docker mode. Use after "
        "subfaster_enum to learn which discovered hosts are live."
    )

    def __init__(self, runner: ToolRunner, pipeline: ReconPipeline) -> None:
        self.runner = runner
        self.pipeline = pipeline

    def run(self) -> ToolResult:
        res = self.pipeline.probe_pass()
        if "error" in res:
            return ToolResult(False, f"probe failed: {res['error']}")
        return ToolResult(
            True,
            f"probed {len(res.get('probed', []))} of {res.get('count', 0)} targets; "
            f"skipped_private={res.get('skipped_private', [])}",
        )


class FindEndpointsTool(Tool):
    name = "find_endpoints"
    description = (
        "Crawl in-scope URLs with katana to discover JS files and links, then mine "
        "them with xnLinkFinder for endpoints, potential parameters, and secrets "
        "(secrets become candidate findings for human review). Run after probe_hosts."
    )

    def __init__(self, runner: ToolRunner, pipeline: ReconPipeline) -> None:
        self.runner = runner
        self.pipeline = pipeline

    def run(self, depth: int = 2) -> ToolResult:
        res = self.pipeline.js_pass(depth=max(1, min(int(depth), 5)))
        if "error" in res.get("katana", {}):
            return ToolResult(False, f"katana failed: {res['katana']['error']}")
        return ToolResult(True, str(res))


def build_recon_tools(runner: ToolRunner, pipeline: ReconPipeline) -> dict[str, Tool]:
    a = SubfasterEnumTool(runner, pipeline)
    b = ProbeHostsTool(runner, pipeline)
    c = FindEndpointsTool(runner, pipeline)
    return {a.name: a, b.name: b, c.name: c}
