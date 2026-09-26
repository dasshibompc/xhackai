"""Deterministic tool layer. Every tool is scope-safe: network access only
exists through the EnforcingClient, and save_finding only records evidence."""
from __future__ import annotations

import abc
from dataclasses import dataclass

import httpx

from .db import Database
from .errors import AgentError
from .scope.client import EnforcingClient


@dataclass
class ToolResult:
    ok: bool
    output: str


class Tool(abc.ABC):
    name: str
    description: str

    @abc.abstractmethod
    def run(self, **kwargs) -> ToolResult: ...


class HttpRequestTool(Tool):
    name = "http_request"
    description = (
        "Send a GET/POST/PUT/DELETE to an in-scope URL. Returns status, interesting "
        "headers, and a body snippet. Out-of-scope or private-address requests are blocked."
    )

    def __init__(self, client: EnforcingClient) -> None:
        self.client = client

    last_output: str = ""

    def run(self, url: str, method: str = "GET", body: str | None = None,
            headers: dict[str, str] | None = None) -> ToolResult:
        try:
            resp = self.client.request(
                method.upper(), url, headers=headers,
                content=body if method.upper() not in ("GET", "HEAD", "DELETE", "OPTIONS") else None,
            )
            summary = self.client.summarize(resp)
            self.last_output = summary
            return ToolResult(True, summary)
        except httpx.HTTPError as exc:
            return ToolResult(False, f"request failed: {exc}")
        except AgentError as exc:
            return ToolResult(False, str(exc))


class GrepTool(Tool):
    name = "grep_response"
    description = "Search the last HTTP response body snippet for a pattern. Cheap way to confirm markers."

    def __init__(self, http_tool: HttpRequestTool) -> None:
        self.http_tool = http_tool

    def run(self, pattern: str) -> ToolResult:
        # We re-search the cached last summary; keeps the agent from re-requesting.
        import re as _re
        last = getattr(self.http_tool, "last_output", "") or ""
        hits = [ln for ln in last.splitlines() if _re.search(pattern, ln)]
        return ToolResult(True, "\n".join(hits[:20]) or "no matches")


class SaveFindingTool(Tool):
    name = "save_finding"
    description = (
        "Record a candidate vulnerability. Requires vuln_type, url, evidence "
        "(what you did and what you observed), confidence 0-1."
    )

    def __init__(self, db: Database) -> None:
        self.db = db

    def run(self, vuln_type: str, url: str, evidence: str,
            confidence: float = 0.5, parameter: str | None = None) -> ToolResult:
        fid = self.db.add_finding(
            vuln_type=vuln_type, url=url, evidence=evidence,
            parameter=parameter, confidence=float(confidence),
        )
        return ToolResult(True, f"finding #{fid} recorded (status: candidate)")


TOOL_CLASSES = [HttpRequestTool, GrepTool, SaveFindingTool]
