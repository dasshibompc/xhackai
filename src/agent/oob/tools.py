"""LLM-callable OOB tools (M5b).

The hunter LLM never touches the interactsh process directly: it registers a
reserved callback payload (getting a unique host + its probe_id back) and later
checks that probe_id for correlated interactions. All correlation semantics
(reserved-payload + unique-id match) stay in the manager, so a confused model
cannot promote someone else's callback into its evidence.
"""
from __future__ import annotations

import json
import time
import uuid

from ..tools import Tool, ToolResult


class OobRegisterTool(Tool):
    name = "oob_register"
    description = (
        "Reserve a unique out-of-band callback host for one blind-vuln test. "
        "Args: purpose (short label, e.g. 'ssrf-fetch'). Returns a payload host "
        "and probe_id. Embed the payload as PARAMETER DATA in an in-scope "
        "request (e.g. ?url=http://<payload>/x) — never as a request target."
    )

    def __init__(self, oob) -> None:
        self.oob = oob

    def run(self, purpose: str = "probe") -> ToolResult:
        if self.oob is None:
            return ToolResult(False, "no OOB manager configured for this run")
        probe_id = f"llm:{str(purpose)[:40]}:{uuid.uuid4().hex[:8]}"
        payload = self.oob.reserve(probe_id)
        if not payload:
            return ToolResult(False, "OOB payload pool exhausted — finish or reuse "
                                     "an existing probe_id with oob_check")
        return ToolResult(True, json.dumps({
            "probe_id": probe_id,
            "payload": payload,
            "usage": "inject http://<payload>/<path> as a parameter value in an "
                     "in-scope request, then poll with oob_check",
        }))


class OobCheckTool(Tool):
    name = "oob_check"
    description = (
        "Check a reserved OOB probe for correlated callbacks. Args: probe_id "
        "(from oob_register) [, wait_seconds max 30]. A confirmed callback is "
        "strong evidence the target fetched our URL."
    )

    def __init__(self, oob) -> None:
        self.oob = oob

    def run(self, probe_id: str, wait_seconds: int = 8) -> ToolResult:
        if self.oob is None:
            return ToolResult(False, "no OOB manager configured for this run")
        deadline = time.time() + min(max(1, int(wait_seconds)), 30)
        while time.time() < deadline:
            events = self.oob.poll(str(probe_id))
            if events:
                protocols = sorted({str(e.get("protocol", "?")) for e in events})
                return ToolResult(True, json.dumps({
                    "confirmed": True,
                    "interactions": len(events),
                    "protocols": protocols,
                }))
            time.sleep(0.5)
        return ToolResult(True, json.dumps({
            "confirmed": False,
            "note": "no callbacks within the wait window — not evidence of absence, "
                    "re-check later or conclude",
        }))


def build_oob_tools(oob) -> dict[str, Tool]:
    """Empty when no manager is configured, so prompts stay honest."""
    if oob is None:
        return {}
    return {
        OobRegisterTool(oob).name: OobRegisterTool(oob),
        OobCheckTool(oob).name: OobCheckTool(oob),
    }
