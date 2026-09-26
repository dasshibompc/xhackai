"""Hunter sessions: the LLM hunts one vulnerability class at a time with a
specialized system prompt, deterministic probe tools, and a narrow objective.

This is the M3 replacement for the generic hunt loop: instead of one agent
vaguely "looking for bugs", each session is an expert in a single class with
the right toolset — cheaper on free models and far more consistent.
"""
from __future__ import annotations

from ..db import Database
from ..llm.provider import LLMProvider
from ..loop import AgentLoop
from ..scope.auth import AuthSpec, enable_auth
from ..scope.client import EnforcingClient
from ..scope.rulebook import Rulebook
from ..tools import GrepTool, HttpRequestTool, SaveFindingTool
from .access import AccessMatrixTool
from .hypotheses import Hypothesis, propose_hypotheses
from .probes import build_probe_tools

DISCOVERY_RULE = (
    "METHOD: Never probe guessed parameters. First use http_request to fetch the "
    "target page(s) and any linked pages listed in the hypotheses; identify REAL "
    "parameters, forms (note method=GET vs POST), and object references from the "
    "actual responses. Only then probe parameters you have seen the app accept."
)

CLASS_PROMPTS = {
    "xss": (
        "You specialize in reflected XSS and template injection. For each target "
        "parameter: send a benign baseline, then test reflection with the probe tool. "
        "When the probe reports raw reflection, try to understand the HTML context "
        "(fetch the page, inspect surrounding markup) and state what a real exploit "
        "would require. Record a finding only for confirmed injection points."
    ),
    "sqli": (
        "You specialize in SQL injection. Use probe_sqli on interesting parameters "
        "(search, filter, sort, id). A finding requires an SQL error signature or a "
        "reproducible boolean differential. Never dump data — detection only. If the "
        "parameter comes from a POST form, call probe_sqli with method=POST."
    ),
    "ssrf": (
        "You specialize in SSRF. Look for parameters that take URLs, hosts, or paths "
        "(fetch, url, target, redirect, proxy, source, feed, img). Use probe_ssrf. "
        "A finding requires internal-service evidence or an OOB callback. If an OOB "
        "domain is provided, use it and report the interaction."
    ),
    "redirect": (
        "You specialize in open redirects. Test redirect-ish parameters (next, url, "
        "return, redirect, goto, continue, target) with probe_redirect. A finding "
        "requires a Location header leaving the origin authority."
    ),
    "idor": (
        "You specialize in IDOR/access control. Identify object references in URLs "
        "or parameters (numeric ids, uuids, emails). Use probe_idor to check whether "
        "foreign objects are returned without denial. Only record findings where the "
        "response strongly indicates another user's data."
    ),
}


IDOR_MATRIX_PROMPT = (
    " You also have the access_matrix tool: when test accounts are configured, "
    "prefer it over probe_idor — pass url_template with an {id} placeholder and "
    "ids mapping each account name to its own object id. It baselines every "
    "account's own object first, then tests cross-account access."
)


class HunterSession:
    """Runs a specialized AgentLoop for one vulnerability class."""

    def __init__(self, provider: LLMProvider, client: EnforcingClient,
                 db: Database, rulebook: Rulebook, max_steps: int = 12,
                 auth_spec: AuthSpec | None = None) -> None:
        self.provider = provider
        self.client = client
        self.db = db
        self.rulebook = rulebook
        self.max_steps = max_steps
        self.auth_spec = auth_spec

    def _tools(self) -> dict:
        http_tool = HttpRequestTool(self.client)
        tools = {
            http_tool.name: http_tool,
            GrepTool(http_tool).name: GrepTool(http_tool),
            SaveFindingTool(self.db).name: SaveFindingTool(self.db),
        }
        tools.update(build_probe_tools(self.client, self.db))
        if self.auth_spec is not None and self.auth_spec.accounts:
            tools["access_matrix"] = AccessMatrixTool(self.client, self.db, self.auth_spec)
        return tools

    def hunt(self, vuln_class: str, hypotheses: list[Hypothesis]) -> str:
        if vuln_class not in CLASS_PROMPTS:
            raise ValueError(f"unknown vuln class: {vuln_class}")
        objective_lines = [
            f"Program: {self.rulebook.name} (authorized bug bounty target).",
            f"Focus class: {vuln_class}.",
            "Candidate hypotheses from recon (test them in order):",
        ]
        for i, h in enumerate(hypotheses, 1):
            line = f"{i}. [{h.vuln_class}] {h.url}"
            if h.param:
                line += f" param={h.param}"
            if h.reason:
                line += f" — {h.reason}"
            objective_lines.append(line)
        objective = "\n".join(objective_lines)

        loop = AgentLoop(self.provider, self._tools(), self.db, max_steps=self.max_steps)
        class_prompt = CLASS_PROMPTS[vuln_class]
        if vuln_class == "idor" and "access_matrix" in loop.tools:
            class_prompt += IDOR_MATRIX_PROMPT
        # the specialized prompt must enumerate the real toolset, or free models
        # will invent tool names — build the system string from the registry
        system = DISCOVERY_RULE + "\n\n" + class_prompt + (
            "\n\nAvailable tools:\n" + loop._tool_list()
            + '\n\nThe tool "finish" ends the session: '
              '{"tool": "finish", "args": {"summary": "..."}}'
            + "\nWork step by step and reply with EXACTLY ONE JSON object per step:\n"
              '{"thought": "...", "action": {"tool": "<name>", "args": {...}}}\n'
        )
        # AgentLoop builds its own system prompt from SYSTEM_PROMPT; we subclass
        # behaviour by passing the specialized prompt via objective injection.
        return loop.run_with_system(system, objective)


class MultiClassHunter:
    """Hypothesize once, then run a hunter session per class with candidates."""

    def __init__(self, provider: LLMProvider, client: EnforcingClient,
                 db: Database, rulebook: Rulebook, max_steps: int = 12,
                 auth_spec: AuthSpec | None = None) -> None:
        self.provider = provider
        self.client = client
        self.db = db
        self.rulebook = rulebook
        self.max_steps = max_steps
        self.auth_spec = auth_spec

    def run(self, classes: list[str] | None = None) -> dict:
        hypotheses = propose_hypotheses(self.provider, self.db, self.rulebook)
        results: dict[str, list[str]] = {}
        by_class: dict[str, list[Hypothesis]] = {}
        for h in hypotheses:
            by_class.setdefault(h.vuln_class, []).append(h)
        for cls, hyps in by_class.items():
            if classes and cls not in classes:
                continue
            session = HunterSession(self.provider, self.client, self.db,
                                    self.rulebook, self.max_steps,
                                    auth_spec=self.auth_spec)
            results[cls] = [session.hunt(cls, hyps)]
        return {"hypotheses": len(hypotheses), "sessions": results}
