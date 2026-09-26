"""M4 lab benchmark scenarios: deterministic cases against the local lab app.

Each scenario uses the SAME code paths the agent uses (probe tools, matrix
tool), so findings appear in the DB exactly as a real hunt would record them.
The suite runner scores detections via the findings-table delta.

Trap cases are canaries: they emulate a naive hunter's mistake and must yield
NO finding. If a trap ever fires, either the lab app drifted or the
deterministic layer got weaker — fix before trusting any numbers.
"""
from __future__ import annotations

from typing import Any, Callable

from .benchmarks import BenchCase
from .db import Database
from .hunt.access import AccessMatrix, AccessMatrixTool
from .scope.auth import AuthSpec
from .scope.client import EnforcingClient

BASE = "http://127.0.0.1:8770"

CaseFn = Callable[[EnforcingClient, Database, "AuthSpec | None"], tuple[bool, str, dict]]


def _matrix_case(accounts: list[str], vulnerable_mode: bool = True) -> CaseFn:
    """Matrix run over the lab's invoice endpoint via the storing Tool (the
    same path an LLM hunter would take). vulnerable_mode adds the ?debug=vuln
    flag that enables the lab's broken-access-control behavior."""
    def run(client: EnforcingClient, db: Database,
            auth_spec: AuthSpec | None) -> tuple[bool, str, dict]:
        if auth_spec is None or not auth_spec.accounts:
            return False, "no test accounts configured", {}
        template = f"{BASE}/api/invoice/{{id}}"
        if vulnerable_mode:
            template += "?debug=vuln"
        tool = AccessMatrixTool(client, db, auth_spec, accounts=accounts)
        res = tool.run(url_template=template, ids={"alice": "101", "bob": "102"})
        return res.ok, res.output[:200], {"tool_output": res.output[:500]}
    return run


def _redirect_case(client: EnforcingClient, db: Database,
                   auth_spec: AuthSpec | None) -> tuple[bool, str, dict]:
    from .hunt.probes import RedirectProbeTool
    res = RedirectProbeTool(client, db).run(url=f"{BASE}/redirect", param="url")
    return res.ok, res.output[:200], {}


def _xss_case(client: EnforcingClient, db: Database,
              auth_spec: AuthSpec | None) -> tuple[bool, str, dict]:
    from .hunt.probes import XssProbeTool
    res = XssProbeTool(client, db).run(url=f"{BASE}/search", param="q")
    return res.ok, res.output[:200], {}


def _idor_denied_trap(client: EnforcingClient, db: Database,
                      auth_spec: AuthSpec | None) -> tuple[bool, str, dict]:
    """Trap: probe_idor on a properly protected endpoint (no auth, no vuln
    flag) must report denial and record NOTHING."""
    from .hunt.probes import IdorProbeTool
    IdorProbeTool(client, db).run(url_template=f"{BASE}/api/invoice/{{id}}",
                                  id_a="101", id_b="102")
    return False, "foreign object denied — probe must stay silent", {}


def _matrix_secure_trap(client: EnforcingClient, db: Database,
                        auth_spec: AuthSpec | None) -> tuple[bool, str, dict]:
    """Trap: matrix with BOTH accounts against the correctly-protected
    endpoint (no debug=vuln) must classify secure and record nothing."""
    return _matrix_case(["alice", "bob"], vulnerable_mode=False)(client, db, auth_spec)


BENCH_SUITES: list[BenchCase] = [
    BenchCase(
        name="idor-matrix-alice-bob",
        description="cross-account IDOR matrix finds alice's/bob's invoices",
        finding_type="IDOR (cross-account matrix)",
        url=f"{BASE}/api/invoice/{{id}}?debug=vuln", param="id",
        run=_matrix_case(["alice", "bob"], vulnerable_mode=True),
    ),
    BenchCase(
        name="idor-matrix-alice-only",
        description="single-account matrix must stay inconclusive (no finding)",
        finding_type="IDOR (cross-account matrix)",
        url=f"{BASE}/api/invoice/{{id}}?debug=vuln", param="id",
        run=_matrix_case(["alice"], vulnerable_mode=True),
        trap=True,
    ),
    BenchCase(
        name="open-redirect",
        description="redirect probe detects the open redirect",
        finding_type="Open Redirect (probe)",
        url=f"{BASE}/redirect", param="url",
        run=_redirect_case,
    ),
    BenchCase(
        name="reflected-xss",
        description="reflection probe detects raw marker echo",
        finding_type="Reflected XSS/SSTI (probe)",
        url=f"{BASE}/search", param="q",
        run=_xss_case,
    ),
    BenchCase(
        name="idor-denied-trap",
        description="probe_idor on a protected endpoint records nothing",
        finding_type="IDOR (probe)",
        url=f"{BASE}/api/invoice/{{id}}", param="id",
        run=_idor_denied_trap,
        trap=True,
    ),
    BenchCase(
        name="matrix-secure-trap",
        description="matrix on a correctly-protected endpoint records nothing",
        finding_type="IDOR (cross-account matrix)",
        url=f"{BASE}/api/invoice/{{id}}", param="id",
        run=_matrix_secure_trap,
        trap=True,
    ),
]


def lab_bench_cases() -> list[BenchCase]:
    """The lab benchmark suite (M4)."""
    return BENCH_SUITES
