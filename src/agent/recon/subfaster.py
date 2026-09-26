"""Passive subdomain enumeration via subfaster (speed-focused subfinder fork).

Passive: queries third-party datasets only. Its OUTPUT is the risk — every
discovered host is checked against the rulebook before entering the inventory.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import OutOfScopeError
from ..scope.rulebook import Rulebook
from .inventory import Inventory
from .runner import SUBFASTER, ToolRunner


@dataclass
class SubfasterResult:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    new_assets: int = 0


def run_subfaster(runner: ToolRunner, rulebook: Rulebook, inventory: Inventory,
                  domain: str, timeout: float = 180.0) -> SubfasterResult:
    if rulebook.automation_policy == "prohibited":
        raise OutOfScopeError(f"program {rulebook.name} prohibits automated testing")
    # defense in depth: only registrable domains derived from the rulebook itself
    if domain.lower().strip() not in rulebook.candidate_domains():
        raise OutOfScopeError(
            f"domain '{domain}' is not derived from the rulebook scope — refusing to enumerate"
        )
    # -silent is subfaster's default; stdout is one subdomain per line, sorted
    out = runner.run(SUBFASTER, ["-d", domain], timeout=timeout)
    result = SubfasterResult()
    for line in out.splitlines():
        host = line.strip().lower().rstrip(".")
        if not host:
            continue
        try:
            _asset_id, _ = inventory.add_host(host, source=f"subfaster:{domain}")
            result.in_scope.append(host)
            result.new_assets += 1
        except OutOfScopeError:
            result.out_of_scope.append(host)
    return result
