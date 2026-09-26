"""Active live-host probing via httpx.

Active tool: it sends requests. It only ever receives hosts that are already
in the inventory AND in scope (never raw wildcards). Private hosts are skipped
under Docker because containers cannot reach the host loopback.
"""
from __future__ import annotations

import ipaddress

from ..scope.client import host_resolves_private
from .inventory import Inventory
from .runner import HTTPX, ToolRunner, parse_json_lines


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def run_httpx(runner: ToolRunner, inventory: Inventory, timeout: float = 300.0,
              docker_mode: bool | None = None) -> dict:
    hosts = [h for h in inventory.in_scope_hosts() if h]
    if docker_mode is None:
        docker_mode = runner.modes.get("httpx") == "docker"
    targets, skipped_private = [], []
    for h in hosts:
        # loopback cannot be reached from a container; skip rather than fail
        if docker_mode and (h in ("localhost",) or _is_ip_literal(h)
                            and ipaddress.ip_address(h).is_loopback):
            skipped_private.append(h)
            continue
        if host_resolves_private(h) and not _is_ip_literal(h):
            skipped_private.append(h)
            continue
        targets.append(h)
    probed, failed = [], []
    if targets:
        out = runner.run(
            HTTPX,
            ["-silent", "-json", "-title", "-tech-detect", "-status-code",
             "-no-color", "-follow-redirects"],
            stdin_text="\n".join(targets),
            timeout=timeout,
        )
        for rec in parse_json_lines(out):
            host = str(rec.get("host") or rec.get("url") or "").lower()
            if "://" in host:
                from urllib.parse import urlparse
                host = urlparse(host).hostname or host
            if not host:
                continue
            try:
                inventory.probe_result(
                    host=host,
                    url=str(rec.get("url", "")),
                    status_code=int(rec.get("status_code") or 0),
                    title=str(rec.get("title") or "")[:200],
                    tech=[str(t) for t in rec.get("tech", [])],
                )
                probed.append(host)
            except Exception:
                failed.append(host)
    return {"probed": probed, "skipped_private": skipped_private,
            "unreachable": [h for h in targets if h not in probed and h not in failed],
            "failed": failed, "count": len(targets)}
