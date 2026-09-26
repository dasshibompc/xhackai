"""Program rulebook: YAML-defined scope, rate limits, and automation policy."""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..errors import OutOfScopeError


@dataclass(frozen=True)
class ScopeEntry:
    """One in-scope asset rule."""

    host: str  # literal host or wildcard pattern like *.example.com
    scheme: str | None = None  # None = any scheme
    path_prefix: str | None = None  # None = any path
    allow_private: bool = False  # opt-in for loopback/private hosts (labs only)


@dataclass
class Rulebook:
    name: str
    scope: list[ScopeEntry]
    out_of_scope: list[str] = field(default_factory=list)
    requests_per_second: float = 1.0
    automation_policy: str = "allowed"  # allowed | restricted | prohibited
    notes: str = ""

    # ----------------------------------------------------------------- parse

    @classmethod
    def load(cls, path: str | Path) -> "Rulebook":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        scope = [
            ScopeEntry(
                host=str(e["host"]).lower(),
                scheme=(str(e["scheme"]).lower() if e.get("scheme") else None),
                path_prefix=(str(e["path_prefix"]) if e.get("path_prefix") else None),
                allow_private=bool(e.get("allow_private", False)),
            )
            for e in raw.get("scope", [])
        ]
        if not scope:
            raise ValueError(f"rulebook {path} defines no in-scope assets")
        return cls(
            name=str(raw.get("name", "unnamed")),
            scope=scope,
            out_of_scope=[str(h).lower() for h in raw.get("out_of_scope", [])],
            requests_per_second=float(raw.get("rate_limit", {}).get("requests_per_second", 1.0)),
            automation_policy=str(raw.get("automation_policy", "allowed")).lower(),
            notes=str(raw.get("notes", "")),
        )

    # ---------------------------------------------------------------- checks

    def _host_in_entry(self, host: str, entry: ScopeEntry) -> bool:
        host = host.lower().rstrip(".")
        if entry.host.startswith("*."):
            base = entry.host[2:]
            return host == base or fnmatch.fnmatch(host, entry.host)
        return host == entry.host

    def _path_ok(self, path: str, entry: ScopeEntry) -> bool:
        if entry.path_prefix is None:
            return True
        prefix = entry.path_prefix.rstrip("/")
        return path == prefix or path.startswith(prefix + "/")

    def check(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason) for a URL. Fail-closed."""
        try:
            p = urlparse(url)
        except ValueError:
            return False, "unparseable URL"

        if p.scheme not in ("http", "https") or not p.hostname:
            return False, "URL must be absolute http(s) with a hostname"
        host = p.hostname.lower().rstrip(".")
        path = p.path or "/"

        for oos in self.out_of_scope:
            if fnmatch.fnmatch(host, oos) or host == oos:
                return False, f"host {host} is explicitly out of scope ({oos})"

        for entry in self.scope:
            if self._host_in_entry(host, entry):
                if entry.scheme and p.scheme != entry.scheme:
                    continue
                if not self._path_ok(path, entry):
                    continue
                return True, f"matched scope entry {entry.host}"
        return False, f"no scope entry matches {host}{path}"

    def requires_private_opt_in(self, url: str) -> bool:
        p = urlparse(url)
        return not any(
            self._host_in_entry(p.hostname or "", e) and e.allow_private
            for e in self.scope
        )

    def assert_can_target(self, url: str) -> None:
        allowed, reason = self.check(url)
        if not allowed:
            raise OutOfScopeError(f"BLOCKED: {url} — {reason}")

    def candidate_domains(self) -> list[str]:
        """Public registrable domains worth passive enumeration.
        Wildcard prefixes are stripped; IP literals are excluded (no DNS records)."""
        domains: list[str] = []
        for e in self.scope:
            host = e.host[2:] if e.host.startswith("*") else e.host
            try:
                ipaddress.ip_address(host)
                continue
            except ValueError:
                pass
            if host not in domains:
                domains.append(host)
        return domains
