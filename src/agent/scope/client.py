"""The enforcing HTTP client.

Every network request made by the agent flows through this class:
  rulebook check (fail-closed) -> private-IP guard -> rate limit -> audit log -> transport.
Out-of-scope requests are blocked before any bytes hit the wire, and every decision
is recorded in a hash-chained audit log.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from ..db import Database
from ..errors import AgentError, OutOfScopeError
from .rulebook import Rulebook

def resolve_host_ips(host: str) -> list:
    """All IPs a host literal/hostname resolves to; [] when resolution fails."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
            return [ipaddress.ip_address(i[4][0]) for i in infos]
        except socket.gaierror:
            return []


def host_resolves_private(host: str) -> bool:
    """True when the host resolves only to loopback/private/link-local space."""
    ips = resolve_host_ips(host)
    return bool(ips) and any(ip.is_private or ip.is_loopback for ip in ips)


class EnforcingClient:
    """The only way the agent touches the network."""

    def __init__(self, rulebook: Rulebook, db: Database, timeout: float = 15.0) -> None:
        self.rulebook = rulebook
        self.db = db
        # Auth harness (M4): a SessionManager attached by scope.auth.enable_auth().
        # None = unauthenticated testing only.
        self.auth: Any | None = None
        self._lock = threading.Lock()
        self._last_request_ts = 0.0
        self._min_interval = 1.0 / max(rulebook.requests_per_second, 0.01)
        self._http = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "bounty-agent/0.1 (authorized research)"},
        )

    # ------------------------------------------------------------ primitives

    def _rate_limit(self) -> None:
        with self._lock:
            wait = self._min_interval - (time.monotonic() - self._last_request_ts)
            if wait > 0:
                time.sleep(wait)
            self._last_request_ts = time.monotonic()

    def _guard_private(self, url: str, allowed_by_rulebook: bool) -> None:
        """Block requests to private/loopback addresses unless the matching
        scope entry explicitly opted in (local lab targets only)."""
        host = urlparse(url).hostname or ""
        if not host_resolves_private(host):
            return
        opted_in = any(
            e.allow_private and (host == e.host or e.host.lstrip("*.") in (host, ""))
            for e in self.rulebook.scope
        )
        if not opted_in:
            raise OutOfScopeError(
                f"BLOCKED: {url} resolves to a private address and no scope entry "
                f"opts in with allow_private: true"
            )

    def _auth_headers(self, account: str, base: dict | None) -> dict:
        """Merge the account's session headers/cookies into the request headers."""
        if self.auth is None:
            raise AgentError(
                f"account='{account}' requested but no auth harness is configured "
                f"for this program (add an auth: section to the rulebook)"
            )
        sess = self.auth.get_session(account)
        headers = dict(base or {})
        headers.update(sess["headers"])
        if sess["cookies"]:
            cookie = "; ".join(f"{k}={v}" for k, v in sess["cookies"].items())
            headers["Cookie"] = f"{headers['Cookie']}; {cookie}" if headers.get("Cookie") else cookie
        return headers

    def request(self, method: str, url: str, account: str | None = None, **kwargs) -> httpx.Response:
        allowed, reason = self.rulebook.check(url)
        if not allowed:
            self.db.log_audit(method, url, "blocked", reason=reason)
            raise OutOfScopeError(f"BLOCKED: {url} — {reason}")
        self._guard_private(url, allowed)
        if account is not None:
            kwargs["headers"] = self._auth_headers(str(account), kwargs.get("headers"))
        self._rate_limit()
        try:
            resp = self._http.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            self.db.log_audit(method, url, "error", reason=str(exc)[:200])
            raise
        finally:
            # Statelessness is an auth-safety invariant: the auth harness
            # attaches credentials explicitly per request (account=...), so a
            # leaked Set-Cookie in httpx's jar must never silently authenticate
            # a later "anonymous" request as the wrong test identity.
            if self._http.cookies:
                self._http.cookies.clear()
        # the audit log records which test identity made each request
        self.db.log_audit(method, url, "allowed", status_code=resp.status_code,
                          reason=(f"account={account}" if account else None))
        return resp

    # ------------------------------------------------------- agent convenience

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data=None, json_body=None, **kwargs) -> httpx.Response:
        if json_body is not None:
            kwargs["json"] = json_body
        elif data is not None:
            kwargs["data"] = data
        return self.request("POST", url, **kwargs)

    def summarize(self, resp: httpx.Response, body_limit: int = 1500) -> str:
        """Compact, token-cheap summary for the LLM context."""
        headers = {k: v for k, v in resp.headers.items() if k.lower() in {
            "content-type", "server", "location", "set-cookie", "content-length",
            "x-frame-options", "access-control-allow-origin", "strict-transport-security",
        }}
        body = resp.text[:body_limit]
        return json.dumps(
            {
                "status": resp.status_code,
                "url": str(resp.request.url),
                "headers": headers,
                "body_snippet": body + ("…[truncated]" if len(resp.text) > body_limit else ""),
            },
            indent=1,
        )
