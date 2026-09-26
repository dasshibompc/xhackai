"""M4 auth harness: authenticated testing with multiple test accounts.

The harness keeps credentials out of the codebase and out of chat: the rulebook
names accounts and maps each to environment-variable names; the harness reads
the actual secrets from the process environment at run time.

Design constraints (unchanged from the plan):
- All network access still flows through the EnforcingClient — this module
  never opens sockets itself.
- Credentials are never logged, never stored in the database, and never placed
  in LLM context. Only account *names* are.
- The harness never creates accounts. It only logs in with accounts the human
  configured for authorized testing.
"""
from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from yaml.error import YAMLError

from ..errors import AgentError

if TYPE_CHECKING:  # pragma: no cover — typing only, avoids an import cycle
    from .client import EnforcingClient


class AuthError(AgentError):
    """Raised when the configured test-account setup cannot be used."""


@dataclass(frozen=True)
class AccountSpec:
    """One test account: a display name plus where its secrets live."""

    name: str
    env_prefix: str  # e.g. LAB_ALICE -> LAB_ALICE_USERNAME / LAB_ALICE_PASSWORD
    login_url: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    headers: dict = field(default_factory=dict)  # static headers, e.g. X-API-Key


class AuthSpec:
    """Parsed `auth:` section of a program rulebook (YAML file or dict).

    YAML shape:

        auth:
          session_mode: cookie        # cookie | header
          header_name: Authorization  # used in header mode
          token_scheme: Bearer        # Bearer | raw | none
          login_success_status: 200
          accounts:
            - name: alice
              env_prefix: LAB_ALICE   # reads LAB_ALICE_USERNAME / LAB_ALICE_PASSWORD
              login_url: http://127.0.0.1:8770/login-session
            - name: svc
              env_prefix: LAB_SVC
              headers:
                X-API-Key: "{LAB_SVC_API_KEY}"   # env placeholders resolved at run time
    """

    def __init__(self, raw: dict | None) -> None:
        raw = raw or {}
        self.raw = raw
        self.accounts: dict[str, AccountSpec] = {}
        for acct in raw.get("accounts", []):
            if not isinstance(acct, dict):
                continue
            name = str(acct.get("name", "")).strip()
            if not name:
                continue
            self.accounts[name] = AccountSpec(
                name=name,
                env_prefix=str(acct.get("env_prefix", "")).strip() or name.upper(),
                login_url=acct.get("login_url") or None,
                username_field=str(acct.get("username_field", "username")),
                password_field=str(acct.get("password_field", "password")),
                headers=dict(acct.get("headers") or {}),
            )
        self.session_mode = str(raw.get("session_mode", "cookie")).lower()
        self.header_name = str(raw.get("header_name", "Authorization"))
        self.token_scheme = str(raw.get("token_scheme", "Bearer"))
        self.success_status = int(raw.get("login_success_status", 200))

    @classmethod
    def load(cls, path: str | Path) -> "AuthSpec":
        """Load the `auth:` section from a program YAML. Missing file or
        missing section yields an empty spec (no accounts configured)."""
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, YAMLError):
            return cls({})
        if not isinstance(raw, dict):
            return cls({})
        return cls(raw.get("auth"))

    # ------------------------------------------------------------ resolution

    def resolve(self, account: str) -> dict[str, Any]:
        """Resolve an account to its auth material from the environment.

        Returns {"headers", "data", "token", "login_url", ...}. Raises
        AuthError for unknown accounts or unset secrets.
        """
        spec = self.accounts.get(account)
        if spec is None:
            raise AuthError(
                f"unknown test account '{account}' — rulebook defines: "
                f"{', '.join(self.accounts) or '(none)'}"
            )
        prefix = spec.env_prefix
        username = os.environ.get(f"{prefix}_USERNAME", "")
        password = os.environ.get(f"{prefix}_PASSWORD", "")
        token = os.environ.get(f"{prefix}_TOKEN", "")

        # static headers from YAML, with {ENV_VAR} placeholders resolved
        headers: dict[str, str] = {}
        for key, value in spec.headers.items():
            if isinstance(value, str) and "{" in value:
                env_names = re.findall(r"\{([A-Z][A-Z0-9_]*)\}", value)
                resolved = value
                for env_name in env_names:
                    env_val = os.environ.get(env_name)
                    if env_val is None:
                        raise AuthError(
                            f"account '{account}': header '{key}' references "
                            f"{{{env_name}}} but that env var is not set"
                        )
                    resolved = resolved.replace("{" + env_name + "}", env_val)
                headers[str(key)] = resolved
            else:
                headers[str(key)] = str(value)

        data: dict[str, str] = {}
        if username:
            data[spec.username_field] = username
        if password:
            data[spec.password_field] = password

        if not headers and not data and not token:
            raise AuthError(
                f"no credentials resolved for account '{account}': expected "
                f"{self.recommended_env_names(account)} in the environment"
            )
        return {
            "headers": headers,
            "data": data,
            "token": token,
            "login_url": spec.login_url,
        }

    def has_credentials(self, account: str) -> bool:
        try:
            self.resolve(account)
            return True
        except AuthError:
            return False

    # -------------------------------------------------------------- helpers

    def recommended_env_names(self, account: str) -> str:
        """The exact env-var names a human must set for this account."""
        spec = self.accounts.get(account)
        if spec is None:
            return f"(unknown account '{account}')"
        prefix = spec.env_prefix
        if spec.login_url:
            return f"{prefix}_USERNAME, {prefix}_PASSWORD"
        if spec.headers:
            env_names = sorted({
                env_name
                for v in spec.headers.values()
                if isinstance(v, str)
                for env_name in re.findall(r"\{([A-Z][A-Z0-9_]*)\}", v)
            })
            if env_names:
                return ", ".join(env_names)
            return "static headers from YAML (no env vars needed)"
        return f"{prefix}_TOKEN"

    def missing_env_vars(self, accounts: list[str] | None = None) -> dict[str, list[str]]:
        """Map account -> missing env var names (empty list = fully configured)."""
        names = accounts if accounts is not None else list(self.accounts)
        out: dict[str, list[str]] = {}
        for name in names:
            spec = self.accounts.get(name)
            if spec is None:
                out[name] = [f"(unknown account '{name}')"]
                continue
            prefix = spec.env_prefix
            missing: list[str] = []
            if spec.login_url:
                if not os.environ.get(f"{prefix}_USERNAME"):
                    missing.append(f"{prefix}_USERNAME")
                if not os.environ.get(f"{prefix}_PASSWORD"):
                    missing.append(f"{prefix}_PASSWORD")
            for v in spec.headers.values():
                if isinstance(v, str):
                    for env_name in re.findall(r"\{([A-Z][A-Z0-9_]*)\}", v):
                        if not os.environ.get(env_name):
                            missing.append(env_name)
            if not missing and not spec.login_url and not spec.headers \
                    and not os.environ.get(f"{prefix}_TOKEN"):
                missing.append(f"{prefix}_TOKEN")
            out[name] = missing
        return out


class SessionManager:
    """Per-account session establishment and cookie/header management.

    Two modes:
    - cookie mode: POST credentials to login_url, capture Set-Cookie from the
      successful response (default)
    - header mode: use a token from the environment directly, or static
      headers (e.g. API keys) from the rulebook with env placeholders
    """

    def __init__(self, client: "EnforcingClient", auth_spec: AuthSpec) -> None:
        self.client = client
        self.auth_spec = auth_spec
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get_session(self, account: str, fresh: bool = False) -> dict:
        """Establish (or reuse a cached) authenticated context for `account`.

        Returns {"headers": {...}, "cookies": {...}, "account": str}.
        """
        if not fresh:
            with self._lock:
                cached = self._cache.get(account)
            if cached is not None:
                return cached

        material = self.auth_spec.resolve(account)
        headers = dict(material["headers"])
        cookies: dict[str, str] = {}
        login_url = material.get("login_url")

        if login_url:
            try:
                resp = self.client.post(login_url, data=dict(material["data"]),
                                        headers=headers or None)
            except Exception as exc:  # noqa: BLE001 — network layer errors
                raise AuthError(f"login request for '{account}' failed: {exc}") from exc
            if resp.status_code != self.auth_spec.success_status:
                raise AuthError(
                    f"login for '{account}' returned {resp.status_code} "
                    f"(expected {self.auth_spec.success_status})"
                )
            for header_value in resp.headers.get_list("set-cookie"):
                pair = header_value.split(";", 1)[0]
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if k.strip():
                        cookies[k.strip()] = v.strip()
            if not cookies and self.auth_spec.session_mode == "cookie":
                raise AuthError(
                    f"login for '{account}' succeeded ({resp.status_code}) but "
                    f"no Set-Cookie was returned"
                )

        if material["token"]:
            if self.auth_spec.token_scheme.lower() in ("bearer", "raw"):
                value = f"Bearer {material['token']}" \
                    if self.auth_spec.token_scheme.lower() == "bearer" else material["token"]
                headers.setdefault(self.auth_spec.header_name, value)

        if not headers and not cookies:
            raise AuthError(f"no auth material for '{account}' after login")

        result = {"headers": headers, "cookies": cookies, "account": account}
        with self._lock:
            self._cache[account] = result
        return result

    def invalidate(self, account: str) -> None:
        with self._lock:
            self._cache.pop(account, None)

    def invalidate_all(self) -> None:
        with self._lock:
            self._cache.clear()


def enable_auth(client: "EnforcingClient", auth_spec: AuthSpec) -> SessionManager:
    """Attach the auth harness to an EnforcingClient.

    After this call, ``client.get(url, account="alice")`` sends the request
    with alice's session cookies/headers, and the audit log records which
    account made each request. Returns the SessionManager (for cache control
    in tests).
    """
    sm = SessionManager(client, auth_spec)
    client.auth = sm
    return sm
