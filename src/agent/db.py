"""SQLite storage: hash-chained audit log, findings, and attempt history."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    status_code INTEGER,
    request_sha256 TEXT NOT NULL,
    prev_sha256 TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_ts REAL NOT NULL,
    vuln_type TEXT NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT,
    evidence TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'candidate',
    report_md TEXT
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    objective TEXT NOT NULL,
    step INTEGER NOT NULL,
    thought TEXT,
    action_json TEXT NOT NULL,
    result TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL UNIQUE,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    in_scope INTEGER NOT NULL DEFAULT 0,
    url TEXT,
    status_code INTEGER,
    title TEXT,
    tech TEXT,
    source TEXT
);

CREATE TABLE IF NOT EXISTS asset_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    asset_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    details TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    UNIQUE(url, kind)
);

CREATE TABLE IF NOT EXISTS tamper_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    categories TEXT NOT NULL,
    redactions INTEGER NOT NULL DEFAULT 0,
    marker_echo INTEGER NOT NULL DEFAULT 0,
    samples TEXT
);

CREATE TABLE IF NOT EXISTS params (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    example_url TEXT,
    UNIQUE(host, name, kind)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    signature TEXT NOT NULL UNIQUE,
    lesson TEXT NOT NULL,
    source TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1
);
"""

_GENESIS = "0" * 64


def parse_evidence(value) -> dict:
    """Evidence columns may hold JSON (tool-recorded findings) or free text
    (LLM save_finding). Parse defensively — prose becomes {"raw": ...} so one
    verbose model can never crash validation or reporting."""
    if isinstance(value, dict):
        return value
    try:
        data = json.loads(value) if value else {}
        return data if isinstance(data, dict) else {"raw": data}
    except (json.JSONDecodeError, TypeError):
        return {"raw": str(value)[:2000]}


def _host_of(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or ""


class Database:
    def __init__(self, path: str | Path = "agent.db") -> None:
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        self._lock = threading.Lock()

    # ------------------------------------------------------------- audit log

    def log_audit(
        self,
        method: str,
        url: str,
        decision: str,
        reason: str | None = None,
        status_code: int | None = None,
    ) -> str:
        """Append one entry to the hash-chained audit log; returns entry hash."""
        with self._lock:
            row = self.conn.execute(
                "SELECT entry_sha256 FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev = row["entry_sha256"] if row else _GENESIS
            ts = time.time()
            request_sha = hashlib.sha256(f"{method} {url}".encode()).hexdigest()
            payload = (
                f"{ts}|{method}|{url}|{decision}|{reason or ''}|"
                f"{status_code if status_code is not None else ''}|{request_sha}|{prev}"
            )
            entry_sha = hashlib.sha256(payload.encode()).hexdigest()
            self.conn.execute(
                "INSERT INTO audit_log (ts, method, url, decision, reason, status_code,"
                " request_sha256, prev_sha256, entry_sha256) VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, method, url, decision, reason, status_code, request_sha, prev, entry_sha),
            )
            self.conn.commit()
            return entry_sha

    def verify_audit_chain(self) -> tuple[bool, int]:
        """Recompute the whole chain; returns (ok, entries_checked)."""
        rows = self.conn.execute(
            "SELECT ts, method, url, decision, reason, status_code, request_sha256,"
            " prev_sha256, entry_sha256 FROM audit_log ORDER BY id"
        ).fetchall()
        prev = _GENESIS
        for r in rows:
            payload = (
                f"{r['ts']}|{r['method']}|{r['url']}|{r['decision']}|{r['reason'] or ''}|"
                f"{r['status_code'] if r['status_code'] is not None else ''}|"
                f"{r['request_sha256']}|{prev}"
            )
            if hashlib.sha256(payload.encode()).hexdigest() != r["entry_sha256"]:
                return False, len(rows)
            if r["prev_sha256"] != prev:
                return False, len(rows)
            prev = r["entry_sha256"]
        return True, len(rows)

    # -------------------------------------------------------------- findings

    def evidence_of(self, row) -> dict:
        """Defensively parsed evidence for a finding row (see parse_evidence)."""
        return parse_evidence(row["evidence"])

    def add_finding(
        self,
        vuln_type: str,
        url: str,
        evidence: dict[str, Any] | str,
        parameter: str | None = None,
        confidence: float = 0.0,
        status: str = "candidate",
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (created_ts, vuln_type, url, parameter, evidence,"
            " confidence, status) VALUES (?,?,?,?,?,?,?)",
            (
                time.time(),
                vuln_type,
                url,
                parameter,
                evidence if isinstance(evidence, str) else json.dumps(evidence),
                confidence,
                status,
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_findings(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
        )

    # --------------------------------------------------------- tamper events

    def log_tamper_event(self, url: str, categories: list[str],
                         redactions: int = 0, marker_echo: bool = False,
                         samples: list[str] | None = None) -> int:
        """Record a prompt-injection attempt seen in scanned content (M5a).
        Samples are pre-neutralized by the guard; stored for human review."""
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        cur = self.conn.execute(
            "INSERT INTO tamper_events (ts, url, host, categories, redactions,"
            " marker_echo, samples) VALUES (?,?,?,?,?,?,?)",
            (time.time(), url, host, ",".join(sorted(set(categories))),
             redactions, int(marker_echo),
             json.dumps(samples[:5]) if samples else None),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_tamper_events(self, host: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM tamper_events"
        args: list = []
        if host:
            q += " WHERE host=?"
            args.append(host)
        q += " ORDER BY id DESC"
        return list(self.conn.execute(q, args).fetchall())

    # -------------------------------------------------------------- feedback

    def add_lesson(self, signature: str, lesson: str, source: str,
                   host: str = "") -> int:
        """Record (or reinforce) a lesson (M5e). Repeated signatures bump the
        weight instead of duplicating rows — weight = how often the pattern
        has already cost us time."""
        signature = (signature or "").strip()[:300]
        if not signature:
            return 0
        with self._lock:
            row = self.conn.execute(
                "SELECT id, weight FROM feedback WHERE signature=?", (signature,)
            ).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE feedback SET weight=weight+1, ts=? WHERE id=?",
                    (time.time(), row["id"]),
                )
                self.conn.commit()
                return int(row["id"])
            cur = self.conn.execute(
                "INSERT INTO feedback (ts, host, signature, lesson, source, weight)"
                " VALUES (?,?,?,?,?,1)",
                (time.time(), host, signature, lesson[:600], source),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def list_lessons(self, host: str | None = None,
                     min_weight: int = 1) -> list[sqlite3.Row]:
        q = "SELECT * FROM feedback WHERE weight>=?"
        args: list = [min_weight]
        if host:
            q += " AND host=?"
            args.append(host)
        q += " ORDER BY weight DESC, ts DESC"
        return list(self.conn.execute(q, args).fetchall())

    # ---------------------------------------------------------- parameters

    def add_param(self, name: str, host: str, kind: str, source: str,
                  example_url: str | None = None) -> int | None:
        """Record a real parameter name (M5c). kind: query|form|mined|
        reflected|differential. Returns row id or None on duplicate."""
        name = (name or "").strip()
        if not name or len(name) > 64:
            return None
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO params (ts, host, name, kind, source,"
                " example_url) VALUES (?,?,?,?,?,?)",
                (time.time(), host.lower(), name, kind, source, example_url),
            )
            self.conn.commit()
            return int(cur.lastrowid) if cur.rowcount else None
        except sqlite3.IntegrityError:
            return None

    def list_params(self, kind: str | None = None,
                    host: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM params"
        cond, args = [], []
        if kind:
            cond.append("kind=?")
            args.append(kind)
        if host:
            cond.append("host=?")
            args.append(host)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY host, name"
        return list(self.conn.execute(q, args).fetchall())

    # ------------------------------------------------------------ endpoints

    def add_endpoint(self, url: str, kind: str, source: str, host: str | None = None,
                     in_scope: int = 1) -> int | None:
        """Insert an endpoint if its host is in scope. Returns row id or None.
        Host must be rulebook-validated BEFORE calling this."""
        url = url.strip()
        if not url:
            return None
        host = (host or _host_of(url)).lower().rstrip(".")
        if not host or not in_scope:
            return None
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO endpoints (ts, host, url, kind, source)"
                " VALUES (?,?,?,?,?)",
                (time.time(), host, url, kind, source),
            )
            self.conn.commit()
            return int(cur.lastrowid) if cur.rowcount else None
        except sqlite3.IntegrityError:
            return None

    def list_endpoints(self, kind: str | None = None,
                       host: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM endpoints"
        cond, args = [], []
        if kind:
            cond.append("kind=?")
            args.append(kind)
        if host:
            cond.append("host=?")
            args.append(host)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY host, url"
        return list(self.conn.execute(q, args).fetchall())

    # -------------------------------------------------------------- attempts

    def add_attempt(
        self,
        session_id: str,
        step: int,
        objective: str,
        thought: str | None,
        action_json: str,
        result: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO attempts (session_id, ts, objective, step, thought,"
            " action_json, result) VALUES (?,?,?,?,?,?,?)",
            (session_id, time.time(), objective, step, thought, action_json, result),
        )
        self.conn.commit()
