"""Asset inventory: the single place recon results become records.

Every write path is scope-checked. Out-of-scope discoveries are recorded as
events only (proof we saw and ignored them) — never as targetable assets.
"""
from __future__ import annotations

import json
import time

from ..db import Database
from ..errors import OutOfScopeError
from ..scope.rulebook import Rulebook


class Inventory:
    def __init__(self, db: Database, rulebook: Rulebook) -> None:
        self.db = db
        self.rulebook = rulebook

    def add_host(self, host: str, source: str) -> tuple[int, bool]:
        """Insert or refresh a host. Returns (asset_id, in_scope).

        Out-of-scope hosts are rejected: OutOfScopeError is raised so callers
        can count them, after an event row is written for the audit trail.
        """
        host = host.lower().strip().rstrip(".")
        if not host:
            raise ValueError("empty host")
        allowed, reason = self.rulebook.check(f"https://{host}/")
        in_scope = 1 if allowed else 0
        now = time.time()
        cur = self.db.conn.execute("SELECT id, in_scope FROM assets WHERE host=?", (host,))
        row = cur.fetchone()
        if row is None:
            cur = self.db.conn.execute(
                "INSERT INTO assets (host, first_seen, last_seen, in_scope, source)"
                " VALUES (?,?,?,?,?)",
                (host, now, now, in_scope, source),
            )
            asset_id = int(cur.lastrowid)
            self._event(asset_id, "new", f"source={source} in_scope={bool(in_scope)}")
        else:
            asset_id = int(row["id"])
            self.db.conn.execute("UPDATE assets SET last_seen=? WHERE id=?", (now, asset_id))
            if bool(row["in_scope"]) != bool(in_scope):
                self._event(asset_id, "scope_changed", f"now in_scope={bool(in_scope)}")
                self.db.conn.execute(
                    "UPDATE assets SET in_scope=? WHERE id=?", (in_scope, asset_id)
                )
        self.db.conn.commit()
        if not allowed:
            raise OutOfScopeError(f"host {host} out of scope ({reason}); recorded, not targetable")
        return asset_id, True

    def probe_result(self, host: str, url: str, status_code: int, title: str, tech: list[str]) -> None:
        """Attach httpx probe data to an in-scope asset."""
        self.db.conn.execute(
            "UPDATE assets SET url=?, status_code=?, title=?, tech=? WHERE host=?",
            (url, status_code, title, json.dumps(tech), host.lower()),
        )
        self.db.conn.commit()

    def mark_unreachable(self, host: str) -> None:
        self.db.conn.execute(
            "UPDATE assets SET status_code=NULL WHERE host=?", (host.lower(),)
        )
        self.db.conn.commit()

    def in_scope_hosts(self) -> list[str]:
        return [
            r["host"]
            for r in self.db.conn.execute(
                "SELECT host FROM assets WHERE in_scope=1 ORDER BY host"
            ).fetchall()
        ]

    def _event(self, asset_id: int, kind: str, details: str) -> None:
        self.db.conn.execute(
            "INSERT INTO asset_events (ts, asset_id, kind, details) VALUES (?,?,?,?)",
            (time.time(), asset_id, kind, details),
        )
        self.db.conn.commit()

    def summary(self) -> dict:
        total = self.db.conn.execute("SELECT COUNT(*) c FROM assets").fetchone()["c"]
        in_scope = self.db.conn.execute(
            "SELECT COUNT(*) c FROM assets WHERE in_scope=1"
        ).fetchone()["c"]
        with_probe = self.db.conn.execute(
            "SELECT COUNT(*) c FROM assets WHERE status_code IS NOT NULL"
        ).fetchone()["c"]
        new_events = self.db.conn.execute(
            "SELECT COUNT(*) c FROM asset_events WHERE kind='new'"
        ).fetchone()["c"]
        return {"total": total, "in_scope": in_scope, "probed": with_probe, "new": new_events}

    def render_table(self) -> list[tuple]:
        rows = self.db.conn.execute(
            "SELECT host, in_scope, url, status_code, title, tech, source FROM assets"
            " ORDER BY in_scope DESC, host"
        ).fetchall()
        out = []
        for r in rows:
            tech = ", ".join(json.loads(r["tech"])) if r["tech"] else ""
            out.append(
                ("Y" if r["in_scope"] else "n", r["host"], str(r["status_code"] or "-"),
                 (r["title"] or "-")[:40], tech[:40], r["source"] or "-")
            )
        return out
