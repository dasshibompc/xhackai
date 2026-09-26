"""M4 access-control testing: the multi-account IDOR matrix.

Method (mirrors manual access-control testing):
  1. Establish a session per test account (via the auth harness).
  2. Verify each account can fetch its OWN object — the baseline. Without this
     a "200" on a cross request means nothing (maybe the object doesn't exist,
     maybe the whole endpoint denies everyone).
  3. Cross requests: every account fetches every OTHER account's object, plus
     an unauthenticated fetch of each object.
  4. Classify: a 200 on a foreign object is at least *uncertain*; combined with
     content that differs from the attacker's own object (or matches the owner's
     baseline), it is a strong IDOR signal. 403/404 is correct behavior.

All requests flow through the EnforcingClient, so scope + rate limits +
audit log apply to every matrix cell. Evidence records account NAMES only —
never credentials.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..db import Database
from ..errors import AgentError
from ..scope.auth import AuthError, AuthSpec, SessionManager
from ..scope.client import EnforcingClient
from ..tools import Tool, ToolResult


@dataclass
class MatrixCell:
    """One request in the matrix."""
    actor: str  # account name, or "anonymous"
    object_owner: str  # account whose object was requested
    status: int | None = None
    body_len: int | None = None
    body_marker_seen: bool | None = None  # owner's identity marker in the body?
    differs_from_own_baseline: bool | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "object_owner": self.object_owner,
            "status": self.status,
            "body_len": self.body_len,
            "body_marker_seen": self.body_marker_seen,
            "differs_from_own_baseline": self.differs_from_own_baseline,
            "error": self.error,
        }


@dataclass
class MatrixResult:
    url_template: str
    id_param: str
    baselines: dict[str, MatrixCell] = field(default_factory=dict)  # owner -> cell
    cells: list[MatrixCell] = field(default_factory=list)  # cross-access attempts
    vulnerable: bool = False
    classification: str = "unknown"  # idor | probable-idor | secure | inconclusive
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "url_template": self.url_template,
            "id_param": self.id_param,
            "baseline": {k: v.as_dict() for k, v in self.baselines.items()},
            "cross_requests": [c.as_dict() for c in self.cells],
            "vulnerable": self.vulnerable,
            "classification": self.classification,
            "notes": self.notes,
        }


def _substitute(template: str, id_param: str, owner_id: str) -> str:
    """Fill {id}, {id_param}, or {owner_id} placeholders in the template."""
    for key in (id_param, "id", "owner_id", "user_id"):
        if "{" + key + "}" in template:
            return template.replace("{" + key + "}", owner_id)
    raise AgentError(
        f"url template '{template}' has no placeholder for id param "
        f"'{id_param}' — use {{{id_param}}} or {{id}}"
    )


def _identity_markers(owner: str, ids: dict[str, str]) -> list[str]:
    """Strings that, if present in a body, indicate whose data came back.

    Only the account NAME is a meaningful marker: an object's own numeric id
    appears in its representation regardless of who fetched it, so id equality
    proves nothing about ownership.
    """
    return [owner] if owner else []


class AccessMatrix:
    """Runs the cross-account object-access matrix against one endpoint."""

    def __init__(self, client: EnforcingClient, db: Database,
                 auth_spec: AuthSpec, accounts: list[str] | None = None) -> None:
        if auth_spec is None or not auth_spec.accounts:
            raise AgentError(
                "access matrix needs a rulebook with an auth: section defining "
                "at least one test account"
            )
        self.client = client
        self.db = db
        self.auth_spec = auth_spec
        # Reuse the client's harness when it was enabled with the same spec
        # (CLI path); otherwise attach our own so `account=` requests work.
        sessions = getattr(client, "auth", None)
        if sessions is None or getattr(sessions, "auth_spec", None) is not auth_spec:
            sessions = SessionManager(client, auth_spec)
            client.auth = sessions
        self.sessions = sessions
        self.accounts = accounts or list(auth_spec.accounts)

    # ------------------------------------------------------------ mechanics

    def _fetch(self, url: str, account: str | None) -> tuple[MatrixCell, str | None]:
        """One matrix request; returns the cell and the response body (if any).

        The body is captured in the same request — no re-fetches, so a matrix
        costs exactly one request per cell.
        """
        actor = account or "anonymous"
        cell = MatrixCell(actor=actor, object_owner="?")
        try:
            resp = self.client.get(url, account=account)
            cell.status = resp.status_code
            body = resp.text
            cell.body_len = len(body)
            return cell, body
        except AuthError as exc:
            cell.error = f"auth: {str(exc)[:200]}"
            return cell, None
        except Exception as exc:  # noqa: BLE001 — one failed cell must not kill the matrix
            cell.error = str(exc)[:200]
            return cell, None

    # ----------------------------------------------------------------- main

    def run(self, url_template: str, ids: dict[str, str],
            id_param: str = "id") -> MatrixResult:
        """Run the matrix.

        ids maps account name -> the object id that belongs to that account
        (e.g. {"alice": "101", "bob": "102"}). The template must contain a
        placeholder for the id.
        """
        result = MatrixResult(url_template=url_template, id_param=id_param)
        missing = [a for a in self.accounts if a not in ids]
        if missing:
            result.notes.append(
                f"no object id provided for accounts: {', '.join(missing)} — skipped"
            )
        owners = [a for a in self.accounts if a in ids]

        # ---- stage 1: own-object baselines
        for owner in owners:
            url = _substitute(url_template, id_param, ids[owner])
            cell, body = self._fetch(url, owner)
            cell.object_owner = owner
            if cell.status == 200 and body is not None:
                markers = _identity_markers(owner, ids)
                cell.body_marker_seen = any(m in body for m in markers)
            result.baselines[owner] = cell
            if cell.status != 200:
                result.notes.append(
                    f"baseline for {owner} returned {cell.status} — cross results "
                    f"involving {owner}'s object are less conclusive"
                )

        # ---- stage 2: cross-account + unauthenticated requests
        for owner in owners:
            url = _substitute(url_template, id_param, ids[owner])
            own = result.baselines[owner]
            for actor in [a for a in owners if a != owner]:
                cell, body = self._fetch(url, actor)
                cell.object_owner = owner
                if cell.status == 200 and body is not None:
                    markers = _identity_markers(owner, ids)
                    if markers:
                        cell.body_marker_seen = any(m in body for m in markers)
                    if own.status == 200 and own.body_len is not None:
                        cell.differs_from_own_baseline = cell.body_len != own.body_len
                result.cells.append(cell)
            anon, anon_body = self._fetch(url, None)
            anon.object_owner = owner
            if anon.status == 200 and anon_body is not None:
                # only marker-bearing bodies suggest a private object leaked;
                # a bare 200 usually means the object is intentionally public
                anon.body_marker_seen = any(m in anon_body for m in _identity_markers(owner, ids))
            result.cells.append(anon)

        result.vulnerable, result.classification = self._classify(result)
        return result

    # ---------------------------------------------------------- classifying

    def _classify(self, result: MatrixResult) -> tuple[bool, str]:
        """Conservative classification from the matrix evidence.

        - idor:           an AUTHENTICATED actor fetched a foreign object with
                          200 AND the body carries the owner's identity marker
                          (or differs from the actor's own baseline) — strong
        - probable-idor:  foreign objects returned 200 but bodies are
                          indistinguishable, OR anonymous requests returned
                          object data (could be intentionally public) — needs
                          human judgment
        - secure:         every authenticated cross request was denied
        - inconclusive:   baselines failed, requests errored, or we never
                          tested a second authenticated identity
        """
        cross = [c for c in result.cells if c.actor != "anonymous"]
        working_baselines = [b for b in result.baselines.values() if b.status == 200]
        if not working_baselines:
            return False, "inconclusive"

        strong: list[MatrixCell] = []
        weak: list[MatrixCell] = []
        denied: list[MatrixCell] = []
        errored: list[MatrixCell] = []
        anon_200: list[MatrixCell] = []
        for cell in result.cells:
            if cell.error:
                errored.append(cell)
            elif cell.status in (401, 403, 404):
                denied.append(cell)
            elif cell.status == 200:
                if cell.actor == "anonymous":
                    anon_200.append(cell)
                elif cell.body_marker_seen or cell.differs_from_own_baseline:
                    strong.append(cell)
                else:
                    weak.append(cell)

        if strong:
            notes = [f"{c.actor} read {c.object_owner}'s object (HTTP 200"
                     + (", owner marker present" if c.body_marker_seen else
                        ", body differs from actor's own object") + ")"
                     for c in strong]
            result.notes.extend(notes)
            return True, "idor"
        if weak:
            result.notes.append(
                "foreign objects returned 200 but bodies did not prove whose data "
                "came back — human must compare objects"
            )
            return True, "probable-idor"
        if any(c for c in anon_200 if c.body_marker_seen):
            result.notes.append(
                "unauthenticated requests returned object data bearing the "
                "owner's identity — verify the object is not intentionally public"
            )
            return True, "probable-idor"
        if not cross:
            # only anonymous requests were made (or a single account) — we never
            # tested a second AUTHENTICATED identity, so nothing is proven
            return False, "inconclusive"
        if denied and not errored:
            return False, "secure"
        return False, "inconclusive"


class AccessMatrixTool(Tool):
    """LLM-callable wrapper. Records a finding only for idor/probable-idor."""

    name = "access_matrix"
    description = (
        "Run a cross-account object-access matrix (IDOR test) on an endpoint. "
        "Args: url_template (with {id}), ids (JSON object mapping account name "
        "to that account's object id), id_param (optional, default 'id'). "
        "Requires configured test accounts."
    )
    needs_client = True

    def __init__(self, client: EnforcingClient, db: Database, auth_spec: AuthSpec,
                 accounts: list[str] | None = None) -> None:
        self.client = client
        self.db = db
        self.auth_spec = auth_spec
        self.accounts = accounts

    def run(self, url_template: str, ids: str | dict, id_param: str = "id") -> ToolResult:
        if isinstance(ids, str):
            try:
                ids = json.loads(ids)
            except json.JSONDecodeError as exc:
                return ToolResult(False, f"ids must be JSON like "
                                         f'{{"alice": "101", "bob": "102"}}: {exc}')
        if not isinstance(ids, dict) or not ids:
            return ToolResult(False, "ids must map account name -> object id")
        try:
            matrix = AccessMatrix(self.client, self.db, self.auth_spec,
                                  accounts=self.accounts)
            result = matrix.run(url_template, ids={str(k): str(v) for k, v in ids.items()},
                                id_param=id_param)
        except AuthError as exc:
            return ToolResult(False, f"auth setup failed: {exc}")
        except AgentError as exc:
            return ToolResult(False, str(exc))

        evidence = result.as_dict()
        # store the account->id mapping so the validator can re-run the matrix
        evidence["ids"] = {str(k): str(v) for k, v in ids.items()}
        evidence["id_param"] = id_param
        if not result.vulnerable:
            # precision-first: secure/inconclusive matrices are history, not findings
            return ToolResult(True, f"matrix result: {result.classification} — "
                                    f"no finding recorded ({evidence['notes']})")
        vuln_type = ("IDOR (cross-account matrix)" if result.classification == "idor"
                     else "Access control (probable IDOR matrix)")
        fid = self.db.add_finding(
            vuln_type=vuln_type, url=url_template, parameter=id_param,
            evidence=evidence, confidence=0.8 if result.classification == "idor" else 0.6,
            status="candidate",
        )
        return ToolResult(True, f"{result.classification}: evidence stored as "
                                f"finding #{fid} (candidate — awaits adversarial validation)")
