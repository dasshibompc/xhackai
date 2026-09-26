"""M5d exploit chains: multi-step access-control proofs with deterministic
execution.

Free models are weak at long multi-step reasoning, so the model never
improvises request sequences here. It chooses a PREBUILT template and supplies
only coordinates (paths, field names, accounts). Python executes every step:

- ``request``  — send via the EnforcingClient as a specific test account
                 (auth harness injects the session), optionally capturing a
                 value from the response (JSON field or regex) into the chain
                 context, with an expected-status assertion
- ``compare``  — evaluate a condition over the context (equals / contains /
                 not_equals / exists) — the verdict primitive

Everything the LLM sees or stores is evidence: per-step request coordinates
and response snippets (sanitized by the M5a guard — pages never speak to the
model), the final context, and a classification. The spec itself is
JSON-serializable so the validator can RE-RUN the whole chain deterministically
as its stage-1 reproduction step.

Side effects, stated plainly: templates with a create step create one object
per run (hence per validation re-run). That is recorded in the evidence bundle
so the human reviewer can judge whether it is acceptable for the target.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..db import Database
from ..errors import AgentError
from ..scope.auth import AuthError
from ..scope.guard import sanitize_body
from ..tools import Tool, ToolResult

_COMPARE_OPS = ("equals", "not_equals", "contains", "exists")


def _substitute(value: Any, ctx: dict[str, Any]) -> Any:
    """Replace {{key}} placeholders in strings; recurse into dict/list."""
    if isinstance(value, str):
        def _rep(m: re.Match) -> str:
            return str(ctx.get(m.group(1), m.group(0)))
        return re.sub(r"\{\{([a-zA-Z0-9_]+)\}\}", _rep, value)
    if isinstance(value, dict):
        return {k: _substitute(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, ctx) for v in value]
    return value


def _capture_from(resp, capture: dict, ctx: dict[str, Any]) -> None:
    """Store a value from the response into ctx under capture['as']."""
    as_name = str(capture.get("as", "")).strip()
    if not as_name:
        raise AgentError("capture step missing 'as' name")
    if "field" in capture:
        field = str(capture["field"])
        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise AgentError(f"capture field '{field}': body is not JSON ({exc})")
        cur: Any = data
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                raise AgentError(f"capture field '{field}' not found in response JSON")
        ctx[as_name] = cur
    elif "regex" in capture:
        m = re.search(str(capture["regex"]), resp.text)
        if not m:
            raise AgentError(f"capture regex {capture['regex']!r} did not match")
        ctx[as_name] = m.group(1) if m.groups() else m.group(0)
    else:
        raise AgentError("capture needs 'field' (JSON path) or 'regex'")


@dataclass
class ChainResult:
    vulnerable: bool
    classification: str  # e.g. idor-chain | secure | denied | inconclusive
    steps: list[dict] = field(default_factory=list)
    ctx: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "classification": self.classification,
            "steps": self.steps,
            "ctx": {k: str(v) for k, v in self.ctx.items()},
            "notes": self.notes,
        }


class ChainRunner:
    """Executes a chain spec step by step. Every network action flows through
    the EnforcingClient (scope + rate limits + audit + account= sessions)."""

    def __init__(self, client, db: Database) -> None:
        self.client = client
        self.db = db
        if getattr(client, "auth", None) is None:
            raise AgentError(
                "chains need the auth harness — enable_auth(client, auth_spec) first"
            )

    def run(self, spec: dict) -> ChainResult:
        steps = spec.get("steps")
        if not isinstance(steps, list) or not steps:
            return ChainResult(False, "inconclusive", notes=["spec has no steps"])
        ctx: dict[str, Any] = {
            "marker": uuid.uuid4().hex[:12],
            "run_id": uuid.uuid4().hex[:8],
        }
        ctx.update({k: v for k, v in (spec.get("context") or {}).items()})
        result = ChainResult(vulnerable=False, classification="inconclusive")
        aborted: str | None = None

        for i, raw in enumerate(steps, 1):
            action = str(raw.get("action", ""))
            if action == "request":
                step_entry, ok, err = self._do_request(raw, ctx)
            elif action == "compare":
                step_entry, ok, err = self._do_compare(raw, ctx)
            else:
                aborted = f"step {i}: unknown action '{action}'"
                result.notes.append(aborted)
                break
            result.steps.append(step_entry)
            if not ok:
                aborted = err or f"step {i} failed"
                result.notes.append(aborted)
                break

        if aborted is None:
            result.vulnerable = True
            result.classification = str(spec.get("conclusion_class", "chained"))
        elif "auth failure" in aborted:
            # broken credentials/sessions on our side — never evidence
            result.classification = "inconclusive"
        elif "denied" in aborted or "403" in aborted or "401" in aborted:
            # target answered with a denial while our sessions were working
            result.classification = "denied"
        elif not result.steps or any(s.get("error") for s in result.steps):
            # nothing completed, or a request/compare step errored — we learned
            # nothing about the target's access control
            result.classification = "inconclusive"
        else:
            # steps ran cleanly and the verdict compare legitimately failed
            result.classification = "secure"
        result.ctx = ctx
        return result

    # ------------------------------------------------------------- steps

    def _do_request(self, step: dict, ctx: dict) -> tuple[dict, bool, str | None]:
        name = str(step.get("name", "request"))
        account = str(step.get("account", ""))
        method = str(step.get("method", "GET")).upper()
        url = _substitute(str(step.get("url", "")), ctx)
        if not url or not account:
            return ({"name": name, "error": "request step needs url + account"},
                    False, "malformed request step")
        body = _substitute(step.get("body"), ctx) if step.get("body") else None
        entry: dict[str, Any] = {"name": name, "action": "request",
                                 "account": account, "method": method, "url": url}
        try:
            if method == "POST":
                resp = self.client.post(url, json_body=body, account=account)
            elif method == "PUT":
                resp = self.client.request("PUT", url, json=body, account=account)
            else:
                resp = self.client.get(url, account=account)
        except AuthError as exc:
            # OUR harness could not establish the session — infrastructure
            # failure, not the target denying access; must not read as "denied"
            entry["error"] = f"auth failure: {exc}"
            return entry, False, f"{name}: auth failure: {exc}"
        except Exception as exc:  # noqa: BLE001
            entry["error"] = str(exc)[:200]
            return entry, False, f"{name}: request error: {exc}"

        entry["status"] = resp.status_code
        snippet = sanitize_body(resp.text[:600]).sanitized
        entry["response_snippet"] = snippet

        expected = step.get("status") or [200]
        if isinstance(expected, int):
            expected = [expected]
        if resp.status_code not in [int(s) for s in expected]:
            err = f"{name}: status {resp.status_code} not in {expected} (denied?)"
            entry["error"] = err
            return entry, False, err

        if step.get("capture"):
            try:
                _capture_from(resp, step["capture"], ctx)
            except AgentError as exc:
                entry["error"] = str(exc)
                return entry, False, f"{name}: {exc}"
            entry["captured_as"] = str(step["capture"].get("as", ""))
        return entry, True, None

    def _do_compare(self, step: dict, ctx: dict) -> tuple[dict, bool, str | None]:
        name = str(step.get("name", "compare"))
        op = str(step.get("op", "")).lower()
        left = _substitute(step.get("left", ""), ctx)
        right = _substitute(step.get("right", ""), ctx)
        entry: dict[str, Any] = {"name": name, "action": "compare", "op": op,
                                 "left": str(left)[:200], "right": str(right)[:200]}
        if op not in _COMPARE_OPS:
            return entry, False, f"{name}: unknown compare op '{op}'"
        if op == "exists":
            ok = left != "" and left != "None" and str(left) != "{{" + str(step.get("left", ""))[2:]
            ok = str(left) not in ("", "None")
        elif op == "equals":
            ok = str(left) == str(right)
        elif op == "not_equals":
            ok = str(left) != str(right)
        else:  # contains
            ok = str(right) in str(left)
        entry["result"] = bool(ok)
        if not ok:
            return entry, False, f"{name}: compare failed ({op}: {left!r} vs {right!r})"
        return entry, True, None


# --------------------------------------------------------------- templates

def build_cross_account_create_read(
    base_url: str,
    create_path: str,
    read_path_template: str,
    body: dict | None = None,
    owner_field: str = "owner",
    accounts: tuple[str, str] = ("alice", "bob"),
    id_field: str = "id",
) -> dict:
    """The canonical two-account chain: A creates an object, B reads it.

    Verdict logic: B's fetch of A's object must succeed (status assertion)
    AND the returned owner field must equal account A — proving B received
    A's data, not a generic 200.
    """
    a, b = accounts
    body = body or {"title": "chain-note-{{marker}}"}
    url = base_url.rstrip("/")
    return {
        "template": "cross-account-create-read",
        "conclusion_class": "idor-chain",
        "side_effects": "creates one object per run as the first account",
        "context": {"account_a": a, "account_b": b},
        "steps": [
            {"action": "request", "name": "create_as_a", "account": a,
             "method": "POST", "url": url + create_path, "body": body,
             "status": [200, 201],
             "capture": {"field": id_field, "as": "created_id"}},
            {"action": "request", "name": "read_as_b", "account": b,
             "method": "GET", "url": url + read_path_template.replace("{id}", "{{created_id}}"),
             "status": [200],
             "capture": {"field": owner_field, "as": "seen_owner"}},
            {"action": "compare", "name": "owner_is_a", "op": "equals",
             "left": "{{seen_owner}}", "right": a},
        ],
    }


CHAIN_TEMPLATES = {
    "cross-account-create-read": build_cross_account_create_read,
}


class ChainTool(Tool):
    """LLM-callable: pick a template, supply coordinates, run it, store evidence."""

    name = "run_chain"
    description = (
        "Run a prebuilt multi-step exploit chain (deterministic; you only supply "
        "coordinates). template='cross-account-create-read': account A creates an "
        "object, account B reads it — proves cross-account access. Args: template, "
        "base_url, create_path (POST, returns JSON with id), read_path_template "
        "(e.g. /api/note/{id} — may include ?debug=vuln), body (JSON for create), "
        "owner_field, id_field, accounts (JSON list of 2). Requires test accounts."
    )
    needs_client = True

    def __init__(self, client, db: Database) -> None:
        self.client = client
        self.db = db

    def run(self, template: str, base_url: str, create_path: str,
            read_path_template: str, body: str | dict | None = None,
            owner_field: str = "owner", id_field: str = "id",
            accounts: str | list | None = None) -> ToolResult:
        builder = CHAIN_TEMPLATES.get(str(template))
        if builder is None:
            return ToolResult(False, f"unknown template '{template}'; "
                                     f"available: {', '.join(CHAIN_TEMPLATES)}")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError as exc:
                return ToolResult(False, f"body is not valid JSON: {exc}")
        if isinstance(accounts, str):
            try:
                accounts = json.loads(accounts)
            except json.JSONDecodeError:
                accounts = None
        if not accounts:
            auth = getattr(self.client, "auth", None)
            accounts = list(auth.auth_spec.accounts)[:2] if auth else None
        if not accounts or len(accounts) < 2:
            return ToolResult(False, "need two test accounts (pass accounts or "
                                     "configure auth: in the rulebook)")
        spec = builder(
            base_url=str(base_url), create_path=str(create_path),
            read_path_template=str(read_path_template), body=body,
            owner_field=str(owner_field), id_field=str(id_field),
            accounts=(str(accounts[0]), str(accounts[1])),
        )
        try:
            runner = ChainRunner(self.client, self.db)
            result = runner.run(spec)
        except AgentError as exc:
            return ToolResult(False, str(exc))

        evidence = {"chain": spec, **result.as_dict()}
        if not result.vulnerable:
            return ToolResult(True, f"chain result: {result.classification} — "
                                    f"no finding recorded ({result.notes})")
        fid = self.db.add_finding(
            vuln_type="Access control (chained)", url=base_url + read_path_template,
            parameter="chain", evidence=evidence,
            confidence=0.85, status="candidate",
        )
        return ToolResult(True, f"{result.classification}: evidence stored as "
                                f"finding #{fid} (candidate — awaits validation; "
                                f"note: {spec.get('side_effects')})")
