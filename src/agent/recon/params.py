"""M5c coverage engine, part 1: parameter mining from observed reality.

The DISCOVERY_RULE already tells hunters "never probe guessed parameters" —
but nothing supplied them with the real ones. This module turns three sources
into a deduplicated parameter inventory:

1. the endpoints table (xnLinkFinder already emits ``param:<name>`` rows);
2. HTML bodies of known live pages: <form> inputs (kind=form) and query
   strings of discovered links (kind=query);
3. reflected-param detection while probing (kind=reflected).

Everything harvested flows into the hypotheses digest v2, so hunters probe
real names instead of guessing. The brute-force stage (discover_hidden_params)
is an Arjun-style differential scan under a strict per-run request budget.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

from ..db import Database
from ..errors import OutOfScopeError
from ..scope.client import EnforcingClient
from ..scope.rulebook import Rulebook
from ..tools import Tool, ToolResult

# parameter-ish names worth keeping from JS-ish text; too permissive is fine,
# the brute-force stage ranks by response differential anyway
_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-\.]{0,63}$")
_JUNK_NAMES = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "_ga", "ref",
}


class _FormParser(HTMLParser):
    """Collects <form> input/select/textarea names and link query params."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.form_fields: list[str] = []
        self.links: list[str] = []
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._in_form = True
        elif tag in ("input", "select", "textarea") and self._in_form:
            name = a.get("name")
            if name and _NAME_RE.match(name):
                self.form_fields.append(name)
        elif tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


def parse_html_links(html: str) -> list[str]:
    """Absolute-ized hrefs from one HTML document (for crawl-follow mining)."""
    from urllib.parse import urljoin
    p = _FormParser()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001
        return []
    return [urljoin("http://_rel_/", href) if not href.startswith(("http://", "https://"))
            else href for href in p.links]


def parse_html_params(html: str) -> tuple[set[str], set[str]]:
    """(form_field_names, link_query_param_names) from one HTML document."""
    p = _FormParser()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001 — malformed HTML must not kill mining
        pass
    query_names: set[str] = set()
    for href in p.links:
        q = urlsplit(href).query
        for name, _val in parse_qsl(q, keep_blank_values=True):
            if _NAME_RE.match(name):
                query_names.add(name)
    return set(p.form_fields), query_names


def mine_params(client: EnforcingClient, db: Database, rulebook: Rulebook,
                max_pages: int = 25) -> dict:
    """Mine parameters from stored endpoints (page bodies fetched fresh) and
    record them in the params table. Scope-checked like everything else.

    Crawl-follow: links discovered on fetched pages (same host, in scope) are
    fetched too, up to max_pages total — the homepage alone hides most of the
    real attack surface (deep pages carry their own forms and query params).
    """
    from urllib.parse import urljoin, urlsplit
    stats = {"pages": 0, "forms": 0, "query": 0, "mined": 0, "errors": 0,
             "followed": 0}
    rows = db.list_endpoints()
    queue: list[str] = [
        r["url"] for r in rows
        if r["kind"] in ("link", "page") and r["url"].startswith(("http://", "https://"))
    ]
    # always include the live asset URLs even if no crawl ran
    for r in db.conn.execute(
        "SELECT url FROM assets WHERE in_scope=1 AND url IS NOT NULL"
    ).fetchall():
        queue.append(r["url"])
    fetched: set[str] = set()

    def _harvest(url: str, html: str) -> None:
        host = urlsplit(url).hostname or ""
        forms, queries = parse_html_params(html)
        for name in forms:
            if name.lower() in _JUNK_NAMES:
                continue
            if db.add_param(name, host, "form", source="mining", example_url=url):
                stats["forms"] += 1
        for name in queries:
            if name.lower() in _JUNK_NAMES:
                continue
            if db.add_param(name, host, "query", source="mining", example_url=url):
                stats["query"] += 1
        stats["pages"] += 1

    while queue and stats["pages"] < max_pages:
        url = queue.pop(0).split("#")[0]
        if url in fetched:
            continue
        fetched.add(url)
        host = urlsplit(url).hostname or ""
        if not host:
            continue
        try:
            resp = client.get(url)
        except OutOfScopeError:
            continue  # links can point out of scope; skip silently
        except Exception:  # noqa: BLE001 — one bad page must not stop mining
            stats["errors"] += 1
            continue
        if resp.status_code != 200 or "html" not in (resp.headers.get("content-type") or ""):
            continue
        _harvest(url, resp.text)
        # follow same-host, in-scope links (depth-1 crawl within the budget)
        for href in parse_html_links(resp.text):
            try:
                abs_url = urljoin(url, href).split("#")[0]
            except ValueError:
                continue
            if abs_url in fetched:
                continue
            try:
                link_host = urlsplit(abs_url).hostname or ""
            except ValueError:
                continue
            if link_host != host or not abs_url.startswith(("http://", "https://")):
                continue
            if not rulebook.check(abs_url)[0]:
                continue
            if abs_url not in queue and stats["pages"] + len(queue) < max_pages:
                queue.append(abs_url)
                db.add_endpoint(abs_url, "page", source="mining-crawl")
                stats["followed"] += 1
    stats["mined"] = stats["forms"] + stats["query"]
    return stats


# ----------------------------------------------------- hidden-param brute-force

# candidate names for differential discovery; small on purpose — every miss
# costs a request and rate budgets belong to the program owner
HIDDEN_PARAM_CANDIDATES = [
    "debug", "test", "admin", "dev", "staging", "internal", "hidden", "secret",
    "console", "render", "view", "format", "export", "include", "template",
    "page", "file", "path", "url", "redirect", "next", "return", "dest",
    "id", "user", "uid", "token", "key", "action", "cmd", "exec", "type",
    "status", "q", "search", "sort", "filter", "limit", "offset", "lang",
]

# unique, benign marker values; a differential must reproduce on the marker
_MARKER_VALUES = ["m5cprobe1", "m5cprobe2"]


def _norm(resp) -> str:
    """Response fingerprint: status + length bucket (body normalized)."""
    import re as _re
    body = _re.sub(r"\s+", " ", resp.text or "").strip().lower()
    return f"{resp.status_code}:{len(body) // 32}"


def discover_hidden_params(client: EnforcingClient, db: Database,
                           url: str, candidates: list[str] | None = None,
                           max_requests: int = 120) -> dict:
    """Arjun-style discovery: baseline with a nonsense param, then re-request
    with each candidate set to a unique marker. A param is 'interesting' when
    its response differs from baseline consistently across two markers.

    Request budget is honored strictly: (1 baseline + 2 per candidate).
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    def _set_param(target: str, name: str, value: str) -> str:
        parts = urlsplit(target)
        q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != name] + [(name, value)]
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           urlencode(q), parts.fragment))

    candidates = candidates or HIDDEN_PARAM_CANDIDATES
    # budget guard: trim candidates to what the allowance permits
    budget = max(0, max_requests - 1)
    usable = max(0, budget // 2)
    candidates = candidates[:usable]
    if not candidates:
        return {"ok": False, "error": "request budget too small", "found": []}

    baseline_url = _set_param(url, "nonexistm5c", "1")
    try:
        baseline = client.get(baseline_url)
    except OutOfScopeError:
        raise  # scope violations are never soft failures
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"baseline request failed: {exc}", "found": []}
    base_fp = _norm(baseline)

    interesting: list[dict] = []
    host = urlsplit(url).hostname or ""
    spent = 1
    for name in candidates:
        fps = []
        for marker in _MARKER_VALUES:
            if spent >= max_requests:
                break
            try:
                resp = client.get(_set_param(url, name, marker))
                spent += 1
                fps.append(_norm(resp))
            except Exception:  # noqa: BLE001
                fps.append(None)
        if len(fps) == 2 and fps[0] == fps[1] and fps[0] != base_fp:
            interesting.append({"name": name, "fingerprint": fps[0],
                                "example_url": _set_param(url, name, "m5cprobe1")})
            db.add_param(name, host, "differential", source="bruteforce",
                         example_url=_set_param(url, name, "m5cprobe1"))
    return {"ok": True, "found": interesting, "requests_spent": spent,
            "candidates_tried": len(candidates), "baseline_fingerprint": base_fp}


# --------------------------------------------------------------------- tools

class ParamMiningTool(Tool):
    name = "mine_params"
    description = (
        "Mine REAL parameter names from the target's pages and forms (mining, "
        "no guessing) into the params inventory. Run before hunting."
    )
    needs_client = True

    def __init__(self, client: EnforcingClient, db: Database,
                 rulebook: Rulebook) -> None:
        self.client = client
        self.db = db
        self.rulebook = rulebook

    def run(self, max_pages: int = 25) -> ToolResult:
        stats = mine_params(self.client, self.db, self.rulebook,
                            max_pages=max(1, min(int(max_pages), 50)))
        return ToolResult(True, f"mining: {stats}")


class HiddenParamTool(Tool):
    name = "discover_hidden_params"
    description = (
        "Arjun-style hidden-parameter discovery on ONE known URL: requests with "
        "candidate param names set to unique markers; params whose responses "
        "differ from baseline consistently are recorded as differential params. "
        "Args: url [, max_requests up to 200]. Honors a strict request budget."
    )
    needs_client = True

    def __init__(self, client: EnforcingClient, db: Database) -> None:
        self.client = client
        self.db = db

    def run(self, url: str, max_requests: int = 120) -> ToolResult:
        try:
            res = discover_hidden_params(self.client, self.db, url,
                                         max_requests=max(10, min(int(max_requests), 200)))
        except OutOfScopeError as exc:
            return ToolResult(False, str(exc))
        if not res.get("ok"):
            return ToolResult(False, str(res.get("error")))
        names = [f["name"] for f in res.get("found", [])]
        return ToolResult(True, f"spent {res['requests_spent']} requests; "
                                f"differential params: {names or 'none'}")


def build_param_tools(client: EnforcingClient, db: Database,
                      rulebook: Rulebook) -> dict[str, Tool]:
    a = ParamMiningTool(client, db, rulebook)
    b = HiddenParamTool(client, db)
    return {a.name: a, b.name: b}
