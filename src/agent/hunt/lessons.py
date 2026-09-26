"""M5e feedback loop: turning validation outcomes into hunt-time memory.

Every rejected candidate becomes a LESSON keyed by a stable signature
(vuln type + host/path + param). Before the next hunt, lessons are injected
into hunter prompts ("known rejections — do not re-chase") and hypotheses
matching a rejected signature are dropped before any LLM call or probe.
Trap regressions from the benchmark suite feed the same store.

Signatures are deliberately coarse (path-shaped, params folded into a
placeholder) so a lesson generalizes across object ids while never matching a
different program. The store lives in SQLite via Database.add_lesson /
list_lessons — memory persists across runs.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..db import Database

# signature granularity: fold numeric/hex/uuid-looking path segments, template
# placeholders ({id}, {{id}}), and any query string into <id> — a rejection of
# /api/note/5001 must cover /api/note/5002 AND a chain template stored as
# /api/note/{id}, but nothing on another host or path shape
_SEGMENT_RE = re.compile(r"^[0-9]+$|^[0-9a-fA-F]{8,}$|^[0-9a-fA-F-]{36}$"
                         r"|^\{\{?[a-zA-Z_][a-zA-Z0-9_]*\}?$")


def _fold_path(path: str) -> str:
    segs = ["<id>" if _SEGMENT_RE.match(seg) else seg.lower()
            for seg in path.split("/") if seg]
    return "/" + "/".join(segs) if segs else "/"


# canonical vulnerability-class families: the validator stores precise vuln
# types ('Access control (chained)') while hypotheses carry coarse classes
# ('idor', 'access-control') — family matching makes rejection rules apply
# across that vocabulary, but never across unrelated classes
_CLASS_FAMILIES: list[tuple[str, tuple[str, ...]]] = [
    ("xss", ("xss", "ssti")),
    ("sqli", ("sql",)),
    ("ssrf", ("ssrf",)),
    ("redirect", ("redirect",)),
    ("access", ("idor", "access", "chained", "authorization", "privilege")),
]


def class_family(name: str) -> str:
    low = (name or "").lower()
    for fam, tokens in _CLASS_FAMILIES:
        if any(t in low for t in tokens):
            return fam
    return low


def _fold_stored_path(sig_path: str) -> str:
    """Fold the path part of a stored signature ('host/api/note/{id}') so it
    matches hypothesis-side paths ('host/api/note/5001'). The host prefix is
    preserved verbatim."""
    if not sig_path or "/" not in sig_path:
        return sig_path
    host_part, _, path_part = sig_path.partition("/")
    return host_part + _fold_path("/" + path_part)


def signature_of(vuln_type: str, url: str, param: str | None = None) -> str:
    """Stable, coarse signature for one (vuln type, URL shape, param)."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = _fold_path(parts.path)
    except ValueError:
        host, path = "", "/"
    sig = f"{host}{path}|{(vuln_type or '').strip().lower()}"
    if param:
        sig += f"|{(param or '').strip().lower()}"
    return sig


def tag_rejection(db: Database, row, reason: str, source: str = "validator") -> int:
    """Turn one rejected finding row into a lesson. Never raises."""
    try:
        sig = signature_of(row["vuln_type"], row["url"], row["parameter"])
        return db.add_lesson(
            signature=sig,
            lesson=f"do not re-chase: {reason[:300]}",
            source=source,
            host=urlsplit(row["url"]).hostname or "",
        )
    except Exception:  # noqa: BLE001 — feedback must never break the pipeline
        return 0


def lessons_block(db: Database, host: str | None = None, max_lessons: int = 12) -> str:
    """Prompt-ready block of known rejections (empty string when none)."""
    rows = db.list_lessons(host=host, min_weight=1)[:max_lessons]
    if not rows:
        return ""
    lines = ["KNOWN REJECTIONS on this program (earlier hunts produced these and a",
             "human/validator rejected them — do NOT re-chase the same pattern; if a",
             "hypothesis matches one of these signatures, skip it and say why):"]
    for r in rows:
        lines.append(f"- [{r['weight']}x] {r['signature']} — {r['lesson']}")
    return "\\n".join(lines)


def filter_hypotheses(hypotheses: list, db: Database,
                      host: str | None = None) -> tuple[list, list]:
    """Drop hypotheses whose (url, class, param) matches a rejected signature.

    Returns (kept, dropped) where dropped entries carry the reason. Only rules
    of a matching vuln class are consulted, so an xss rejection never blocks an
    ssrf hypothesis on the same URL.
    """
    rules: dict[str, set[tuple[str, str | None]]] = {}
    for r in db.list_lessons(host=host):
        try:
            sig_path, sig_type, sig_param = (r["signature"].split("|", 2) + [None])[:3]
        except ValueError:
            continue
        # fold the stored path too, so a lesson recorded from a template URL
        # ({id}) generalizes to concrete ids and vice versa
        rules.setdefault(sig_type, set()).add((_fold_stored_path(sig_path or "/"),
                                               sig_param))

    kept, dropped = [], []
    for h in hypotheses:
        cls = getattr(h, "vuln_class", "")
        url = getattr(h, "url", "")
        param = getattr(h, "param", None)
        cls_fam = class_family(cls)
        sig = signature_of("", url, param).split("|", 1)[0]  # host/path part only
        blocked = False
        for sig_type, pairs in rules.items():
            # empty stored type matches any class; otherwise families must agree
            if sig_type and class_family(sig_type) != cls_fam:
                continue
            for path, rparam in pairs:
                if path == sig and (rparam is None or rparam == (param or "").lower()):
                    blocked = True
                    break
            if blocked:
                break
        if blocked:
            dropped.append((h, "matches a known-rejected signature"))
        else:
            kept.append(h)
    return kept, dropped
