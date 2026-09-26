"""JS/file discovery via katana (ProjectDiscovery's next-gen crawler).

Active crawler: it follows links. Targets passed to it are always concrete,
previously validated URLs from our own inventory — never raw wildcards. Every
discovered URL is scope-checked before it reaches the endpoints store, so a
link to a third-party CDN or an out-of-scope subdomain cannot leak in.
"""
from __future__ import annotations

from ..db import Database
from ..errors import OutOfScopeError
from ..scope.rulebook import Rulebook
from .runner import KATANA, ToolRunner


def run_katana(runner: ToolRunner, rulebook: Rulebook, db: Database,
               targets: list[str], timeout: float = 600.0, depth: int = 2) -> dict:
    checked: list[str] = []
    for t in targets:
        allowed, _ = rulebook.check(t)  # re-verify at launch time
        if not allowed:
            raise OutOfScopeError(f"katana target failed scope re-check: {t}")
        checked.append(t)
    if not checked:
        return {"js": 0, "links": 0, "targets": 0}

    out = runner.run(
        KATANA,
        ["-silent", "-d", str(depth), "-jc", "-kf", "all", "-c", "10",
         "-rl", "30", "-timeout", "10"],
        stdin_text="\n".join(checked),
        timeout=timeout,
    )
    js_count = link_count = 0
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith(("http://", "https://")):
            continue  # skip noise lines
        url = line.split(" ")[0]
        is_js = ".js" in url.split("?")[0].rsplit("/", 1)[-1] or url.endswith(".js")
        allowed, _ = rulebook.check(url)  # every discovered URL re-checked
        if not allowed:
            continue
        if db.add_endpoint(url, "js" if is_js else "link",
                           source="katana", host=None, in_scope=1):
            if is_js:
                js_count += 1
            else:
                link_count += 1
    return {"js": js_count, "links": link_count, "targets": len(checked)}
