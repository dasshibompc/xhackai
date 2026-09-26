"""A deliberately vulnerable local web app for development and testing.

ONLY for local authorized testing of the agent. Do not deploy anywhere.

Vulnerabilities included (M1 test targets):
  1. Reflected XSS      — /search?q=<script>...
  2. Open redirect      — /redirect?url=https://evil.example
  3. IDOR               — /api/user/<id> returns any id's data
  4. SQL injection      — /login (string-concatenated query)
"""
from __future__ import annotations

import argparse
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

PAGE = """<!doctype html><html><head><title>Lab App</title></head><body>
<h1>Lab App</h1>
<ul>
  <li><a href="/search?q=test">search</a></li>
  <li><a href="/redirect?url=/search?q=ok">redirect demo</a></li>
  <li><a href="/api/user/1">user 1</a></li>
</ul>
<h2>Login</h2>
<form method="post" action="/login">
  <input name="username"><input name="password" type="password">
  <button>login</button>
</form>
</body></html>"""


class LabHandler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        qs = parse_qs(u.query)

        if u.path == "/":
            return self._send(200, PAGE)

        if u.path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin\n")

        if u.path == "/search":  # reflected XSS
            q = qs.get("q", [""])[0]
            return self._send(200, f"<h1>Results for: {q}</h1><p>No results.</p>")

        if u.path == "/redirect":  # open redirect
            target = qs.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return None

        if u.path == "/fetch":  # SSRF demo: server fetches attacker-supplied URL
            target = qs.get("url", [""])[0]
            if not target:
                return self._send(400, "missing url param")
            import urllib.request
            try:
                with urllib.request.urlopen(target, timeout=5) as r:
                    return self._send(200, r.read(4096).decode("utf-8", "replace"))
            except Exception as exc:
                return self._send(502, f"fetch failed: {exc}")

        if u.path.startswith("/api/user/"):  # IDOR
            uid = u.path.rsplit("/", 1)[1]
            return self._send(
                200,
                f'{{"id": {quote(uid)}, "username": "user{uid}", "email": "user{uid}@lab.local", "ssn": "123-45-{uid:0>4}"}}',
                content_type="application/json",
            )

        if u.path == "/admin":
            return self._send(403, "<h1>forbidden</h1>")

        return self._send(404, "<h1>not found</h1>")

    def do_POST(self) -> None:  # noqa: N802 — SQL injection demo
        length = int(self.headers.get("Content-Length", 0))
        params = parse_qs(self.rfile.read(length).decode())
        user = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        conn = sqlite3.connect("lab_users.db")
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
        conn.execute("INSERT OR IGNORE INTO users VALUES ('admin', 's3cret')")
        conn.commit()
        query = f"SELECT username FROM users WHERE username='{user}' AND password='{password}'"
        try:
            rows = conn.execute(query).fetchall()
        except sqlite3.OperationalError as exc:
            return self._send(200, f"<h1>Login</h1><p>error: {exc}</p>")
        if rows:
            return self._send(200, f"<h1>Welcome {rows[0][0]}</h1>")
        return self._send(200, "<h1>Login failed</h1>")

    def log_message(self, *args) -> None:  # silence default logging
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    print(f"vulnerable lab app on http://127.0.0.1:{args.port}")

    class LabServer(ThreadingHTTPServer):
        allow_reuse_address = True

    LabServer(("127.0.0.1", args.port), LabHandler).serve_forever()
