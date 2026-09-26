"""A deliberately vulnerable local web app for development and testing.

ONLY for local authorized testing of the agent. Do not deploy anywhere.

Vulnerabilities included:
  M1: Reflected XSS      — /search?q=<script>...
  M1: Open redirect      — /redirect?url=https://evil.example
  M1: IDOR               — /api/user/<id> returns any id's data
  M1: SQL injection      — /login (string-concatenated query)
  M3: SSRF               — /fetch?url=http://127.0.0.1:PORT/
  M4: Access control     — /api/invoice/<id>?debug=vuln skips the ownership
                           check ("legacy compatibility mode"); without the
                           flag the endpoint correctly denies foreign ids.

M4 test accounts (LOCAL lab credentials only):
  alice / 123456   (user id 101)
  bob / abcdef     (user id 102)
"""
from __future__ import annotations

import argparse
import secrets
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

# Local lab test accounts — never use real credentials here.
LAB_ACCOUNTS = {
    "alice": {"password": "123456", "user_id": 101},
    "bob": {"password": "abcdef", "user_id": 102},
}
_SESSIONS: dict[str, str] = {}  # session token -> username
_SESSION_LOCK = threading.Lock()

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
<h2>Customer portal</h2>
<form method="post" action="/login-session">
  <input name="username"><input name="password" type="password">
  <button>sign in</button>
</form>
<!-- debug=vuln on invoice endpoints enables legacy compatibility mode -->
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

        if u.path == "/api/me":  # session identity (M4 auth harness target)
            user = self._session_user()
            if user is None:
                return self._send(401, '{"error": "authentication required"}',
                                  content_type="application/json")
            import json as _json
            return self._send(200, _json.dumps({
                "username": user, "user_id": LAB_ACCOUNTS[user]["user_id"],
            }), content_type="application/json")

        if u.path == "/api/invoices":  # the session user's own object list
            user = self._session_user()
            if user is None:
                return self._send(401, '{"error": "authentication required"}',
                                  content_type="application/json")
            import json as _json
            uid = LAB_ACCOUNTS[user]["user_id"]
            return self._send(200, _json.dumps({"invoices": [
                {"id": uid, "owner": user, "amount": uid * 91,
                 "description": f"services rendered for {user}"},
            ]}), content_type="application/json")

        if u.path.startswith("/api/invoice/"):  # M4 access-control target
            return self._handle_invoice(u, qs)

        if u.path == "/logout":
            token = self._session_token()
            with _SESSION_LOCK:
                _SESSIONS.pop(token, None)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "sid=; Path=/; Max-Age=0")
            self.end_headers()
            return None

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

    def _session_token(self) -> str:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if part.strip().startswith("sid="):
                return part.strip()[4:]
        return ""

    def _session_user(self) -> str | None:
        token = self._session_token()
        if not token:
            return None
        with _SESSION_LOCK:
            return _SESSIONS.get(token)

    def _handle_invoice(self, u, qs) -> None:
        """Ownership-checked invoice endpoint with a seeded broken-access-control
        mode: ?debug=vuln ("legacy compatibility") skips the ownership check."""
        import json as _json
        user = self._session_user()
        if user is None:
            return self._send(401, '{"error": "authentication required"}',
                              content_type="application/json")
        try:
            invoice_id = int(u.path.rsplit("/", 1)[1])
        except ValueError:
            return self._send(404, '{"error": "no such invoice"}',
                              content_type="application/json")
        owner_name, owner = next(
            ((name, acct) for name, acct in LAB_ACCOUNTS.items()
             if acct["user_id"] == invoice_id),
            (None, None),
        )
        if owner is None:
            return self._send(404, '{"error": "no such invoice"}',
                              content_type="application/json")
        # the vulnerability: debug=vuln bypasses the ownership check
        if "debug" not in qs or qs["debug"][0] != "vuln":
            if invoice_id != LAB_ACCOUNTS[user]["user_id"]:
                return self._send(403, '{"error": "access denied"}',
                                  content_type="application/json")
        return self._send(200, _json.dumps({
            "id": invoice_id, "owner": owner_name,
            "amount": invoice_id * 91,
            "description": f"services rendered for {owner_name}",
        }), content_type="application/json")

    def do_POST(self) -> None:  # noqa: N802 — SQL injection demo / session login
        length = int(self.headers.get("Content-Length", 0))
        params = parse_qs(self.rfile.read(length).decode())
        u = urlparse(self.path)

        if u.path == "/login-session":  # cookie-session login (M4)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            acct = LAB_ACCOUNTS.get(username)
            if acct is None or acct["password"] != password:
                return self._send(401, "<h1>sign in failed</h1>")
            token = secrets.token_hex(16)
            with _SESSION_LOCK:
                _SESSIONS[token] = username
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", f"sid={token}; Path=/; HttpOnly")
            self.end_headers()
            body = f"<h1>Welcome {username}</h1><a href=\"/api/invoices\">your invoices</a>"
            self.wfile.write(body.encode())
            return None

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
