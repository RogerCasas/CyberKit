"""
CyberKit — Local deliberately-vulnerable test server (stdlib only).

A safe, self-contained target for exercising the v4.1 web-attack tools on your
own machine. NOT part of the app and NOT meant for deployment — it intentionally
contains insecure endpoints so the detectors have something to find.

Run:
    python testbed/vuln_server.py
Then point the tools at http://127.0.0.1:8000/...  (see the printed menu).

Stop with Ctrl+C.
"""

# ─── HOW TO RUN ──────────────────────────────────────────────────────────────
# From the project root (the folder that contains the `app/` and `testbed/`
# directories), run:
#
#     python testbed/vuln_server.py
#
# Leave it running in its own terminal, then use the tools in another window.
# Press Ctrl+C in this terminal to stop the server.
# ─────────────────────────────────────────────────────────────────────────────

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST, PORT = "127.0.0.1", 8000

# MySQL-style error string the SQLi Tester's error patterns match.
SQL_ERROR = ("You have an error in your SQL syntax; check the manual that "
             "corresponds to your MySQL server version near \"'\" at line 1")

MENU = """<!doctype html><html><body style="font-family:sans-serif">
<h2>CyberKit local test target</h2>
<ul>
 <li><b>XSS (vulnerable):</b> /xss?q=test</li>
 <li><b>XSS (safe / encoded):</b> /xss-safe?q=test</li>
 <li><b>SQLi (error-based):</b> /sqli?id=1</li>
 <li><b>Open Redirect:</b> /redirect?next=/home</li>
 <li><b>CSRF-weak login form:</b> /login</li>
</ul></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code=200, body="", ctype="text/html", extra_headers=None):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _q(self, name, default=""):
        qs = parse_qs(urlparse(self.path).query)
        return qs.get(name, [default])[0]

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self._send(body=MENU)

        elif path == "/xss":
            # VULNERABLE: reflects the parameter raw into the HTML body.
            q = self._q("q")
            self._send(body=f"<html><body>You searched for: {q}</body></html>")

        elif path == "/xss-safe":
            # SAFE: reflects the parameter HTML-escaped (should NOT be flagged).
            q = self._q("q")
            self._send(body=f"<html><body>You searched for: {html.escape(q)}</body></html>")

        elif path == "/sqli":
            # ERROR-BASED: any quote in `id` "breaks the query" and leaks an error.
            ident = self._q("id", "1")
            if "'" in ident or '"' in ident or "\\" in ident:
                self._send(code=500, body=f"<html><body><pre>{SQL_ERROR}</pre></body></html>")
            else:
                self._send(body=f"<html><body>Product #{html.escape(ident)} found.</body></html>")

        elif path == "/redirect":
            # OPEN REDIRECT: echoes `next` straight into the Location header.
            nxt = self._q("next", "/home")
            self._send(code=302, body="", extra_headers=[("Location", nxt)])

        elif path == "/login":
            # CSRF-WEAK: no anti-CSRF token, cookie has no SameSite attribute.
            form = ("<html><body><h3>Login</h3>"
                    "<form method='post' action='/login'>"
                    "<input name='username'><input name='password' type='password'>"
                    "<button>Sign in</button></form></body></html>")
            self._send(body=form, extra_headers=[("Set-Cookie", "session=abc123; Path=/")])

        else:
            self._send(code=404, body="<html><body>404</body></html>")

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
        except (ValueError, OSError):
            pass
        if path == "/login":
            # Accepts the POST regardless of Origin/Referer (no CSRF protection).
            self._send(body="<html><body>Signed in.</body></html>")
        else:
            self._send(code=404, body="<html><body>404</body></html>")


def _print_guide():
    base = f"http://{HOST}:{PORT}"
    line = "=" * 74
    print(line)
    print(f"  CyberKit local test target - running at {base}/")
    print("  Press Ctrl+C to stop.")
    print(line)
    print()
    print("  Paste each URL below into the matching tool. For XSS / SQLi /")
    print("  Open Redirect: paste the URL, click \"Parse from URL\", then Scan.")
    print()
    rows = [
        ("XSS Tester",    f"{base}/xss?q=test",
         "param 'q'  -> VULNERABLE  (payload reflected unescaped)"),
        ("XSS Tester",    f"{base}/xss-safe?q=test",
         "param 'q'  -> Clean       (reflection is HTML-encoded; no finding)"),
        ("SQLi Tester",   f"{base}/sqli?id=1",
         "param 'id' -> VULNERABLE  (error-based SQL injection)"),
        ("Open Redirect", f"{base}/redirect?next=/home",
         "param 'next' -> VULNERABLE (redirects to an external host)"),
        ("CSRF Analyser", f"{base}/login",
         "WARN: cookie has no SameSite + form has no anti-CSRF token"),
    ]
    for tool, url, expected in rows:
        print(f"  {tool:<14} {url}")
        print(f"  {'':<14} -> {expected}")
        print()
    print(line)


if __name__ == "__main__":
    _print_guide()
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
