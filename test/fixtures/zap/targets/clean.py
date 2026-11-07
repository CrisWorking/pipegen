# Clean ZAP fixture target: one static page, strict headers, no version leak. Local test use only.
from http.server import BaseHTTPRequestHandler, HTTPServer
PAGE = b"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>clean</title></head><body><p>clean</p></body></html>"
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
}
class H(BaseHTTPRequestHandler):
    server_version = "app"
    sys_version = ""
    def version_string(self): return "app"
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in HEADERS.items(): self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def do_GET(self):
        if self.path in ("/", "/index.html"): self._send(200, PAGE)
        else: self._send(404, b"not found", "text/plain; charset=utf-8")
    do_HEAD = do_GET
    def do_POST(self): self._send(405, b"no", "text/plain; charset=utf-8")
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
