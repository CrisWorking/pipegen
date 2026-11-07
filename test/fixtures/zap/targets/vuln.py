# Vulnerable ZAP fixture target: reflected XSS in /search?q=, no security headers. Local test use only, never deploy.
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
INDEX = b"<html><head><title>vuln</title></head><body><a href=\"/search?q=hello\">search</a><form action=\"/search\" method=\"get\"><input name=\"q\"><input type=\"submit\"></form></body></html>"
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            body = INDEX
        elif u.path == "/search":
            q = parse_qs(u.query).get("q", [""])[0]
            body = ("<html><body><p>You searched for: " + q + "</p></body></html>").encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
