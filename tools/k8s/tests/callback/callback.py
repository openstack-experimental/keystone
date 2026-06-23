#!/usr/bin/env python3
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
"""Simple callback server for Dex OIDC test."""
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DATA_FILE = os.environ.get("DATA_FILE", "/tmp/callback_data.json")


class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/oidc/callback":
            print(f"CAPTURE: GET callback {parsed.query}", flush=True)
            params = parse_qs(parsed.query)
            data = {k: v[0] for k, v in params.items()}
            with open(DATA_FILE, "w") as f:
                json.dump(data, f)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"OK")
        elif parsed.path == "/status":
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE) as f:
                    data = json.load(f)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            else:
                self.send_response(204)
                self.end_headers()
        elif parsed.path == "/clear":
            if os.path.exists(DATA_FILE):
                os.remove(DATA_FILE)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[{self.client_address[0]}] {format % args}", flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8050"))
    server = HTTPServer(("0.0.0.0", port), CallbackHandler)
    print(f"listening on {port}", flush=True)
    server.serve_forever()
