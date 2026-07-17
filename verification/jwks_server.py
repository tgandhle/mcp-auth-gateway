"""Serve a JWKS file at /.well-known/jwks.json for local verification.

Reads jwks.json (produced by gen_keys.py) and serves it on 127.0.0.1. Port from
--port or JWKS_PORT (default 9001). Local dev only; binds loopback.
"""
from __future__ import annotations

import argparse
import http.server
import os
import socketserver


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("JWKS_PORT", "9001")))
    ap.add_argument("--jwks", default="jwks.json")
    args = ap.parse_args()

    with open(args.jwks, "rb") as f:
        payload = f.read()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/.well-known/jwks.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a: object) -> None:
            pass

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", args.port), Handler) as httpd:
        print(f"JWKS on http://127.0.0.1:{args.port}/.well-known/jwks.json")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
