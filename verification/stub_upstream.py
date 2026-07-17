"""Minimal stub MCP upstream for local verification.

Answers any POST with a fixed JSON-RPC result so a forwarded (authorized)
request is observable. Port from --port or UPSTREAM_PORT (default 9000). Local
dev only; binds loopback. Not an MCP implementation, just an echo target.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import socketserver


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("UPSTREAM_PORT", "9000")))
    args = ap.parse_args()

    body = json.dumps({"jsonrpc": "2.0", "result": {"upstream": "reached"}, "id": 1}).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            n = int(self.headers.get("content-length", 0))
            self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", args.port), Handler) as httpd:
        print(f"stub upstream on http://127.0.0.1:{args.port}/")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
