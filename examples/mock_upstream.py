#!/usr/bin/env python3
"""Stdlib-only mock upstream used as a deterministic paid endpoint for tests and the demo."""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/ok":
            self._send_json(200, {"result": "ok"})
        elif parsed.path == "/slow":
            time.sleep(5)
            self._send_json(200, {"result": "ok"})
        elif parsed.path == "/fail":
            self._send_json(500, {"error": "fail"})
        elif parsed.path == "/echo":
            self._send_json(
                200,
                {
                    "headers": dict(self.headers.items()),
                    "query": parse_qs(parsed.query),
                },
            )
        else:
            self._send_json(404, {"error": "not found"})

    def _send_json(self, status, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 9000), Handler)
    print("mock upstream listening on http://127.0.0.1:9000")
    server.serve_forever()


if __name__ == "__main__":
    main()
