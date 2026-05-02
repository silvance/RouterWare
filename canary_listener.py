#!/usr/bin/env python3
"""
Minimal canary listener.

Logs every request hitting any path and emits a structured line with the
beacon's `t` (token) and `c` (channel) query parameters so you can tell
which deployed CAC-style credential tripped and which extension was
responsible (ocsp / aia / crl / san).

Run behind TLS in real use; for training a plain HTTP listener on a lab
host is fine.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class CanaryHandler(BaseHTTPRequestHandler):
    def _log_hit(self) -> None:
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query)
        record = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "remote": self.client_address[0],
            "method": self.command,
            "path": parts.path,
            "token": (qs.get("t") or [None])[0],
            "channel": (qs.get("c") or [None])[0],
            "ua": self.headers.get("User-Agent"),
            "host": self.headers.get("Host"),
        }
        sys.stdout.write(json.dumps(record) + "\n")
        sys.stdout.flush()

    def do_GET(self) -> None:  # noqa: N802
        self._log_hit()
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET
    do_POST = do_GET

    def log_message(self, format: str, *args) -> None:  # silence default stderr noise
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), CanaryHandler)
    sys.stderr.write(f"listening on {args.bind}:{args.port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
