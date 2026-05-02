#!/usr/bin/env python3
"""
Canary listener with system-fingerprint enrichment.

Layers of capture:

1. Per-request log line (every hit on any path) records source IP, full
   request headers, and the beacon's `t` (token) and `c` (channel) query
   params so trips can be attributed to a specific deployed credential
   and to the validation behavior that fired (ocsp / aia / crl / san /
   icon / urlclick / img / fp ...).

2. GET /page returns an HTML beacon. When a browser renders it, JS
   collects an OS/browser fingerprint (UA, platform, languages,
   timezone, screen, hardware concurrency, device memory, canvas hash,
   WebGL renderer) and POSTs it to /fp. Used as the iframe target from
   companion HTML "instructions" files.

3. POST /fp consumes the JSON fingerprint and logs it as a `fingerprint`
   event tagged with the same token.

Run behind TLS in production. For training a plain HTTP listener on a
lab host is fine.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlsplit


BEACON_PAGE = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>CAC Import Helper</title></head>
<body>
<p>Loading\xe2\x80\xa6</p>
<script>
(async () => {
  const qs = new URLSearchParams(location.search);
  const token = qs.get("t") || "";
  const fp = {
    ua: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: { w: screen.width, h: screen.height, d: screen.colorDepth, dpr: devicePixelRatio },
    hwConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    plugins: Array.from(navigator.plugins || []).map(p => p.name),
    canvas: (() => {
      try {
        const c = document.createElement("canvas");
        const ctx = c.getContext("2d");
        ctx.textBaseline = "top";
        ctx.font = "14px Arial";
        ctx.fillStyle = "#069";
        ctx.fillText("canary-fp", 2, 2);
        return c.toDataURL().slice(-64);
      } catch (e) { return null; }
    })(),
    webgl: (() => {
      try {
        const gl = document.createElement("canvas").getContext("webgl");
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        return dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null;
      } catch (e) { return null; }
    })(),
    referrer: document.referrer,
    href: location.href,
  };
  try {
    await fetch("/fp?t=" + encodeURIComponent(token), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fp),
      keepalive: true,
    });
  } catch (e) {}
  document.body.innerHTML = "<p>Done.</p>";
})();
</script>
</body></html>
"""


EventSink = Callable[[dict], None]


def make_s3_sink(bucket: str, prefix: str) -> EventSink:
    """Return a sink that writes each event as a JSON object to S3.

    Credentials come from the standard boto3 chain (env vars,
    ~/.aws/credentials, instance/task role, SSO). One PUT per event;
    fine for the volumes a canary listener sees.
    """
    try:
        import boto3
    except ImportError:
        sys.exit(
            "S3 sink requested but boto3 is not installed. "
            "Run: pip install boto3"
        )
    client = boto3.client("s3")
    prefix = prefix.strip("/")

    def sink(event: dict) -> None:
        ts = dt.datetime.now(dt.timezone.utc)
        token = event.get("token") or "unknown"
        # Token-major layout: a single list_objects under
        # <prefix>/events/<token>/ enumerates every hit for that token.
        key_parts = [
            prefix,
            "events",
            str(token),
            ts.strftime("%Y/%m/%d"),
            f"{ts.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}.json",
        ]
        key = "/".join(p for p in key_parts if p)
        try:
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=json.dumps(event, default=str).encode("utf-8"),
                ContentType="application/json",
            )
        except Exception as exc:  # pragma: no cover -- best-effort archival
            sys.stderr.write(f"s3 sink error: {exc}\n")

    return sink


def stdout_sink(event: dict) -> None:
    sys.stdout.write(json.dumps(event, default=str) + "\n")
    sys.stdout.flush()


class CanaryHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""
    sinks: list[EventSink] = [stdout_sink]

    def _emit(self, kind: str, **fields) -> None:
        record = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "kind": kind,
            **fields,
        }
        for sink in self.sinks:
            sink(record)

    def _hit(self) -> tuple[str, dict[str, str], str | None, str | None]:
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query)
        token = (qs.get("t") or [None])[0]
        channel = (qs.get("c") or [None])[0]
        headers = {k: v for k, v in self.headers.items()}
        self._emit(
            "request",
            remote=self.client_address[0],
            method=self.command,
            path=parts.path,
            query=parts.query,
            token=token,
            channel=channel,
            headers=headers,
        )
        return parts.path, headers, token, channel

    def do_GET(self) -> None:  # noqa: N802
        path, _headers, token, _channel = self._hit()
        if path == "/page":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(BEACON_PAGE)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(BEACON_PAGE)
            return
        # Default: 1x1 transparent GIF so <img> / icon fetches succeed
        # quietly. Cert validators that expect specific bodies will treat
        # this as malformed -- which is fine, we already logged the hit.
        gif = (
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
            b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
            b"\x00\x00\x02\x02D\x01\x00;"
        )
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(gif)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(gif)

    def do_HEAD(self) -> None:  # noqa: N802
        self._hit()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        path, _headers, token, _channel = self._hit()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/fp":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {"raw": body[:512].hex()}
            self._emit(
                "fingerprint",
                remote=self.client_address[0],
                token=token,
                payload=payload,
            )
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # silence default stderr noise
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--s3-bucket",
        default=None,
        help="If set, each event is also archived as a JSON object in this "
        "bucket. Uses standard AWS credential chain.",
    )
    parser.add_argument(
        "--s3-prefix",
        default="canary",
        help="Key prefix inside the bucket (default: canary)",
    )
    args = parser.parse_args()

    sinks: list[EventSink] = [stdout_sink]
    if args.s3_bucket:
        sinks.append(make_s3_sink(args.s3_bucket, args.s3_prefix))
        sys.stderr.write(
            f"archiving to s3://{args.s3_bucket}/{args.s3_prefix.strip('/')}/events/...\n"
        )
    CanaryHandler.sinks = sinks

    server = ThreadingHTTPServer((args.bind, args.port), CanaryHandler)
    sys.stderr.write(f"listening on {args.bind}:{args.port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
