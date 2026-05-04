#!/usr/bin/env python3
"""
Canary listener.

Routes path-encoded beacons of shape /v/<token>/[<role>/]<filename>,
infers the channel from the filename suffix, and emits a structured
event to every configured sink (stdout always; S3 if --s3-bucket).

Channels (recognised by filename):
  ocsp                                    -> ocsp
  *.crl                                   -> crl
  *.p7c, *.p7s                            -> aia
  *.ico                                   -> icon       (Explorer icon fetch)
  help                                    -> urlclick   (.url URL= click)
  *.gif                                   -> img        (HTML pixel)
  page                                    -> page       (serves HTML beacon)
  fp                                      -> fp         (POST endpoint for JS fp)
  *.dotx, *.dot, *.docx                   -> tmpl       (Word attachedTemplate)
  pdf-open, *.pdf                         -> pdf        (PDF /OpenAction /URI)

When `<role>` is present (id/sig/enc), it identifies which CAC cert
fired the beacon.

Run behind TLS in production. For training a plain HTTP listener on a
lab host is fine.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import signal
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit


BEACON_PAGE = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>CAC Import Helper</title></head>
<body>
<p>Loading\xe2\x80\xa6</p>
<script>
(async () => {
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
    await fetch(location.pathname.replace(/\\/page$/, "/fp"), {
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


# 1x1 transparent GIF -- bodyless OK for cert/icon validators, harmless
# fallback for anything else.
PIXEL_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
    b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
    b"\x00\x00\x02\x02D\x01\x00;"
)


def channel_for(filename: str) -> str:
    """Map the last path segment to a channel name."""
    if filename == "ocsp":
        return "ocsp"
    if filename.endswith(".crl"):
        return "crl"
    if filename.endswith((".p7c", ".p7s")):
        return "aia"
    if filename.endswith(".ico"):
        return "icon"
    if filename == "help":
        return "urlclick"
    if filename.endswith(".gif"):
        return "img"
    if filename == "page":
        return "page"
    if filename == "fp":
        return "fp"
    if filename.endswith((".dotx", ".dot", ".docx")):
        return "tmpl"
    if filename == "pdf-open" or filename.endswith(".pdf"):
        return "pdf"
    return "unknown"


def parse_path(path: str) -> tuple[str | None, str | None, str | None]:
    """
    Parse /v/<token>/[<role>/]<file>.
    Returns (token, role, channel); any of them may be None.
    """
    parts = path.strip("/").split("/")
    if len(parts) < 2 or parts[0] != "v":
        return None, None, None
    token = parts[1]
    rest = parts[2:]
    if not rest:
        return token, None, None
    if len(rest) >= 2 and rest[0] in {"id", "sig", "enc"}:
        return token, rest[0], channel_for(rest[-1])
    return token, None, channel_for(rest[-1])


EventSink = Callable[[dict], None]


def s3_event_path(event: dict, prefix: str) -> str:
    """S3 path prefix (without date/random suffix) for an event.

    Token-major: events with a parsed token AND a recognised channel
    go under <prefix>/events/<token>/. Anything else -- scanner
    traffic on /robots.txt or /.env, unrecognised filenames under
    /v/<token>/, plain HTTP probes -- goes to <prefix>/unknown/ so it
    doesn't pollute per-token analysis.
    """
    token = event.get("token")
    channel = event.get("channel")
    if not token or channel == "unknown":
        return f"{prefix}/unknown"
    return f"{prefix}/events/{token}"


def make_s3_sink(bucket: str, prefix: str) -> EventSink:
    """Write each event as a JSON object to S3.

    Uses s3_event_path() for routing, so all non-token traffic lands
    under <prefix>/unknown/<date>/ instead of polluting events/.
    Calls head_bucket at startup to fail fast on credential or
    bucket-access problems.
    """
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        sys.exit(
            "S3 sink requested but boto3 is not installed. Run: pip install boto3"
        )
    client = boto3.client("s3")
    try:
        client.head_bucket(Bucket=bucket)
    except (BotoCoreError, ClientError) as exc:
        sys.exit(f"s3 sink: bucket {bucket!r} not accessible: {exc}")
    prefix = prefix.strip("/")

    def sink(event: dict) -> None:
        ts = dt.datetime.now(dt.timezone.utc)
        suffix = f"{ts.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}.json"
        base = s3_event_path(event, prefix)
        key = f"{base}/{ts.strftime('%Y/%m/%d')}/{suffix}"
        try:
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=json.dumps(event, default=str).encode("utf-8"),
                ContentType="application/json",
            )
        except (BotoCoreError, ClientError) as exc:  # best-effort archival
            sys.stderr.write(f"s3 sink error: {exc}\n")

    return sink


def stdout_sink(event: dict) -> None:
    sys.stdout.write(json.dumps(event, default=str) + "\n")
    sys.stdout.flush()


# ---- Webhook sink (Slack + generic) --------------------------------------

def webhook_matches(
    event: dict, channels: set[str] | None, include_unknown: bool
) -> bool:
    """Predicate: should this event be forwarded to a webhook?"""
    ch = event.get("channel")
    if not include_unknown and ch == "unknown":
        return False
    if channels is None:
        return True
    kind = event.get("kind")
    if kind == "fingerprint":
        return "fingerprint" in channels
    role = event.get("role")
    if ch in channels:
        return True
    if role and f"{role}/{ch}" in channels:
        return True
    return False


def webhook_payload(event: dict, fmt: str) -> dict:
    """Render an event into the webhook body for the chosen format."""
    if fmt == "generic":
        return event
    if fmt != "slack":
        raise ValueError(f"unknown webhook format: {fmt!r}")

    token = event.get("token") or "?"
    remote = event.get("remote") or "?"
    ts = event.get("ts") or "?"

    if event.get("kind") == "fingerprint":
        p = event.get("payload") or {}
        screen = p.get("screen") or {}
        bullets = []
        ua = p.get("ua")
        if ua:
            bullets.append(f"UA: `{ua[:120]}`")
        if tz := p.get("tz"):
            bullets.append(f"TZ: `{tz}`")
        if screen.get("w") and screen.get("h"):
            bullets.append(f"Screen: `{screen['w']}x{screen['h']}`")
        if webgl := p.get("webgl"):
            bullets.append(f"GPU: `{webgl[:80]}`")
        hw_bits = []
        if hw := p.get("hwConcurrency"):
            hw_bits.append(f"{hw} cores")
        if mem := p.get("deviceMemory"):
            hw_bits.append(f"{mem} GB")
        if hw_bits:
            bullets.append("HW: " + ", ".join(hw_bits))
        text = (
            f":rotating_light: *Canary tripped — fingerprint*\n"
            f"Token `{token}` from `{remote}` at {ts}\n"
            + "\n".join(bullets)
        )
    else:
        ch = event.get("channel") or "?"
        role = event.get("role")
        label = f"{role}/{ch}" if role else ch
        ua = (event.get("headers") or {}).get("User-Agent", "")
        text = (
            f":warning: Canary hit\n"
            f"Token `{token}` channel `{label}` from `{remote}` at {ts}\n"
            f"UA: `{ua[:120]}`"
        )
    return {"text": text}


def make_webhook_sink(
    url: str,
    fmt: str = "generic",
    channels: set[str] | None = None,
    include_unknown: bool = False,
) -> EventSink:
    """Fan out matching events to a webhook URL.

    Each event gets its own daemon thread doing a best-effort POST so a
    slow webhook doesn't block the request handler.
    """
    import urllib.request

    def post(event: dict) -> None:
        body = json.dumps(
            webhook_payload(event, fmt), default=str
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as exc:  # best-effort
            sys.stderr.write(f"webhook error: {exc}\n")

    def sink(event: dict) -> None:
        if not webhook_matches(event, channels, include_unknown):
            return
        threading.Thread(target=post, args=(event,), daemon=True).start()

    return sink


# Cap on POST body size. Real fingerprint payloads are <2 KB; 64 KB
# leaves headroom while bounding memory use against malicious clients.
MAX_BODY_BYTES = 65_536


class CanaryHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""
    sinks: list[EventSink] = [stdout_sink]
    # Per-request socket timeout. Slowloris-style attacks tie up
    # threads if this is None (the default). 30 seconds is generous
    # for legit cert/AIA fetches and tight enough to bound a thread.
    timeout = 30

    def _emit(self, kind: str, **fields) -> None:
        record = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "kind": kind,
            **fields,
        }
        for sink in self.sinks:
            sink(record)

    def _parse(self) -> tuple[str | None, str | None, str | None, dict]:
        path = urlsplit(self.path).path
        token, role, channel = parse_path(path)
        # Preserve duplicate headers (matters for proxy chains writing
        # multiple X-Forwarded-For headers) by joining with ", ", which
        # is the RFC 7230 equivalent of multiple identical-name headers.
        headers: dict[str, str] = {}
        for k, v in self.headers.items():
            if k in headers:
                headers[k] = f"{headers[k]}, {v}"
            else:
                headers[k] = v
        return token, role, channel, headers

    def _emit_request(self, channel: str | None, role: str | None,
                      token: str | None, headers: dict) -> None:
        self._emit(
            "request",
            remote=self.client_address[0],
            method=self.command,
            path=urlsplit(self.path).path,
            token=token,
            role=role,
            channel=channel,
            headers=headers,
        )

    def _send(self, status: int, body: bytes = b"", content_type: str | None = None) -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        token, role, channel, headers = self._parse()
        self._emit_request(channel, role, token, headers)
        if channel == "page":
            self._send(200, BEACON_PAGE, "text/html; charset=utf-8")
        else:
            self._send(200, PIXEL_GIF, "image/gif")

    def do_HEAD(self) -> None:  # noqa: N802
        token, role, channel, headers = self._parse()
        self._emit_request(channel, role, token, headers)
        self._send(200)

    def do_POST(self) -> None:  # noqa: N802
        token, role, channel, headers = self._parse()
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self._emit_request(channel, role, token, headers)
            self._send(411)
            return
        try:
            length = int(raw_len)
        except ValueError:
            self._emit_request(channel, role, token, headers)
            self._send(400)
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._emit_request(channel, role, token, headers)
            self._send(413)
            return
        body = self.rfile.read(length) if length else b""

        if channel == "fp":
            # The fingerprint event is the canonical record for this hit
            # and includes the headers; skip the duplicate request event.
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {"raw": body[:512].hex()}
            self._emit(
                "fingerprint",
                remote=self.client_address[0],
                token=token,
                headers=headers,
                payload=payload,
            )
        else:
            self._emit_request(channel, role, token, headers)
        self._send(204)

    def log_message(self, format: str, *args) -> None:  # silence default stderr
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
    parser.add_argument(
        "--webhook-url",
        default=None,
        help="If set, matching events are POSTed to this URL "
        "(Slack incoming webhook, custom alerting endpoint, etc.).",
    )
    parser.add_argument(
        "--webhook-format",
        choices=("slack", "generic"),
        default="generic",
        help="slack: Slack-shaped {text: ...} message. "
        "generic: POSTs the raw event JSON. Default: generic.",
    )
    parser.add_argument(
        "--webhook-channels",
        default=None,
        help="Comma-separated channel allowlist for the webhook. "
        "Use either bare channels ('fingerprint,page,tmpl') or "
        "role-qualified ('id/ocsp'). Default: every channel except "
        "'unknown'.",
    )
    parser.add_argument(
        "--webhook-include-unknown",
        action="store_true",
        help="Forward channel=unknown events to the webhook too. Off by "
        "default; scanner traffic is noisy.",
    )
    args = parser.parse_args()

    sinks: list[EventSink] = [stdout_sink]
    if args.s3_bucket:
        sinks.append(make_s3_sink(args.s3_bucket, args.s3_prefix))
        sys.stderr.write(
            f"archiving to s3://{args.s3_bucket}/{args.s3_prefix.strip('/')}/events/...\n"
        )
    if args.webhook_url:
        channels: set[str] | None = None
        if args.webhook_channels:
            channels = {c.strip() for c in args.webhook_channels.split(",") if c.strip()}
        sinks.append(
            make_webhook_sink(
                args.webhook_url,
                args.webhook_format,
                channels,
                args.webhook_include_unknown,
            )
        )
        sys.stderr.write(
            f"webhook ({args.webhook_format}) -> {args.webhook_url}\n"
        )
    CanaryHandler.sinks = sinks

    server = ThreadingHTTPServer((args.bind, args.port), CanaryHandler)
    sys.stderr.write(f"listening on {args.bind}:{args.port}\n")

    def graceful_shutdown(signum, _frame):
        # server.shutdown() blocks until serve_forever returns and must
        # be called from a different thread.
        sys.stderr.write(f"\nsignal {signum} received; draining...\n")
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, graceful_shutdown)
    signal.signal(signal.SIGINT, graceful_shutdown)

    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
