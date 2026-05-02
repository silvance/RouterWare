#!/usr/bin/env python3
"""
Replay canary trips from the S3 archive.

Pulls every event archived for a given token (or enumerates all tokens),
sorts chronologically, and prints a human-readable timeline. Use after
a canary trip to see exactly which channels fired, who they came from,
and what the JS fingerprint captured.

Examples:
  read_events.py --bucket my-canary-archive --prefix demo --list-tokens
  read_events.py --bucket my-canary-archive --prefix demo --token Mi7zFWY3kvUZktFb
  read_events.py --bucket my-canary-archive --prefix demo --token X --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from typing import Iterable


def _trunc(value: str | None, n: int = 80) -> str:
    if not value:
        return ""
    return value if len(value) <= n else value[: n - 1] + "…"


def channel_label(event: dict) -> str:
    if event.get("kind") == "fingerprint":
        return "fingerprint"
    ch = event.get("channel") or "?"
    return f"{event['role']}/{ch}" if event.get("role") else ch


def list_tokens(client, bucket: str, prefix: str) -> list[str]:
    base = f"{prefix.strip('/')}/events/"
    seen: set[str] = set()
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=base, Delimiter="/"):
        for cp in page.get("CommonPrefixes") or []:
            token = cp["Prefix"][len(base):].rstrip("/")
            if token:
                seen.add(token)
    return sorted(seen)


def fetch_events(client, bucket: str, prefix: str, token: str) -> list[dict]:
    base = f"{prefix.strip('/')}/events/{token}/"
    keys: list[str] = []
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=base):
        for obj in page.get("Contents") or []:
            keys.append(obj["Key"])
    events: list[dict] = []
    for key in keys:
        body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
        try:
            events.append(json.loads(body))
        except json.JSONDecodeError:
            sys.stderr.write(f"skip unparseable object: {key}\n")
    events.sort(key=lambda e: e.get("ts", ""))
    return events


def render_request(event: dict) -> Iterable[str]:
    headers = event.get("headers") or {}
    ua = headers.get("User-Agent", "")
    ts = (event.get("ts") or "?")[11:19]
    yield (
        f"  {ts}  [{channel_label(event):14}] "
        f"{(event.get('remote') or '?'):15}  {_trunc(ua, 60)}"
    )
    accept_lang = headers.get("Accept-Language")
    if accept_lang:
        yield f"                                 accept-language: {accept_lang}"


def render_fingerprint(event: dict) -> Iterable[str]:
    payload = event.get("payload") or {}
    ts = (event.get("ts") or "?")[11:19]
    yield (
        f"  {ts}  [fingerprint   ] "
        f"{(event.get('remote') or '?'):15}"
    )
    screen = payload.get("screen") or {}
    rows = [
        ("ua", _trunc(payload.get("ua"))),
        ("platform", payload.get("platform")),
        ("languages", ", ".join(payload.get("languages") or [])),
        ("timezone", payload.get("tz")),
        (
            "screen",
            (
                f"{screen.get('w')}x{screen.get('h')}"
                f"@{screen.get('d')} dpr={screen.get('dpr')}"
            )
            if screen
            else None,
        ),
        ("hw concurrency", payload.get("hwConcurrency")),
        ("device memory", payload.get("deviceMemory")),
        ("plugins", ", ".join(payload.get("plugins") or [])),
        ("webgl", payload.get("webgl")),
        ("canvas", payload.get("canvas")),
        ("referrer", payload.get("referrer")),
    ]
    for k, v in rows:
        if v in (None, "", []):
            continue
        yield f"      {k:18} {v}"


def print_timeline(token: str, events: list[dict]) -> None:
    if not events:
        print(f"no events for token {token}")
        return
    counts = Counter(channel_label(e) for e in events)
    first, last = events[0].get("ts", "?"), events[-1].get("ts", "?")
    print(f"token: {token}")
    print(f"events: {len(events)}  first={first}  last={last}")
    print("channels: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print()
    for e in events:
        renderer = render_fingerprint if e.get("kind") == "fingerprint" else render_request
        for line in renderer(e):
            print(line)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--prefix", default="canary")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", help="Replay every hit recorded for this token")
    group.add_argument(
        "--list-tokens",
        action="store_true",
        help="Enumerate every token that has at least one event in the bucket",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw NDJSON (sorted by ts) instead of the pretty timeline",
    )
    args = parser.parse_args()

    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is required. Run: pip install boto3")
    client = boto3.client("s3")

    if args.list_tokens:
        for token in list_tokens(client, args.bucket, args.prefix):
            print(token)
        return 0

    events = fetch_events(client, args.bucket, args.prefix, args.token)
    if args.json:
        for event in events:
            sys.stdout.write(json.dumps(event, default=str) + "\n")
        return 0
    print_timeline(args.token, events)
    return 0


if __name__ == "__main__":
    sys.exit(main())
