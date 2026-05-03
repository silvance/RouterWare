#!/usr/bin/env python3
"""
Replay canary trips from the S3 archive.

Pulls every event archived for a given token (or enumerates all tokens),
sorts chronologically, and prints a human-readable timeline. Use after
a canary trip to see exactly which channels fired, who they came from,
and what the JS fingerprint captured.

Optional enrichment:
- Pass --geo-db / --asn-db to a MaxMind GeoLite2 .mmdb and each source
  IP gets annotated with city/region/country and ASN/org.
- Fingerprint events are summarised into a single human-readable line
  ("Windows 10/11 / Edge 121 / Intel UHD 630 / 8 cores / 16 GB / ...")
  alongside the full key/value detail.

Examples:
  read_events.py --bucket my-canary-archive --prefix demo --list-tokens
  read_events.py --bucket my-canary-archive --prefix demo --token <T>
  read_events.py --bucket my-canary-archive --prefix demo --token <T> --json
  read_events.py --bucket my-canary-archive --prefix demo --token <T> \\
      --geo-db ./GeoLite2-City.mmdb --asn-db ./GeoLite2-ASN.mmdb
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable


def _trunc(value: str | None, n: int = 80) -> str:
    if not value:
        return ""
    return value if len(value) <= n else value[: n - 1] + "…"


def channel_label(event: dict) -> str:
    if event.get("kind") == "fingerprint":
        return "fingerprint"
    ch = event.get("channel") or "?"
    return f"{event['role']}/{ch}" if event.get("role") else ch


# ---- Fingerprint synthesis ------------------------------------------------
# Hand-rolled UA parsing covering the cases we actually encounter. Avoids
# pulling in `ua-parser` for two functions' worth of regex.

def _parse_os(ua: str) -> str:
    if not ua:
        return "?"
    if "Windows NT 10.0" in ua:
        return "Windows 10/11"
    if "Windows NT 6.3" in ua:
        return "Windows 8.1"
    if "Windows NT 6.1" in ua:
        return "Windows 7"
    if m := re.search(r"Mac OS X (\d+)[_.](\d+)", ua):
        return f"macOS {m.group(1)}.{m.group(2)}"
    if m := re.search(r"iPhone OS (\d+)[_.](\d+)", ua):
        return f"iOS {m.group(1)}.{m.group(2)}"
    if m := re.search(r"Android (\d+)", ua):
        return f"Android {m.group(1)}"
    if "Linux" in ua:
        return "Linux"
    if "FreeBSD" in ua:
        return "FreeBSD"
    return "?"


def _parse_browser(ua: str) -> str:
    if not ua:
        return "?"
    # Order matters: Edg/ before Chrome/ (Edge UA contains both).
    if m := re.search(r"Edg/(\d+)", ua):
        return f"Edge {m.group(1)}"
    if m := re.search(r"OPR/(\d+)", ua):
        return f"Opera {m.group(1)}"
    if m := re.search(r"Firefox/(\d+)", ua):
        return f"Firefox {m.group(1)}"
    if m := re.search(r"Chrome/(\d+)", ua):
        return f"Chrome {m.group(1)}"
    if "Safari" in ua and "Chrome" not in ua:
        if m := re.search(r"Version/(\d+)", ua):
            return f"Safari {m.group(1)}"
        return "Safari"
    return "?"


def _parse_gpu(webgl: str | None) -> str | None:
    """Pull the GPU name out of a WebGL renderer string.

    Examples:
      "ANGLE (Intel UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)"
        -> "Intel UHD Graphics 630"
      "Intel Iris Pro OpenGL Engine"
        -> "Intel Iris Pro"
    """
    if not webgl:
        return None
    if m := re.match(r"ANGLE \((.+?)(?: Direct3D| OpenGL|\))", webgl):
        return m.group(1).strip()
    return webgl


def synthesize_fingerprint(payload: dict) -> str:
    """Collapse a fingerprint payload into one human-readable line."""
    parts: list[str] = []
    ua = payload.get("ua") or ""
    os_str, browser_str = _parse_os(ua), _parse_browser(ua)
    if os_str != "?" or browser_str != "?":
        parts.append(f"{os_str} / {browser_str}")
    if gpu := _parse_gpu(payload.get("webgl")):
        parts.append(gpu)
    hw_bits: list[str] = []
    if hw := payload.get("hwConcurrency"):
        hw_bits.append(f"{hw} cores")
    if mem := payload.get("deviceMemory"):
        hw_bits.append(f"{mem} GB")
    if hw_bits:
        parts.append(" / ".join(hw_bits))
    if langs := payload.get("languages"):
        parts.append(langs[0])
    if tz := payload.get("tz"):
        parts.append(tz)
    screen = payload.get("screen") or {}
    if screen.get("w") and screen.get("h"):
        parts.append(f"{screen['w']}x{screen['h']}")
    return " / ".join(parts)


# ---- Geo enrichment (optional) -------------------------------------------

GeoLookup = Callable[[str], str]


def make_geo_lookup(
    city_db: Path | None, asn_db: Path | None
) -> GeoLookup:
    """Return a function that maps an IP to a formatted geo suffix.

    Uses MaxMind GeoLite2 .mmdb files via the `maxminddb` package.
    Returns a no-op function if neither DB is provided or maxminddb
    isn't installed.
    """
    if not city_db and not asn_db:
        return lambda _ip: ""
    try:
        import maxminddb
    except ImportError:
        sys.stderr.write(
            "geo: maxminddb not installed (pip install maxminddb); "
            "skipping geo enrichment\n"
        )
        return lambda _ip: ""

    city = (
        maxminddb.open_database(str(city_db))
        if city_db and city_db.exists()
        else None
    )
    asn = (
        maxminddb.open_database(str(asn_db))
        if asn_db and asn_db.exists()
        else None
    )
    if not city and not asn:
        return lambda _ip: ""

    def lookup(ip: str) -> str:
        bits: list[str] = []
        if city:
            try:
                rec = city.get(ip) or {}
                city_name = (rec.get("city") or {}).get("names", {}).get("en")
                subs = rec.get("subdivisions") or [{}]
                region = subs[0].get("iso_code")
                country = (rec.get("country") or {}).get("iso_code")
                geo = ", ".join(b for b in [city_name, region, country] if b)
                if geo:
                    bits.append(geo)
            except (ValueError, KeyError):
                pass
        if asn:
            try:
                rec = asn.get(ip) or {}
                org = rec.get("autonomous_system_organization")
                num = rec.get("autonomous_system_number")
                if org and num:
                    bits.append(f"{org}, AS{num}")
                elif org:
                    bits.append(org)
            except (ValueError, KeyError):
                pass
        return f" ({' — '.join(bits)})" if bits else ""

    return lookup


_NULL_GEO: GeoLookup = lambda _ip: ""


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
            event = json.loads(body)
        except json.JSONDecodeError:
            sys.stderr.write(f"skip unparseable object: {key}\n")
            continue
        event["_s3_key"] = key
        events.append(event)
    events.sort(key=lambda e: e.get("ts", ""))
    return events


def render_request(event: dict, geo: GeoLookup = _NULL_GEO) -> Iterable[str]:
    headers = event.get("headers") or {}
    ua = headers.get("User-Agent", "")
    ts = (event.get("ts") or "?")[11:19]
    remote = event.get("remote") or "?"
    yield (
        f"  {ts}  [{channel_label(event):14}] "
        f"{remote:15}  {_trunc(ua, 60)}"
    )
    if geo_str := geo(remote):
        yield f"                                 geo:{geo_str}"
    accept_lang = headers.get("Accept-Language")
    if accept_lang:
        yield f"                                 accept-language: {accept_lang}"


def render_fingerprint(event: dict, geo: GeoLookup = _NULL_GEO) -> Iterable[str]:
    payload = event.get("payload") or {}
    ts = (event.get("ts") or "?")[11:19]
    remote = event.get("remote") or "?"
    yield f"  {ts}  [fingerprint   ] {remote:15}"
    if geo_str := geo(remote):
        yield f"                                 geo:{geo_str}"
    if synth := synthesize_fingerprint(payload):
        yield f"      = {synth}"
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


def print_timeline(
    token: str, events: list[dict], geo: GeoLookup = _NULL_GEO
) -> None:
    if not events:
        print(f"no events for token {token}")
        return
    counts = Counter(channel_label(e) for e in events)
    sources = Counter(e.get("remote") or "?" for e in events)
    first, last = events[0].get("ts", "?"), events[-1].get("ts", "?")
    print(f"token: {token}")
    print(f"events: {len(events)}  first={first}  last={last}")
    print("channels: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print("sources:")
    for ip, n in sources.most_common():
        print(f"  {ip:15} hits={n}{geo(ip)}")
    print()
    for e in events:
        renderer = render_fingerprint if e.get("kind") == "fingerprint" else render_request
        for line in renderer(e, geo):
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
    parser.add_argument(
        "--geo-db",
        type=Path,
        default=None,
        help="Path to MaxMind GeoLite2-City.mmdb. If supplied, source IPs "
        "are annotated with city/region/country.",
    )
    parser.add_argument(
        "--asn-db",
        type=Path,
        default=None,
        help="Path to MaxMind GeoLite2-ASN.mmdb. If supplied, source IPs "
        "are annotated with their ASN/org.",
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
    geo = make_geo_lookup(args.geo_db, args.asn_db)
    print_timeline(args.token, events, geo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
