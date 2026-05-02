#!/usr/bin/env python3
"""Standalone DOCX template beacon.

Writes a Word document whose `attachedTemplate` relationship points at
your canary listener. Word fetches the URL when the document is opened.

Useful as a honeyfile on its own when you want a beacon without the
full CAC backup folder -- e.g. plant a `Q3 Strategy.docx` on a
shared drive with `--text "Q3 Strategy ..."`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from beacons import (
    DEFAULT_DOCX_FILENAME,
    beacon_url,
    random_token,
    validate_beacon_url,
    write_docx_beacon,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--beacon-url",
        required=True,
        help="Base URL of your canary listener, e.g. https://pki-status.lab.example",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(f"./{DEFAULT_DOCX_FILENAME}"),
        help=f"Output path. Default: ./{DEFAULT_DOCX_FILENAME}",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Override the per-deployment token (random if omitted).",
    )
    parser.add_argument(
        "--text",
        default=None,
        help="Custom body text (one paragraph per line). Default: a CAC PIN "
        "reset procedure. Override when planting outside a CAC context.",
    )
    parser.add_argument(
        "--allow-public-callback",
        action="store_true",
        help="Permit --beacon-url to point at a public OOB/canary service.",
    )
    args = parser.parse_args()

    try:
        validate_beacon_url(args.beacon_url, args.allow_public_callback)
    except ValueError as exc:
        parser.error(str(exc))

    token = args.token or random_token()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_docx_beacon(args.output, args.beacon_url, token, body_text=args.text)

    print(f"wrote   {args.output}")
    print(f"token:  {token}")
    print(f"beacon: {beacon_url(args.beacon_url, token, 'template.dotx')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
