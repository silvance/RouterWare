#!/usr/bin/env python3
"""
CAC-style canary token generator.

Produces a deception artifact shaped like a U.S. DoD Common Access Card
backup folder, as if a careless user exported their CAC keys with
ActivClient and dropped the result on a fileshare. The folder contains:

  - <last>_<edipi>_id.pfx   PIV/Identity cert + key  (smartcardLogon)
  - <last>_<edipi>_sig.pfx  Digital Signature cert + key (S/MIME)
  - <last>_<edipi>_enc.pfx  Encryption cert + key (S/MIME key mgmt)
  - <last>_<edipi>_*.cer    Public certs in PEM
  - DoD_CA_Bundle.pem       Synthetic intermediate + root with DoD-shape DNs
  - pin.txt                 The 6-digit PIN, in plaintext
  - Important - CAC Reset Instructions.url   Honeyfolder fire-on-browse
  - How to import this CAC.html              Honeyfolder JS fingerprint

Every cert and companion file embeds path-encoded beacon URLs of the
shape https://<host>/v/<token>/<role>/<filename>. The listener routes
on the path, infers the channel from the filename suffix, and tags
per-cert beacons with the role (id/sig/enc) so you can tell which key
the operator tried to use.

Self-signed leaves: the leaves are NOT cryptographically chained to
the bundled CA certs. The bundle is for visual completeness during a
quick peek -- a deeper offline cryptographic verify still fails. By
design (#4 in the deception roadmap is intentionally skipped to keep
the artifact harmless against real DoD services).

Authorized internal deception, blue-team training, and red-team
engagement use only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PUBLIC_CANARY_HOSTS = frozenset(
    {
        "canarytokens.com",
        "canarytokens.org",
        "interact.sh",
        "oast.fun",
        "oast.live",
        "oast.pro",
        "oast.me",
        "oast.online",
        "oast.site",
        "oastify.com",
        "requestbin.com",
        "requestbin.net",
        "requestcatcher.com",
        "webhook.site",
        "pipedream.com",
        "beeceptor.com",
        "burpcollaborator.net",
    }
)


INTERMEDIATE_CN = "DOD ID CA-59"
ROOT_CN = "DoD Root CA 3"
DOD_POLICY_OID = "2.16.840.1.101.2.1.11.39"


def _ku(**kw) -> x509.KeyUsage:
    defaults = dict(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    return x509.KeyUsage(**{**defaults, **kw})


# Per-role properties for the three CAC certs. The id cert also gets a
# UPN otherName SAN (handled separately in build_leaf_cert).
ROLES: dict[str, dict] = {
    "id": {
        "friendly": "Identity",
        "eku": [
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SMARTCARD_LOGON,
        ],
        "ku": _ku(digital_signature=True),
    },
    "sig": {
        "friendly": "Signature",
        "eku": [ExtendedKeyUsageOID.EMAIL_PROTECTION],
        "ku": _ku(digital_signature=True, content_commitment=True),
    },
    "enc": {
        "friendly": "Encryption",
        "eku": [ExtendedKeyUsageOID.EMAIL_PROTECTION],
        "ku": _ku(key_encipherment=True),
    },
}


def random_edipi() -> str:
    return str(secrets.randbelow(9) + 1) + "".join(
        str(secrets.randbelow(10)) for _ in range(9)
    )


def random_pin() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(6))


def validate_beacon_url(url: str, allow_public: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"--beacon-url must be http(s); got {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError("--beacon-url must include a hostname")
    if allow_public:
        return
    host = parts.hostname.lower()
    for blocked in PUBLIC_CANARY_HOSTS:
        if host == blocked or host.endswith("." + blocked):
            raise ValueError(
                f"--beacon-url points at the public service {blocked!r}; "
                "use a host you control, or pass --allow-public-callback "
                "if you really mean it."
            )


def beacon_url(base: str, token: str, *segments: str) -> str:
    base = base.rstrip("/")
    suffix = "/".join(segments)
    return f"{base}/v/{token}/{suffix}"


def build_subject(last: str, first: str, middle: str, edipi: str) -> x509.Name:
    cn = f"{last.upper()}.{first.upper()}.{middle.upper()}.{edipi}"
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "CONTRACTOR"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def build_intermediate_dn() -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, INTERMEDIATE_CN),
        ]
    )


def build_root_dn() -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CN),
        ]
    )


def _encode_utf8_string(value: str) -> bytes:
    body = value.encode("utf-8")
    if len(body) >= 0x80:
        raise ValueError("UPN too long for short-form DER length")
    return bytes([0x0C, len(body)]) + body


def build_leaf_cert(
    *,
    role: str,
    subject: x509.Name,
    issuer_dn: x509.Name,
    leaf_pubkey,
    signing_key,
    edipi: str,
    upn: str,
    beacon_base: str,
    token: str,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> x509.Certificate:
    serial = int.from_bytes(secrets.token_bytes(16), "big") >> 1

    san_entries = [x509.RFC822Name(f"{edipi}@mail.mil")]
    if role == "id":
        san_entries.insert(
            0,
            x509.OtherName(
                type_id=x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                value=_encode_utf8_string(upn),
            ),
        )

    aia = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                access_method=x509.OID_OCSP,
                access_location=x509.UniformResourceIdentifier(
                    beacon_url(beacon_base, token, role, "ocsp")
                ),
            ),
            x509.AccessDescription(
                access_method=x509.OID_CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier(
                    beacon_url(beacon_base, token, role, "DODIDCA-59_IT.p7c")
                ),
            ),
        ]
    )
    cdp = x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[
                    x509.UniformResourceIdentifier(
                        beacon_url(beacon_base, token, role, "DODIDCA59.crl")
                    )
                ],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )
    cert_policies = x509.CertificatePolicies(
        [
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier(DOD_POLICY_OID),
                policy_qualifiers=None,
            )
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_dn)
        .public_key(leaf_pubkey)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ROLES[role]["ku"], critical=True)
        .add_extension(x509.ExtendedKeyUsage(ROLES[role]["eku"]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(aia, critical=False)
        .add_extension(cdp, critical=False)
        .add_extension(cert_policies, critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_pubkey), critical=False
        )
    )
    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def build_synthetic_ca(
    *,
    subject_dn: x509.Name,
    issuer_dn: x509.Name,
    public_key,
    signing_key,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> x509.Certificate:
    serial = int.from_bytes(secrets.token_bytes(16), "big") >> 1
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_dn)
        .issuer_name(issuer_dn)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(_ku(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
    )
    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def jitter_mtime(path: Path, target: dt.datetime, jitter_minutes: int = 120) -> None:
    offset = secrets.randbelow(jitter_minutes * 60 * 2) - (jitter_minutes * 60)
    ts = (target + dt.timedelta(seconds=offset)).timestamp()
    os.utime(path, (ts, ts))


def write_honeyfolder(
    out_dir: Path, beacon_base: str, token: str
) -> list[Path]:
    url_path = out_dir / "Important - CAC Reset Instructions.url"
    html_path = out_dir / "How to import this CAC.html"

    icon_url = beacon_url(beacon_base, token, "icon.ico")
    click_url = beacon_url(beacon_base, token, "help")
    pixel_url = beacon_url(beacon_base, token, "p.gif")
    page_url = beacon_url(beacon_base, token, "page")

    url_path.write_text(
        "[InternetShortcut]\r\n"
        f"URL={click_url}\r\n"
        f"IconFile={icon_url}\r\n"
        "IconIndex=0\r\n",
        encoding="utf-8",
    )
    html_path.write_text(
        "<!doctype html>\n"
        "<html><head><meta charset=\"utf-8\">\n"
        "<title>How to import your CAC backup</title></head>\n"
        "<body style=\"font-family:sans-serif;max-width:640px;margin:2em auto\">\n"
        "<h1>CAC Backup Import</h1>\n"
        "<p>Double-click the <code>.pfx</code> file in this folder and enter "
        "the PIN you were issued. If you do not have your PIN, contact your "
        "RA.</p>\n"
        f"<img src=\"{pixel_url}\" width=\"1\" height=\"1\" alt=\"\" "
        "style=\"position:absolute;left:-9999px\">\n"
        f"<iframe src=\"{page_url}\" width=\"1\" height=\"1\" "
        "style=\"position:absolute;left:-9999px;border:0\"></iframe>\n"
        "</body></html>\n",
        encoding="utf-8",
    )
    return [url_path, html_path]


def build_ca_chain(
    base_date: dt.datetime,
) -> tuple[x509.Certificate, x509.Certificate]:
    """Synthetic root + intermediate with DoD-shape DNs.

    Root self-signs and is valid ~20 years (real DoD roots span similar).
    Intermediate is signed by root, valid ~10 years. Leaves are NOT
    signed by the intermediate (would-be #4 on the deception roadmap),
    so the chain validates internally but no leaf chains to it.
    """
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    root_dn = build_root_dn()
    root_cert = build_synthetic_ca(
        subject_dn=root_dn,
        issuer_dn=root_dn,
        public_key=root_key.public_key(),
        signing_key=root_key,
        not_before=base_date - dt.timedelta(days=10 * 365),
        not_after=base_date + dt.timedelta(days=10 * 365),
    )
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_cert = build_synthetic_ca(
        subject_dn=build_intermediate_dn(),
        issuer_dn=root_dn,
        public_key=inter_key.public_key(),
        signing_key=root_key,
        not_before=base_date - dt.timedelta(days=5 * 365),
        not_after=base_date + dt.timedelta(days=5 * 365),
    )
    return root_cert, inter_cert


def write_role_pfx(
    *,
    role: str,
    out_dir: Path,
    surname_lower: str,
    edipi: str,
    last: str,
    first: str,
    upn: str,
    subject: x509.Name,
    inter_cert: x509.Certificate,
    root_cert: x509.Certificate,
    beacon_base: str,
    token: str,
    pin: str,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> tuple[Path, Path]:
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = build_leaf_cert(
        role=role,
        subject=subject,
        issuer_dn=inter_cert.subject,
        leaf_pubkey=leaf_key.public_key(),
        signing_key=leaf_key,
        edipi=edipi,
        upn=upn,
        beacon_base=beacon_base,
        token=token,
        not_before=not_before,
        not_after=not_after,
    )
    cer_path = out_dir / f"{surname_lower}_{edipi}_{role}.cer"
    pfx_path = out_dir / f"{surname_lower}_{edipi}_{role}.pfx"
    cer_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    pfx_path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=f"CAC {ROLES[role]['friendly']} - {last.upper()}.{first.upper()}".encode(),
            key=leaf_key,
            cert=leaf_cert,
            cas=[inter_cert, root_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(pin.encode()),
        )
    )
    return cer_path, pfx_path


def apply_mtimes(
    out_dir: Path,
    pki_files: list[Path],
    pin_path: Path,
    companion_paths: list[Path],
    base_date: dt.datetime,
) -> None:
    """Cluster PKI mtimes near base_date; pin.txt slightly later
    (added a few days after the export); companions later still."""
    for path in pki_files:
        jitter_mtime(path, base_date)
    jitter_mtime(pin_path, base_date + dt.timedelta(days=1 + secrets.randbelow(30)))
    for path in companion_paths:
        jitter_mtime(path, base_date + dt.timedelta(days=1 + secrets.randbelow(60)))
    jitter_mtime(out_dir, base_date + dt.timedelta(days=60))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--beacon-url",
        required=True,
        help="Base URL of your canary listener (no path), e.g. "
        "https://pki-status.lab.example",
    )
    parser.add_argument("--last", default="DOE")
    parser.add_argument("--first", default="JOHN")
    parser.add_argument("--middle", default="Q")
    parser.add_argument(
        "--edipi", default=None, help="10-digit EDIPI; random if omitted"
    )
    parser.add_argument(
        "--upn", default=None, help="UPN for SAN; defaults to <edipi>@mil"
    )
    parser.add_argument(
        "--pin",
        default=None,
        help="6-8 digit PIN to wrap the .pfx files. Random 6-digit if omitted. "
        "Also written to pin.txt for the operator to find.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("./CAC Backup"),
        help="The folder to plant. Default: './CAC Backup'.",
    )
    parser.add_argument(
        "--validity-days",
        type=int,
        default=1095,
        help="CAC certs are typically issued for 3 years",
    )
    parser.add_argument(
        "--no-companions",
        action="store_true",
        help="Skip the .url + HTML honeyfolder companions. Without these, "
        "only the cert validation beacons fire.",
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

    edipi = args.edipi or random_edipi()
    if len(edipi) != 10 or not edipi.isdigit():
        parser.error("EDIPI must be exactly 10 digits")
    pin = args.pin or random_pin()
    if not (pin.isdigit() and 6 <= len(pin) <= 8):
        parser.error("--pin must be 6-8 digits")
    upn = args.upn or f"{edipi}@mil"
    token = secrets.token_urlsafe(12)

    # Pretend the user exported their CAC 3-9 months ago. All file
    # mtimes will cluster around base_date with light jitter; the PIN
    # sticky-note and the companions land slightly later, like a user
    # who came back to add notes after the export session.
    days_back = 90 + secrets.randbelow(180)
    base_date = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_back)
    not_before = base_date
    not_after = base_date + dt.timedelta(days=args.validity_days)

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    root_cert, inter_cert = build_ca_chain(base_date)
    subject = build_subject(args.last, args.first, args.middle, edipi)
    surname_lower = args.last.lower()

    pki_files: list[Path] = []
    for role in ROLES:
        cer, pfx = write_role_pfx(
            role=role,
            out_dir=out_dir,
            surname_lower=surname_lower,
            edipi=edipi,
            last=args.last,
            first=args.first,
            upn=upn,
            subject=subject,
            inter_cert=inter_cert,
            root_cert=root_cert,
            beacon_base=args.beacon_url,
            token=token,
            pin=pin,
            not_before=not_before,
            not_after=not_after,
        )
        pki_files.extend([cer, pfx])

    bundle_path = out_dir / "DoD_CA_Bundle.pem"
    bundle_path.write_bytes(
        inter_cert.public_bytes(serialization.Encoding.PEM)
        + root_cert.public_bytes(serialization.Encoding.PEM)
    )
    pki_files.append(bundle_path)

    pin_path = out_dir / "pin.txt"
    pin_path.write_text(f"PIN: {pin}\n", encoding="utf-8")

    companion_paths: list[Path] = []
    if not args.no_companions:
        companion_paths = write_honeyfolder(out_dir, args.beacon_url, token)

    # Manifest stays OUTSIDE the planted folder -- the operator must never see it.
    manifest_path = out_dir.parent / f".{out_dir.name}.token.txt"
    cn = f"{args.last.upper()}.{args.first.upper()}.{args.middle.upper()}.{edipi}"
    manifest_path.write_text(
        f"token={token}\n"
        f"edipi={edipi}\n"
        f"upn={upn}\n"
        f"cn={cn}\n"
        f"pin={pin}\n"
        f"beacon_base={args.beacon_url}\n"
        f"out_dir={out_dir}\n"
        f"base_date={base_date.isoformat()}\n",
        encoding="utf-8",
    )

    apply_mtimes(out_dir, pki_files, pin_path, companion_paths, base_date)

    for path in sorted(out_dir.iterdir()):
        print(f"wrote {path}")
    print()
    print(f"manifest: {manifest_path}")
    print(f"token:    {token}")
    print(f"PIN:      {pin}")
    print(f"plant the folder: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
