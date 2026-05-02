#!/usr/bin/env python3
"""
CAC-style canary token generator.

Produces a self-signed X.509 credential whose Subject DN, SAN UPN, and
extensions mimic the shape of a U.S. DoD Common Access Card identity
certificate. The certificate is *not* chained to any real DoD CA -- it is
a deception artifact intended to be planted in monitored locations
(workstation cert stores, file shares, repos, screenshots, etc.) so that
any party that tries to validate, parse, or use it triggers a beacon
back to a listener you control.

Beacon channels embedded in the certificate:
  * Authority Information Access -> caIssuers URI       (cert-chain fetch)
  * Authority Information Access -> OCSP responder URI  (revocation check)
  * CRL Distribution Points URI                         (revocation check)
  * Subject Alternative Name URI                        (some parsers fetch)

Each URI carries a unique token so the listener can attribute the trip
to a specific deployed credential.

Intended for blue-team training, honeypot/honeyfile programs, and
authorized internal deception engagements only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# Hosts that are well-known public out-of-band / canary-hosting services.
# Refusing them by default prevents a trainee from accidentally pointing
# their demo at someone else's listener.
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


# CAC identity certs use the DoD PKI naming convention:
#   CN = LAST.FIRST.MIDDLE.EDIPI
# where EDIPI is the 10-digit DoD ID number. The OU stack identifies the
# issuing service. We mirror the shape but fill in synthetic values.
DEFAULT_OU_STACK = ["PKI", "DoD", "U.S. Government"]


def random_edipi() -> str:
    # EDIPIs are 10 digits, first digit non-zero.
    return str(secrets.randbelow(9) + 1) + "".join(
        str(secrets.randbelow(10)) for _ in range(9)
    )


def build_subject(
    last: str,
    first: str,
    middle: str,
    edipi: str,
    ou_stack: list[str],
) -> x509.Name:
    cn = f"{last.upper()}.{first.upper()}.{middle.upper()}.{edipi}"
    rdns: list[x509.NameAttribute] = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ou_stack[-1]),
    ]
    for ou in ou_stack[:-1]:
        rdns.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    rdns.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "CONTRACTOR"))
    rdns.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(rdns)


def build_issuer() -> x509.Name:
    # Mimics a DoD ID intermediate CA name. Self-signed, so this is the
    # same as the cert's own issuer field.
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DOD ID CA-DECOY"),
        ]
    )


def beacon_uri(base: str, token: str, channel: str) -> str:
    sep = "&" if "?" in base else "?"
    return f"{base.rstrip('/')}{sep}t={token}&c={channel}"


def build_certificate(
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    signing_key,
    edipi: str,
    upn: str,
    beacon_base: str,
    token: str,
    not_after: dt.datetime,
) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    serial = int.from_bytes(secrets.token_bytes(16), "big") >> 1

    # SAN: the UPN is what Windows logon and DoD apps key off of. We also
    # stash a beacon URI here -- some certificate parsers chase URI SANs.
    san = x509.SubjectAlternativeName(
        [
            x509.OtherName(
                # 1.3.6.1.4.1.311.20.2.3 = Microsoft UPN
                type_id=x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                value=_encode_utf8_string(upn),
            ),
            x509.RFC822Name(f"{edipi}@mail.mil"),
            x509.UniformResourceIdentifier(
                beacon_uri(beacon_base, token, "san")
            ),
        ]
    )

    aia = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                access_method=x509.OID_OCSP,
                access_location=x509.UniformResourceIdentifier(
                    beacon_uri(beacon_base, token, "ocsp")
                ),
            ),
            x509.AccessDescription(
                access_method=x509.OID_CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier(
                    beacon_uri(beacon_base, token, "aia")
                ),
            ),
        ]
    )

    cdp = x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[
                    x509.UniformResourceIdentifier(
                        beacon_uri(beacon_base, token, "crl")
                    )
                ],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )

    eku = x509.ExtendedKeyUsage(
        [
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ExtendedKeyUsageOID.SMARTCARD_LOGON,
        ]
    )

    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    # DoD certificate policy OID (real, harmless to include) lets the cert
    # look right to anyone who inspects policies.
    cert_policies = x509.CertificatePolicies(
        [
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier("2.16.840.1.101.2.1.11.39"),
                policy_qualifiers=None,
            )
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(eku, critical=False)
        .add_extension(san, critical=False)
        .add_extension(aia, critical=False)
        .add_extension(cdp, critical=False)
        .add_extension(cert_policies, critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
    )

    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def _encode_utf8_string(value: str) -> bytes:
    # Microsoft UPN otherName values are wrapped in a UTF8String. We hand-roll
    # the DER (tag 0x0C) so we don't need an ASN.1 library just for this.
    body = value.encode("utf-8")
    if len(body) >= 0x80:
        raise ValueError("UPN too long for short-form DER length")
    return bytes([0x0C, len(body)]) + body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--beacon-url",
        required=True,
        help="Base HTTPS URL of your canary listener, e.g. https://canary.example.org/cb",
    )
    parser.add_argument("--last", default="DOE")
    parser.add_argument("--first", default="JOHN")
    parser.add_argument("--middle", default="Q")
    parser.add_argument(
        "--edipi",
        default=None,
        help="10-digit EDIPI; random if omitted",
    )
    parser.add_argument(
        "--upn",
        default=None,
        help="UPN for SAN; defaults to <edipi>@mil",
    )
    parser.add_argument(
        "--p12-password",
        default="password",
        help="Password to wrap the PKCS#12 with (CACs prompt for a PIN; "
        "make this look plausible to the finder).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("./canary-out"),
        help="Where to drop the generated files",
    )
    parser.add_argument(
        "--validity-days",
        type=int,
        default=1095,  # CAC certs are typically issued for 3 years
    )
    parser.add_argument(
        "--honeyfolder",
        action="store_true",
        help="Also drop companion files (.url shortcut + HTML 'instructions') "
        "next to the .pfx so the credential fires-on-browse and "
        "fingerprints the viewer's browser/OS.",
    )
    parser.add_argument(
        "--allow-public-callback",
        action="store_true",
        help="Permit --beacon-url to point at a public OOB/canary service "
        "(canarytokens.org, webhook.site, interact.sh, etc.). Off by default "
        "so a trainee doesn't accidentally exfiltrate to a third party.",
    )
    args = parser.parse_args()

    try:
        validate_beacon_url(args.beacon_url, args.allow_public_callback)
    except ValueError as exc:
        parser.error(str(exc))

    edipi = args.edipi or random_edipi()
    if len(edipi) != 10 or not edipi.isdigit():
        parser.error("EDIPI must be exactly 10 digits")
    upn = args.upn or f"{edipi}@mil"
    token = secrets.token_urlsafe(12)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = build_subject(args.last, args.first, args.middle, edipi, DEFAULT_OU_STACK)
    issuer = build_issuer()

    not_after = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=args.validity_days)
    cert = build_certificate(
        subject=subject,
        issuer=issuer,
        public_key=private_key.public_key(),
        signing_key=private_key,
        edipi=edipi,
        upn=upn,
        beacon_base=args.beacon_url,
        token=token,
        not_after=not_after,
    )

    stem = f"cac-canary-{edipi}"
    cert_path = args.out_dir / f"{stem}.pem"
    key_path = args.out_dir / f"{stem}.key"
    p12_path = args.out_dir / f"{stem}.pfx"
    manifest_path = args.out_dir / f"{stem}.token.txt"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=f"CAC ID - {args.last.upper()}.{args.first.upper()}".encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            args.p12_password.encode()
        ),
    )
    p12_path.write_bytes(p12_bytes)
    manifest_path.write_text(
        "token={token}\nedipi={edipi}\nupn={upn}\ncn={cn}\nbeacon_base={beacon}\n".format(
            token=token,
            edipi=edipi,
            upn=upn,
            cn=f"{args.last.upper()}.{args.first.upper()}.{args.middle.upper()}.{edipi}",
            beacon=args.beacon_url,
        )
    )

    print(f"wrote {cert_path}")
    print(f"wrote {key_path}")
    print(f"wrote {p12_path}  (password: {args.p12_password})")
    print(f"wrote {manifest_path}")

    if args.honeyfolder:
        for path in write_honeyfolder(args.out_dir, args.beacon_url, token):
            print(f"wrote {path}")

    print(f"token: {token}")
    return 0


def write_honeyfolder(out_dir: Path, beacon_base: str, token: str) -> list[Path]:
    """Drop companion artifacts that fire-on-browse and fingerprint the viewer.

    - `Important - CAC Reset Instructions.url`
        Windows Internet Shortcut. The `IconFile=` URL is fetched by
        Explorer when the folder is *listed*, no clicks needed -- icon
        rendering is the detonator. URL= fires on double-click.

    - `How to import this CAC.html`
        Browser-rendered helper that pulls a 1x1 tracking pixel
        (channel=img) and embeds an iframe to /page (channel=fp), which
        runs the JS fingerprint script in the listener.
    """
    url_path = out_dir / "Important - CAC Reset Instructions.url"
    html_path = out_dir / "How to import this CAC.html"

    icon_url = beacon_uri(beacon_base, token, "icon")
    click_url = beacon_uri(beacon_base, token, "urlclick")
    pixel_url = beacon_uri(beacon_base, token, "img")
    page_url = beacon_uri(beacon_base.rsplit("/", 1)[0] + "/page", token, "fp")

    url_body = (
        "[InternetShortcut]\r\n"
        f"URL={click_url}\r\n"
        f"IconFile={icon_url}\r\n"
        "IconIndex=0\r\n"
    )
    url_path.write_text(url_body, encoding="utf-8")

    html_body = (
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
        "</body></html>\n"
    )
    html_path.write_text(html_body, encoding="utf-8")

    return [url_path, html_path]


if __name__ == "__main__":
    sys.exit(main())
