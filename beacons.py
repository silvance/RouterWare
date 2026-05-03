"""Shared helpers + beacon-file writers for the RouterWare toolkit.

Reused by:
  - generate_cac_canary.py   (full CAC backup folder bundle)
  - generate_docx_beacon.py  (standalone DOCX template beacon)
  - generate_pdf_beacon.py   (standalone PDF /OpenAction beacon)
"""

from __future__ import annotations

import secrets
import zipfile
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape


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


DEFAULT_DOCX_FILENAME = "CAC Reset Procedure.docx"
DEFAULT_PDF_FILENAME = "PIN Reset Instructions.pdf"
DEFAULT_BODY_TEXT = (
    "CAC PIN Reset Procedure\n"
    "1. Insert your CAC into the reader.\n"
    "2. Launch ActivClient User Console.\n"
    "3. Select Change PIN from the Tools menu.\n"
    "4. Enter your old PIN, then your new PIN twice.\n"
)


def random_token() -> str:
    return secrets.token_urlsafe(12)


def validate_beacon_url(url: str, allow_public: bool) -> None:
    """Raise ValueError if url is malformed or points at a public OOB service.

    Also rejects URLs that include a path/query/fragment because we
    append `/v/<token>/...` to the base, and a non-empty path or
    query string in the user input would produce malformed cert
    extension URLs (e.g. `https://h/x?y=z/v/abc/ocsp`).
    """
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"--beacon-url must be http(s); got {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError("--beacon-url must include a hostname")
    if parts.path and parts.path != "/":
        raise ValueError(
            f"--beacon-url must not include a path; got {parts.path!r}. "
            "The toolkit appends /v/<token>/... internally."
        )
    if parts.query:
        raise ValueError("--beacon-url must not include a query string")
    if parts.fragment:
        raise ValueError("--beacon-url must not include a fragment")
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
    """Path-encoded beacon URL: <base>/v/<token>/<segments...>"""
    return f"{base.rstrip('/')}/v/{token}/{'/'.join(segments)}"


def write_docx_beacon(
    out_path: Path,
    beacon_base: str,
    token: str,
    body_text: str | None = None,
) -> Path:
    """Write a DOCX whose attachedTemplate points at the listener.

    Word fetches the template URL when the document is opened. Modern
    Office may show a security warning before fetching; many users
    click through. Even a blocked fetch attempt can be useful signal.
    """
    if body_text is None:
        body_text = DEFAULT_BODY_TEXT
    tmpl_url = beacon_url(beacon_base, token, "template.dotx")
    body_xml = "".join(
        f"<w:p><w:r><w:t>{escape(line)}</w:t></w:r></w:p>"
        for line in body_text.splitlines()
        if line.strip()
    )
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
            "</Types>"
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>"
        ),
        "word/_rels/document.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'
            "</Relationships>"
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body>" + body_xml + "</w:body>"
            "</w:document>"
        ),
        "word/settings.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<w:attachedTemplate r:id="rId1"/>'
            "</w:settings>"
        ),
        "word/_rels/settings.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="{tmpl_url}" TargetMode="External"/>'
            "</Relationships>"
        ),
    }
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in parts.items():
            zf.writestr(name, content)
    return out_path


def _pdf_string(value: str) -> bytes:
    body = value.encode("utf-8")
    body = body.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    return b"(" + body + b")"


def write_pdf_beacon(
    out_path: Path,
    beacon_base: str,
    token: str,
    body_text: str | None = None,
) -> Path:
    """Minimal PDF with /OpenAction /URI pointing at the listener.

    Modern Acrobat Reader prompts before fetching external URLs; some
    third-party PDF viewers and older Reader versions fetch silently.
    Even a prompt is partial signal at the network layer (DNS resolves
    on prompt in some clients) and many users click through.
    """
    if body_text is None:
        body_text = DEFAULT_BODY_TEXT
    open_url = beacon_url(beacon_base, token, "pdf-open")

    lines = [line for line in body_text.splitlines() if line.strip()]
    if not lines:
        lines = ["Document"]
    title, body = lines[0], lines[1:]

    stream_chunks = [
        b"BT /F1 16 Tf 72 720 Td " + _pdf_string(title) + b" Tj ET\n",
    ]
    y = 690
    for line in body:
        stream_chunks.append(
            f"BT /F1 11 Tf 72 {y} Td ".encode()
            + _pdf_string(line)
            + b" Tj ET\n"
        )
        y -= 18
    stream = b"".join(stream_chunks)

    objects = [
        (
            b"<< /Type /Catalog /Pages 2 0 R "
            b"/OpenAction << /Type /Action /S /URI /URI "
            + _pdf_string(open_url)
            + b" >> >>"
        ),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        (
            b"<< /Length "
            + str(len(stream)).encode()
            + b" >>\nstream\n"
            + stream
            + b"endstream"
        ),
    ]

    out = bytearray(b"%PDF-1.4\n%\xc4\xe5\xf2\xe5\xeb\xa7\xf3\xa0\xd0\xc4\xc6\n")
    offsets = [0]
    for i, body_obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body_obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += b"trailer\n"
    out += f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
    out += f"startxref\n{xref}\n%%EOF\n".encode()
    out_path.write_bytes(bytes(out))
    return out_path
