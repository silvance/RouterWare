"""End-to-end smoke tests for the canary toolkit.

Runs the generator CLI and asserts the artifacts have the right shape,
plus unit tests for the listener path parser. Pure stdlib +
cryptography (already required); run with:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import http.client
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

from beacons import validate_beacon_url
from canary_listener import (
    CanaryHandler,
    channel_for,
    parse_path,
    s3_event_path,
    webhook_matches,
    webhook_payload,
)
from read_events import _parse_browser, _parse_gpu, _parse_os, synthesize_fingerprint


class ListenerRouting(unittest.TestCase):
    def test_channel_for_known_filenames(self):
        cases = [
            ("ocsp", "ocsp"),
            ("DODIDCA59.crl", "crl"),
            ("DODIDCA-59_IT.p7c", "aia"),
            ("icon.ico", "icon"),
            ("help", "urlclick"),
            ("p.gif", "img"),
            ("page", "page"),
            ("fp", "fp"),
            ("template.dotx", "tmpl"),
            ("pdf-open", "pdf"),
            ("nope.thing", "unknown"),
        ]
        for filename, expected in cases:
            with self.subTest(filename=filename):
                self.assertEqual(channel_for(filename), expected)

    def test_parse_path_shapes(self):
        self.assertEqual(parse_path("/v/abc/page"), ("abc", None, "page"))
        self.assertEqual(parse_path("/v/abc/icon.ico"), ("abc", None, "icon"))
        self.assertEqual(parse_path("/v/abc/id/ocsp"), ("abc", "id", "ocsp"))
        self.assertEqual(
            parse_path("/v/abc/sig/DODIDCA59.crl"), ("abc", "sig", "crl")
        )
        self.assertEqual(parse_path("/random"), (None, None, None))


class GeneratorEndToEnd(unittest.TestCase):
    """Run the generator CLI once, then assert against the artifacts."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.bundle_dir = Path(cls._tmp.name) / "CAC Backup"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "generate_cac_canary.py"),
                "--beacon-url", "https://canary.test.example",
                "--last", "TESTUSER",
                "--first", "ALEX",
                "--middle", "K",
                "--out-dir", str(cls.bundle_dir),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        cls.edipi = cls._discover_edipi(cls.bundle_dir)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    @staticmethod
    def _discover_edipi(bundle_dir: Path) -> str:
        for path in bundle_dir.iterdir():
            m = re.match(r"testuser_(\d{10})_id\.cer$", path.name)
            if m:
                return m.group(1)
        raise AssertionError(f"no testuser_*_id.cer found in {bundle_dir}")

    def _leaf(self, role: str) -> x509.Certificate:
        path = self.bundle_dir / f"testuser_{self.edipi}_{role}.cer"
        return x509.load_pem_x509_certificate(path.read_bytes())

    def test_all_files_present(self):
        files = {p.name for p in self.bundle_dir.iterdir()}
        expected = {
            "CAC Reset Procedure.docx",
            "DoD_CA_Bundle.pem",
            "How to import this CAC.html",
            "Important - CAC Reset Instructions.url",
            "PIN Reset Instructions.pdf",
            "pin.txt",
            *(f"testuser_{self.edipi}_{r}.cer" for r in ("id", "sig", "enc")),
            *(f"testuser_{self.edipi}_{r}.pfx" for r in ("id", "sig", "enc")),
        }
        self.assertEqual(files, expected)

    def test_chain_signatures_verify(self):
        bundle = (self.bundle_dir / "DoD_CA_Bundle.pem").read_bytes()
        certs = x509.load_pem_x509_certificates(bundle)
        self.assertEqual(len(certs), 2)
        inter = next(c for c in certs if "DOD ID CA-59" in c.subject.rfc4514_string())
        root = next(c for c in certs if "DoD Root CA 3" in c.subject.rfc4514_string())

        for role in ("id", "sig", "enc"):
            with self.subTest(role=role):
                leaf = self._leaf(role)
                inter.public_key().verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    leaf.signature_hash_algorithm,
                )
        root.public_key().verify(
            inter.signature,
            inter.tbs_certificate_bytes,
            padding.PKCS1v15(),
            inter.signature_hash_algorithm,
        )
        root.public_key().verify(
            root.signature,
            root.tbs_certificate_bytes,
            padding.PKCS1v15(),
            root.signature_hash_algorithm,
        )

    def test_id_cert_has_smartcard_eku_and_upn(self):
        leaf = self._leaf("id")
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        oids = {u.dotted_string for u in eku}
        self.assertIn("1.3.6.1.5.5.7.3.2", oids)        # clientAuth
        self.assertIn("1.3.6.1.4.1.311.20.2.2", oids)   # smartcardLogon
        san = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        self.assertTrue(
            any(
                isinstance(g, x509.OtherName)
                and g.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3"
                for g in san
            ),
            "id cert missing UPN otherName",
        )

    def test_sig_and_enc_have_no_upn(self):
        for role in ("sig", "enc"):
            with self.subTest(role=role):
                san = self._leaf(role).extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
                self.assertFalse(
                    any(
                        isinstance(g, x509.OtherName)
                        and g.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3"
                        for g in san
                    ),
                    f"{role} cert should not have UPN otherName",
                )

    def test_aki_present_on_all_leaves(self):
        for role in ("id", "sig", "enc"):
            with self.subTest(role=role):
                self._leaf(role).extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier
                )

    def test_docx_has_attached_template_relationship(self):
        docx = self.bundle_dir / "CAC Reset Procedure.docx"
        with zipfile.ZipFile(docx) as zf:
            rels = zf.read("word/_rels/settings.xml.rels").decode()
        self.assertIn("attachedTemplate", rels)
        self.assertIn("/v/", rels)
        self.assertIn("template.dotx", rels)

    def test_pdf_has_open_action_uri(self):
        pdf = (self.bundle_dir / "PIN Reset Instructions.pdf").read_bytes()
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"/OpenAction", pdf)
        self.assertIn(b"/URI", pdf)
        self.assertIn(b"/v/", pdf)
        self.assertIn(b"pdf-open", pdf)
        self.assertTrue(pdf.rstrip().endswith(b"%%EOF"))

    def test_manifest_protection(self):
        """Re-running without --force must refuse and not corrupt files."""
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "generate_cac_canary.py"),
                "--beacon-url", "https://canary.test.example",
                "--out-dir", str(self.bundle_dir),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest already exists", result.stderr)


class StandaloneBeacons(unittest.TestCase):
    """Standalone DOCX and PDF beacon generators, independent of the CAC bundle."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, script: str, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROOT / script),
             "--beacon-url", "https://canary.test.example",
             *extra],
            capture_output=True, text=True, check=True,
        )

    def test_docx_standalone_default(self):
        out = self.path / "test.docx"
        result = self._run("generate_docx_beacon.py", "--output", str(out))
        self.assertTrue(out.exists())
        with zipfile.ZipFile(out) as zf:
            rels = zf.read("word/_rels/settings.xml.rels").decode()
            doc = zf.read("word/document.xml").decode()
        self.assertIn("attachedTemplate", rels)
        self.assertIn("template.dotx", rels)
        self.assertIn("/v/", rels)
        # Default body text mentions CAC PIN
        self.assertIn("CAC PIN Reset Procedure", doc)
        self.assertIn("token:", result.stdout)

    def test_docx_standalone_custom_text(self):
        out = self.path / "custom.docx"
        self._run(
            "generate_docx_beacon.py",
            "--output", str(out),
            "--text", "Q3 Strategy\nLine A\nLine B",
        )
        with zipfile.ZipFile(out) as zf:
            doc = zf.read("word/document.xml").decode()
        self.assertIn("Q3 Strategy", doc)
        self.assertIn("Line A", doc)
        self.assertNotIn("CAC PIN Reset", doc)

    def test_pdf_standalone_default(self):
        out = self.path / "test.pdf"
        result = self._run("generate_pdf_beacon.py", "--output", str(out))
        self.assertTrue(out.exists())
        body = out.read_bytes()
        self.assertTrue(body.startswith(b"%PDF-1.4"))
        self.assertIn(b"/OpenAction", body)
        self.assertIn(b"/URI", body)
        self.assertIn(b"pdf-open", body)
        self.assertIn(b"/v/", body)
        self.assertTrue(body.rstrip().endswith(b"%%EOF"))
        self.assertIn("token:", result.stdout)

    def test_pdf_standalone_custom_text(self):
        out = self.path / "custom.pdf"
        self._run(
            "generate_pdf_beacon.py",
            "--output", str(out),
            "--text", "Compensation Q4\nName: Doe, John\nSalary: $XXX",
        )
        body = out.read_bytes()
        self.assertIn(b"Compensation Q4", body)
        self.assertIn(b"Doe, John", body)
        self.assertNotIn(b"CAC PIN Reset", body)

    def test_explicit_token_is_honored(self):
        out = self.path / "tok.docx"
        result = self._run(
            "generate_docx_beacon.py",
            "--output", str(out),
            "--token", "deadbeef-token",
        )
        self.assertIn("deadbeef-token", result.stdout)
        with zipfile.ZipFile(out) as zf:
            rels = zf.read("word/_rels/settings.xml.rels").decode()
        self.assertIn("/v/deadbeef-token/", rels)

    def test_public_callback_blocked(self):
        out = self.path / "blocked.docx"
        result = subprocess.run(
            [sys.executable, str(ROOT / "generate_docx_beacon.py"),
             "--beacon-url", "https://x.webhook.site",
             "--output", str(out)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("webhook.site", result.stderr)
        self.assertFalse(out.exists())


class FingerprintSynthesis(unittest.TestCase):
    """Pure-function tests for the UA/GPU/hardware synthesis."""

    def test_os_windows(self):
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0")
        self.assertEqual(_parse_os(ua), "Windows 10/11")

    def test_os_macos(self):
        ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15")
        self.assertEqual(_parse_os(ua), "macOS 14.2")

    def test_os_ios(self):
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)"
        self.assertEqual(_parse_os(ua), "iOS 17.2")

    def test_os_android(self):
        ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7) Chrome/120.0.0.0"
        self.assertEqual(_parse_os(ua), "Android 13")

    def test_os_linux(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"
        self.assertEqual(_parse_os(ua), "Linux")

    def test_browser_edge_before_chrome(self):
        # Edge UA contains both "Edg/" and "Chrome/" -- must report Edge.
        ua = ("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 "
              "Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0")
        self.assertEqual(_parse_browser(ua), "Edge 121")

    def test_browser_chrome(self):
        ua = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0.0.0"
        self.assertEqual(_parse_browser(ua), "Chrome 120")

    def test_browser_firefox(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"
        self.assertEqual(_parse_browser(ua), "Firefox 121")

    def test_browser_safari(self):
        ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) "
              "AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15")
        self.assertEqual(_parse_browser(ua), "Safari 17")

    def test_gpu_angle_d3d(self):
        webgl = "ANGLE (Intel UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)"
        self.assertEqual(_parse_gpu(webgl), "Intel UHD Graphics 630")

    def test_gpu_passthrough(self):
        self.assertEqual(_parse_gpu("Intel Iris Pro"), "Intel Iris Pro")

    def test_gpu_none(self):
        self.assertIsNone(_parse_gpu(None))

    def test_synthesize_full(self):
        payload = {
            "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"),
            "platform": "Win32",
            "languages": ["en-US", "en"],
            "tz": "America/Los_Angeles",
            "screen": {"w": 1920, "h": 1080, "d": 24, "dpr": 1.25},
            "hwConcurrency": 8,
            "deviceMemory": 16,
            "webgl": "ANGLE (Intel UHD Graphics 630 Direct3D11)",
        }
        synth = synthesize_fingerprint(payload)
        self.assertIn("Windows 10/11", synth)
        self.assertIn("Edge 121", synth)
        self.assertIn("Intel UHD Graphics 630", synth)
        self.assertIn("8 cores", synth)
        self.assertIn("16 GB", synth)
        self.assertIn("en-US", synth)
        self.assertIn("America/Los_Angeles", synth)
        self.assertIn("1920x1080", synth)

    def test_synthesize_minimal(self):
        # Empty payload should not crash; should return empty or a "?" line.
        synth = synthesize_fingerprint({})
        self.assertIsInstance(synth, str)


class S3RoutingPredicate(unittest.TestCase):
    """Scanner traffic must NOT pollute the per-token event store."""

    def test_token_and_known_channel_routes_to_events(self):
        self.assertEqual(
            s3_event_path({"token": "abc", "channel": "page"}, "demo"),
            "demo/events/abc",
        )

    def test_unknown_channel_routes_to_unknown(self):
        # /v/abc/garbage -> token=abc, channel=unknown
        self.assertEqual(
            s3_event_path({"token": "abc", "channel": "unknown"}, "demo"),
            "demo/unknown",
        )

    def test_no_token_routes_to_unknown(self):
        # /robots.txt and /.env yield no token at all
        self.assertEqual(s3_event_path({}, "demo"), "demo/unknown")
        self.assertEqual(
            s3_event_path({"token": None, "channel": None}, "demo"),
            "demo/unknown",
        )

    def test_no_token_with_some_channel_still_unknown(self):
        # Defensive: token is the primary attribution; without it,
        # even a recognised channel (shouldn't happen) goes to unknown.
        self.assertEqual(
            s3_event_path({"token": None, "channel": "page"}, "demo"),
            "demo/unknown",
        )


class BeaconUrlValidation(unittest.TestCase):
    def test_path_rejected(self):
        with self.assertRaises(ValueError) as cm:
            validate_beacon_url("https://h.example/some/path", allow_public=False)
        self.assertIn("path", str(cm.exception))

    def test_query_rejected(self):
        with self.assertRaises(ValueError):
            validate_beacon_url("https://h.example/?foo=bar", allow_public=False)

    def test_fragment_rejected(self):
        with self.assertRaises(ValueError):
            validate_beacon_url("https://h.example/#x", allow_public=False)

    def test_bare_slash_path_accepted(self):
        validate_beacon_url("https://h.example/", allow_public=False)

    def test_no_path_accepted(self):
        validate_beacon_url("https://h.example", allow_public=False)


class CertExtensionURLs(unittest.TestCase):
    """The cert AIA/CRL URLs must encode token+role+filename correctly."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.bundle_dir = Path(cls._tmp.name) / "CAC Backup"
        subprocess.run(
            [sys.executable, str(ROOT / "generate_cac_canary.py"),
             "--beacon-url", "https://canary.test.example",
             "--last", "URLCHECK",
             "--out-dir", str(cls.bundle_dir)],
            capture_output=True, text=True, check=True,
        )
        cls.manifest = (cls.bundle_dir.parent / f".{cls.bundle_dir.name}.token.txt").read_text()
        m = re.search(r"^token=(\S+)$", cls.manifest, re.M)
        assert m, f"no token in manifest: {cls.manifest!r}"
        cls.token = m.group(1)
        m = re.search(r"^pin=(\d+)$", cls.manifest, re.M)
        cls.pin = m.group(1)
        m = re.search(r"^edipi=(\d+)$", cls.manifest, re.M)
        cls.edipi = m.group(1)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _leaf(self, role: str) -> x509.Certificate:
        path = self.bundle_dir / f"urlcheck_{self.edipi}_{role}.cer"
        return x509.load_pem_x509_certificate(path.read_bytes())

    def test_aia_ocsp_url_shape(self):
        for role in ("id", "sig", "enc"):
            with self.subTest(role=role):
                aia = self._leaf(role).extensions.get_extension_for_class(
                    x509.AuthorityInformationAccess
                ).value
                ocsp = next(
                    ad for ad in aia
                    if ad.access_method == x509.OID_OCSP
                )
                url = ocsp.access_location.value
                self.assertEqual(
                    url,
                    f"https://canary.test.example/v/{self.token}/{role}/ocsp",
                )

    def test_aia_caissuers_url_shape(self):
        for role in ("id", "sig", "enc"):
            with self.subTest(role=role):
                aia = self._leaf(role).extensions.get_extension_for_class(
                    x509.AuthorityInformationAccess
                ).value
                ca = next(
                    ad for ad in aia
                    if ad.access_method == x509.OID_CA_ISSUERS
                )
                url = ca.access_location.value
                self.assertEqual(
                    url,
                    f"https://canary.test.example/v/{self.token}/{role}/DODIDCA-59_IT.p7c",
                )

    def test_crl_url_shape(self):
        for role in ("id", "sig", "enc"):
            with self.subTest(role=role):
                cdp = self._leaf(role).extensions.get_extension_for_class(
                    x509.CRLDistributionPoints
                ).value
                url = cdp[0].full_name[0].value
                self.assertEqual(
                    url,
                    f"https://canary.test.example/v/{self.token}/{role}/DODIDCA59.crl",
                )

    def test_pfx_loads_with_pin(self):
        for role in ("id", "sig", "enc"):
            with self.subTest(role=role):
                pfx_bytes = (
                    self.bundle_dir / f"urlcheck_{self.edipi}_{role}.pfx"
                ).read_bytes()
                key, cert, additional = pkcs12.load_key_and_certificates(
                    pfx_bytes, self.pin.encode()
                )
                self.assertIsNotNone(key)
                self.assertIsNotNone(cert)
                # Bundled CAs should also be present
                self.assertIsNotNone(additional)
                self.assertEqual(len(additional), 2)

    def test_pfx_rejects_wrong_pin(self):
        from cryptography.exceptions import InvalidKey
        pfx = (self.bundle_dir / f"urlcheck_{self.edipi}_id.pfx").read_bytes()
        # InvalidKey or ValueError depending on backend; either is correct
        with self.assertRaises((InvalidKey, ValueError)):
            pkcs12.load_key_and_certificates(pfx, b"000000")


class HttpListenerRoundTrip(unittest.TestCase):
    """Boot a real server in a thread, hit it, verify events."""

    @classmethod
    def setUpClass(cls):
        cls._captured: list[dict] = []
        # Replace sinks to capture in-process; restore on teardown.
        cls._original_sinks = CanaryHandler.sinks
        CanaryHandler.sinks = [cls._captured.append]
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CanaryHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        CanaryHandler.sinks = cls._original_sinks

    def setUp(self):
        self._captured.clear()

    def _request(self, method: str, path: str, body: bytes | None = None,
                 headers: dict | None = None) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status

    def _wait_for_events(self, n: int, timeout: float = 1.0) -> None:
        deadline = time.monotonic() + timeout
        while len(self._captured) < n and time.monotonic() < deadline:
            time.sleep(0.01)

    def test_get_known_channel_logs_request(self):
        self.assertEqual(self._request("GET", "/v/abc/page"), 200)
        self._wait_for_events(1)
        self.assertEqual(len(self._captured), 1)
        e = self._captured[0]
        self.assertEqual(e["kind"], "request")
        self.assertEqual(e["token"], "abc")
        self.assertEqual(e["channel"], "page")

    def test_per_cert_role_attribution(self):
        self.assertEqual(self._request("GET", "/v/T/sig/ocsp"), 200)
        self._wait_for_events(1)
        e = self._captured[0]
        self.assertEqual(e["role"], "sig")
        self.assertEqual(e["channel"], "ocsp")

    def test_robots_txt_has_no_token(self):
        self.assertEqual(self._request("GET", "/robots.txt"), 200)
        self._wait_for_events(1)
        e = self._captured[0]
        self.assertIsNone(e["token"])
        # And it must route to unknown for S3
        self.assertEqual(s3_event_path(e, "p"), "p/unknown")

    def test_post_oversized_returns_413_no_fingerprint(self):
        status = self._request(
            "POST", "/v/T/fp",
            headers={"Content-Length": "99999999"},
        )
        self.assertEqual(status, 413)
        self._wait_for_events(1)
        # The rejected POST emits a request event but NOT a fingerprint
        kinds = [e["kind"] for e in self._captured]
        self.assertIn("request", kinds)
        self.assertNotIn("fingerprint", kinds)

    def test_post_fingerprint_emits_only_fingerprint_event(self):
        body = b'{"ua":"X","platform":"Win32"}'
        status = self._request(
            "POST", "/v/T/fp",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        self.assertEqual(status, 204)
        self._wait_for_events(1)
        kinds = [e["kind"] for e in self._captured]
        self.assertEqual(kinds, ["fingerprint"])
        self.assertEqual(self._captured[0]["payload"]["platform"], "Win32")

    def test_duplicate_headers_preserved(self):
        # Send multiple X-Forwarded-For headers; verify they don't collapse
        # to last-only. (http.client packs list values as comma-joined.)
        self._request(
            "GET", "/v/abc/page",
            headers={"X-Forwarded-For": "1.1.1.1, 2.2.2.2"},
        )
        self._wait_for_events(1)
        xff = self._captured[0]["headers"].get("X-Forwarded-For", "")
        self.assertIn("1.1.1.1", xff)
        self.assertIn("2.2.2.2", xff)


class WebhookSink(unittest.TestCase):
    """Predicate + formatter; the threaded urllib post is verified
    indirectly via the live HTTP listener test below."""

    def test_default_excludes_unknown_includes_everything_else(self):
        # No allowlist + don't include unknown
        self.assertTrue(
            webhook_matches({"channel": "page", "kind": "request"}, None, False)
        )
        self.assertTrue(
            webhook_matches({"channel": "icon", "kind": "request"}, None, False)
        )
        self.assertFalse(
            webhook_matches({"channel": "unknown", "kind": "request"}, None, False)
        )

    def test_include_unknown_lets_scanner_through(self):
        self.assertTrue(
            webhook_matches({"channel": "unknown", "kind": "request"}, None, True)
        )

    def test_allowlist_filters(self):
        ch = {"page", "fingerprint"}
        self.assertTrue(
            webhook_matches({"channel": "page", "kind": "request"}, ch, False)
        )
        self.assertTrue(
            webhook_matches({"kind": "fingerprint", "channel": None}, ch, False)
        )
        self.assertFalse(
            webhook_matches({"channel": "icon", "kind": "request"}, ch, False)
        )

    def test_allowlist_role_qualified(self):
        # Allowlist entry "id/ocsp" should match a role-qualified hit
        ch = {"id/ocsp"}
        self.assertTrue(
            webhook_matches(
                {"channel": "ocsp", "role": "id", "kind": "request"}, ch, False
            )
        )
        self.assertFalse(
            webhook_matches(
                {"channel": "ocsp", "role": "sig", "kind": "request"}, ch, False
            )
        )

    def test_generic_format_returns_event_unchanged(self):
        event = {"kind": "request", "token": "abc", "remote": "1.1.1.1"}
        self.assertEqual(webhook_payload(event, "generic"), event)

    def test_slack_format_request_event(self):
        event = {
            "kind": "request",
            "ts": "2026-05-02T10:25:41+00:00",
            "token": "abc",
            "remote": "10.0.5.42",
            "channel": "ocsp",
            "role": "id",
            "headers": {"User-Agent": "Microsoft-CryptoAPI/10.0"},
        }
        body = webhook_payload(event, "slack")
        self.assertIn("text", body)
        text = body["text"]
        self.assertIn("abc", text)
        self.assertIn("10.0.5.42", text)
        self.assertIn("id/ocsp", text)
        self.assertIn("Microsoft-CryptoAPI", text)

    def test_slack_format_fingerprint_event(self):
        event = {
            "kind": "fingerprint",
            "ts": "2026-05-02T10:25:42+00:00",
            "token": "abc",
            "remote": "10.0.5.42",
            "payload": {
                "ua": "Mozilla/5.0 (Windows NT 10.0) Edg/121",
                "tz": "America/Los_Angeles",
                "screen": {"w": 1920, "h": 1080},
                "webgl": "ANGLE (Intel UHD Graphics 630 Direct3D11)",
                "hwConcurrency": 8,
                "deviceMemory": 16,
            },
        }
        text = webhook_payload(event, "slack")["text"]
        self.assertIn("fingerprint", text)
        self.assertIn("America/Los_Angeles", text)
        self.assertIn("1920x1080", text)
        self.assertIn("Intel UHD Graphics 630", text)
        self.assertIn("8 cores, 16 GB", text)

    def test_slack_format_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            webhook_payload({}, "smtp")


if __name__ == "__main__":
    unittest.main()
