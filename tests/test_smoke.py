"""End-to-end smoke tests for the canary toolkit.

Runs the generator CLI and asserts the artifacts have the right shape,
plus unit tests for the listener path parser. Pure stdlib +
cryptography (already required); run with:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from canary_listener import channel_for, parse_path


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


if __name__ == "__main__":
    unittest.main()
