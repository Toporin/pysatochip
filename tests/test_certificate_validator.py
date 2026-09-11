# -*- coding: utf-8 -*-
"""Tests for the certificate chain validation, including the pycryptodomex
fallback that no longer depends on `ecdsa` (issue #8).

The shipped chain is: a secp384r1 root CA which signs secp256k1 subCAs, which in
turn sign the per-device certificates; every signature is ecdsa-with-SHA512. So
validation needs both a P-384 and a secp256k1 verification path, and neither can
come from libsecp256k1 alone.

No smartcard required: a synthetic chain of the same shape stands in for the
device certificate, which we cannot mint without the real subCA private key.
"""

import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip import ec_backend
from pysatochip.certificate_validator import HAS_OPENSSL, CertificateValidator

CERT_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "pysatochip", "cert")
DEVICE_TYPES = ("Satochip", "SeedKeeper", "Satodime")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    CAN_BUILD_CERTS = True
except ImportError:  # pragma: no cover
    CAN_BUILD_CERTS = False


def read_cert(name):
    with open(os.path.join(CERT_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


def cert_name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Toporin"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def build_chain():
    """A P-384 root -> secp256k1 subCA -> secp256k1 device chain, mirroring the
    real Satochip PKI so both verification legs get exercised."""
    name = cert_name
    start = datetime.datetime(2024, 1, 1)
    end = datetime.datetime(2044, 1, 1)
    root_key = ec.generate_private_key(ec.SECP384R1())
    sub_key = ec.generate_private_key(ec.SECP256K1())
    dev_key = ec.generate_private_key(ec.SECP256K1())

    def cert(subject, issuer_name, pub, signer, serial):
        return (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer_name)
                .public_key(pub).serial_number(serial)
                .not_valid_before(start).not_valid_after(end)
                .sign(signer, hashes.SHA512()))

    root = cert(name(u"Test Root"), name(u"Test Root"),
                root_key.public_key(), root_key, 1)
    sub = cert(name(u"Test SubCA"), root.subject,
               sub_key.public_key(), root_key, 2)
    dev = cert(name(u"Test Device"), sub.subject,
               dev_key.public_key(), sub_key, 3)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    dev_pub = dev_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return pem(root), pem(sub), pem(dev), bytes(dev_pub), sub_key, start, end


@unittest.skipUnless(CAN_BUILD_CERTS, "needs cryptography to mint test certs")
class TestSyntheticChain(unittest.TestCase):
    """Exercises both the P-384 (root->subCA) and secp256k1 (subCA->device)
    legs of the pycryptodomex fallback."""

    @classmethod
    def setUpClass(cls):
        (cls.root_pem, cls.sub_pem, cls.dev_pem, cls.dev_pub,
         cls.sub_key, cls.start, cls.end) = build_chain()

    def validator(self):
        return CertificateValidator(backend="pycryptodomex")

    def test_valid_chain_is_accepted(self):
        ok, pubkey, _ca, _sub, _dev, err = \
            self.validator()._validate_chain_pycryptodomex(
                self.root_pem, self.sub_pem, self.dev_pem)
        self.assertTrue(ok, err)
        self.assertEqual(bytes(pubkey), self.dev_pub)

    def test_tampered_subca_is_rejected(self):
        """Breaks the P-384 leg."""
        bad = self.sub_pem.replace("MII", "MIJ", 1)
        ok, _pub, _ca, _sub, _dev, err = \
            self.validator()._validate_chain_pycryptodomex(
                self.root_pem, bad, self.dev_pem)
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_device_signed_by_wrong_key_is_rejected(self):
        """Breaks the secp256k1 leg."""
        rogue_key = ec.generate_private_key(ec.SECP256K1())
        rogue = (x509.CertificateBuilder()
                 .subject_name(cert_name(u"Rogue"))
                 .issuer_name(cert_name(u"Test SubCA"))
                 .public_key(rogue_key.public_key()).serial_number(4)
                 .not_valid_before(self.start).not_valid_after(self.end)
                 .sign(rogue_key, hashes.SHA512()))
        rogue_pem = rogue.public_bytes(serialization.Encoding.PEM).decode()
        ok, _pub, _ca, _sub, _dev, err = \
            self.validator()._validate_chain_pycryptodomex(
                self.root_pem, self.sub_pem, rogue_pem)
        self.assertFalse(ok)
        self.assertEqual(err, "Bad certificate signature")

    def test_swapped_root_is_rejected(self):
        other_root, _s, _d, _p, _k, _st, _e = build_chain()
        ok, _pub, _ca, _sub, _dev, err = \
            self.validator()._validate_chain_pycryptodomex(
                other_root, self.sub_pem, self.dev_pem)
        self.assertFalse(ok)
        self.assertEqual(err, "Bad certificate signature")

    def test_malformed_pem_is_rejected(self):
        ok, _pub, _ca, _sub, _dev, err = \
            self.validator()._validate_chain_pycryptodomex(
                "not a certificate", self.sub_pem, self.dev_pem)
        self.assertFalse(ok)
        self.assertTrue(err)


class TestShippedCertificates(unittest.TestCase):
    """The real prod and test CA files must parse and their P-384 root->subCA
    links must verify. We cannot mint a device cert, so the chain stops there."""

    def _ca_pubkey(self, ca_name):
        from Cryptodome.Util.asn1 import DerBitString, DerSequence
        import base64
        import re
        pem = read_cert(ca_name)
        der = base64.b64decode(''.join(re.search(
            r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
            pem, re.S).group(1).split()))
        seq = DerSequence(); seq.decode(der)
        tbs = DerSequence(); tbs.decode(seq[0])
        spki = DerSequence(); spki.decode(tbs[6])
        bits = DerBitString(); bits.decode(spki[1])
        return bits.value

    def _tbs_and_sig(self, name):
        from Cryptodome.Util.asn1 import DerBitString, DerSequence
        import base64
        import re
        pem = read_cert(name)
        der = base64.b64decode(''.join(re.search(
            r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
            pem, re.S).group(1).split()))
        seq = DerSequence(); seq.decode(der)
        bits = DerBitString(); bits.decode(seq[2])
        return seq[0], bits.value

    def test_root_ca_is_p384(self):
        for ca in ("ca.cert", "test-ca.cert"):
            self.assertEqual(len(self._ca_pubkey(ca)), 97,
                             "%s should hold a 97-byte P-384 point" % ca)

    def test_real_subca_signatures_verify(self):
        for ca, prefix in (("ca.cert", "subca"), ("test-ca.cert", "test-subca")):
            ca_pub = self._ca_pubkey(ca)
            for dev in ("satochip", "seedkeeper", "satodime"):
                with self.subTest(ca=ca, device=dev):
                    tbs, sig = self._tbs_and_sig("%s-%s.cert" % (prefix, dev))
                    self.assertTrue(
                        ec_backend.verify_p384(ca_pub, tbs, sig, "sha512"))

    def test_tampered_subca_signature_fails(self):
        ca_pub = self._ca_pubkey("ca.cert")
        tbs, sig = self._tbs_and_sig("subca-satochip.cert")
        tampered = tbs[:-1] + bytes([tbs[-1] ^ 0x01])
        self.assertFalse(ec_backend.verify_p384(ca_pub, tampered, sig, "sha512"))

    def test_unknown_device_type_is_reported(self):
        cv = CertificateValidator(backend="pycryptodomex")
        ok, _pub, _ca, _sub, _dev, err = cv._validate_chain(
            read_cert("subca-satochip.cert"), "NotACard")
        self.assertFalse(ok)
        self.assertIn("Unknown card_type", err)

    def test_parse_pem_certificate(self):
        cv = CertificateValidator(backend="pycryptodomex")
        result = cv.parse_pem_certificate(read_cert("ca.cert"))
        self.assertTrue(result)


class TestBackendSelection(unittest.TestCase):

    def test_openssl_backend_requires_pyopenssl(self):
        cv = CertificateValidator(backend="openssl")
        ok, _pub, _ca, _sub, _dev, err = cv._validate_chain(
            read_cert("subca-satochip.cert"), "Satochip")
        if HAS_OPENSSL:
            # pyOpenSSL is present, so it fails on the chain itself, not setup
            self.assertNotIn("not available", err)
        else:  # pragma: no cover
            self.assertIn("pyOpenSSL is not available", err)

    def test_p384_needs_a_capable_library(self):
        """P-384 cannot come from libsecp256k1; ec_backend must fall back to
        pycryptodomex when cryptography is missing."""
        self.assertTrue(ec_backend.HAS_CRYPTOGRAPHY or ec_backend.HAS_PYCRYPTODOMEX,
                        "no library available for P-384 verification")


if __name__ == "__main__":
    unittest.main(verbosity=2)
