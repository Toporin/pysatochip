# -*- coding: utf-8 -*-
"""Compatibility tests for pysatochip.ecc after the ecdsa removal (issue #8).

ecc.py is public API -- downstream consumers such as the Electrum Satochip
plugin and Satochip-Bridge import ECPubkey/ECPrivkey directly -- so these tests
pin both the behaviour and the exported surface. No smartcard required.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import vectors as v
from pysatochip import ec_backend
from pysatochip.ecc import (CURVE_ORDER, ECPrivkey, ECPubkey,
                            InvalidECPointException, construct_sig65,
                            der_sig_from_r_and_s, der_sig_from_sig_string,
                            generator, get_r_and_s_from_der_sig,
                            get_r_and_s_from_sig_string, is_secret_within_curve_range,
                            msg_magic, point_at_infinity, sig_string_from_der_sig,
                            sig_string_from_r_and_s)

BACKENDS = ec_backend.available_backends()

GENERATOR_COMPRESSED = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")


class EccTestCase(unittest.TestCase):

    def setUp(self):
        self._saved = ec_backend.BACKEND

    def tearDown(self):
        ec_backend.BACKEND = self._saved

    def for_each_backend(self):
        if not BACKENDS:
            self.skipTest("no hardened EC backend available")
        for backend in BACKENDS:
            ec_backend.set_backend(backend)
            with self.subTest(backend=backend):
                yield backend


class TestECPrivkey(EccTestCase):

    def test_pubkey_derivation_matches_frozen_vectors(self):
        for _ in self.for_each_backend():
            pk = ECPrivkey(v.PRIV_A)
            self.assertEqual(pk.get_public_key_bytes(True), v.PUB_A_COMPRESSED)
            self.assertEqual(pk.get_public_key_bytes(False), v.PUB_A_UNCOMPRESSED)
            self.assertEqual(pk.get_public_key_hex(True), v.PUB_A_COMPRESSED.hex())
            self.assertEqual(pk.get_private_key_bytes(), v.PRIV_A)
            self.assertEqual(pk.secret_scalar, int.from_bytes(v.PRIV_A, "big"))

    def test_rejects_bad_secrets(self):
        for _ in self.for_each_backend():
            with self.assertRaises(Exception):
                ECPrivkey(b"\x01" * 31)          # wrong length
            with self.assertRaises(InvalidECPointException):
                ECPrivkey(bytes(32))             # zero
            with self.assertRaises(InvalidECPointException):
                ECPrivkey(CURVE_ORDER.to_bytes(32, "big"))   # == order

    def test_alternate_constructors(self):
        for _ in self.for_each_backend():
            scalar = int.from_bytes(v.PRIV_A, "big")
            self.assertEqual(ECPrivkey.from_secret_scalar(scalar),
                             ECPubkey(v.PUB_A_UNCOMPRESSED))
            # oversized secret is reduced mod n rather than rejected
            self.assertTrue(ECPrivkey.from_arbitrary_size_secret(b"\x07" * 40))
            with self.assertRaises(Exception):
                ECPrivkey.normalize_secret_bytes(bytes(32))


class TestSigning(EccTestCase):

    def test_sign_roundtrip(self):
        for _ in self.for_each_backend():
            pk = ECPrivkey(v.PRIV_A)
            sig_string = pk.sign(v.DIGEST)
            self.assertEqual(len(sig_string), 64)
            ECPubkey(v.PUB_A_UNCOMPRESSED).verify_message_hash(sig_string, v.DIGEST)

    def test_sign_transaction_is_low_s_der(self):
        for _ in self.for_each_backend():
            der = ECPrivkey(v.PRIV_A).sign_transaction(v.DIGEST)
            r, s = get_r_and_s_from_der_sig(der)
            self.assertLessEqual(s, CURVE_ORDER // 2)
            self.assertEqual(der_sig_from_r_and_s(r, s), der)

    def test_sign_message_roundtrip(self):
        for _ in self.for_each_backend():
            pk = ECPrivkey(v.PRIV_A)
            pub = ECPubkey(v.PUB_A_UNCOMPRESSED)
            for compressed in (True, False):
                sig65 = pk.sign_message(v.MESSAGE, compressed)
                self.assertEqual(len(sig65), 65)
                pub.verify_message_for_address(sig65, v.MESSAGE)

    def test_verifies_message_signed_by_old_implementation(self):
        for _ in self.for_each_backend():
            ECPubkey(v.PUB_A_UNCOMPRESSED).verify_message_for_address(
                v.SIG65_COMPRESSED, v.MESSAGE)

    def test_rejects_signature_from_other_key(self):
        for _ in self.for_each_backend():
            with self.assertRaises(Exception):
                ECPubkey(v.PUB_B_UNCOMPRESSED).verify_message_hash(
                    v.SIG_STRING, v.DIGEST)

    def test_rejects_wrong_length_sig_string(self):
        for _ in self.for_each_backend():
            with self.assertRaises(Exception):
                ECPubkey(v.PUB_A_UNCOMPRESSED).verify_message_hash(
                    v.SIG_STRING[:63], v.DIGEST)


class TestECPubkey(EccTestCase):

    def test_compressed_and_uncompressed_are_equal(self):
        self.assertEqual(ECPubkey(v.PUB_A_COMPRESSED),
                         ECPubkey(v.PUB_A_UNCOMPRESSED))
        self.assertNotEqual(ECPubkey(v.PUB_A_UNCOMPRESSED),
                            ECPubkey(v.PUB_B_UNCOMPRESSED))

    def test_rejects_point_off_curve(self):
        with self.assertRaises(InvalidECPointException):
            ECPubkey(b"\x04" + bytes(64))
        self.assertFalse(ECPubkey.is_pubkey_bytes(b"\x04" + bytes(64)))
        self.assertTrue(ECPubkey.is_pubkey_bytes(v.PUB_A_COMPRESSED))

    def test_recovery_from_sig_string(self):
        for _ in self.for_each_backend():
            self.assertEqual(
                ECPubkey.from_sig_string(v.SIG_STRING, v.RECID_FOR_PUB_A, v.DIGEST),
                ECPubkey(v.PUB_A_UNCOMPRESSED))
            with self.assertRaises(ValueError):
                ECPubkey.from_sig_string(v.SIG_STRING, 9, v.DIGEST)
            with self.assertRaises(Exception):
                ECPubkey.from_sig_string(v.SIG_STRING[:10], 0, v.DIGEST)

    def test_from_signature65(self):
        for _ in self.for_each_backend():
            pub, compressed = ECPubkey.from_signature65(
                v.SIG65_COMPRESSED,
                __import__("pysatochip.util", fromlist=["sha256d"]).sha256d(
                    msg_magic(v.MESSAGE)))
            self.assertTrue(compressed)
            self.assertEqual(pub, ECPubkey(v.PUB_A_UNCOMPRESSED))

    def test_point_arithmetic(self):
        g = generator()
        self.assertEqual(g.get_public_key_bytes(True), GENERATOR_COMPRESSED)
        a = ECPubkey(v.PUB_A_UNCOMPRESSED)
        scalar = int.from_bytes(v.PRIV_A, "big")
        self.assertEqual(g * scalar, a)
        self.assertEqual(scalar * g, a)
        self.assertEqual(a + a, a * 2)
        b_ = ECPubkey(v.PUB_B_UNCOMPRESSED)
        self.assertEqual(a + b_, b_ + a)
        with self.assertRaises(TypeError):
            a * "2"
        with self.assertRaises(TypeError):
            a + 1

    def test_infinity(self):
        inf = point_at_infinity()
        self.assertTrue(inf.is_at_infinity())
        self.assertFalse(ECPubkey(v.PUB_A_UNCOMPRESSED).is_at_infinity())
        with self.assertRaises(Exception):
            inf.get_public_key_bytes()

    def test_order_and_range_helpers(self):
        self.assertEqual(ECPubkey.order(), CURVE_ORDER)
        self.assertTrue(is_secret_within_curve_range(v.PRIV_A))
        self.assertFalse(is_secret_within_curve_range(0))
        self.assertFalse(is_secret_within_curve_range(CURVE_ORDER))


class TestSignatureCodecs(unittest.TestCase):
    """These replaced ecdsa.util.sigencode_*/sigdecode_*; the *_canonize
    variants enforced low-S, so the replacements must too."""

    def test_der_and_compact_conversions(self):
        self.assertEqual(sig_string_from_der_sig(v.SIG_DER_LOWS), v.SIG_STRING)
        self.assertEqual(der_sig_from_sig_string(v.SIG_STRING), v.SIG_DER_LOWS)
        self.assertEqual(get_r_and_s_from_sig_string(v.SIG_STRING), (v.SIG_R, v.SIG_S))
        self.assertEqual(get_r_and_s_from_der_sig(v.SIG_DER_LOWS), (v.SIG_R, v.SIG_S))
        self.assertEqual(sig_string_from_r_and_s(v.SIG_R, v.SIG_S), v.SIG_STRING)
        self.assertEqual(der_sig_from_r_and_s(v.SIG_R, v.SIG_S), v.SIG_DER_LOWS)

    def test_high_s_is_canonicalized_on_encode(self):
        high_s = CURVE_ORDER - v.SIG_S
        self.assertEqual(der_sig_from_r_and_s(v.SIG_R, high_s), v.SIG_DER_LOWS)
        self.assertEqual(sig_string_from_r_and_s(v.SIG_R, high_s), v.SIG_STRING)

    def test_high_s_is_preserved_on_decode(self):
        """Decoding must report what was actually there, so callers can detect
        a non-canonical signature."""
        self.assertEqual(get_r_and_s_from_der_sig(v.SIG_DER_HIGHS),
                         (v.SIG_R, CURVE_ORDER - v.SIG_S))

    def test_rejects_malformed_der(self):
        for bad in (b"", b"\x30\x00", b"\x02\x01\x01", v.SIG_DER_LOWS + b"\x00"):
            with self.assertRaises(Exception):
                get_r_and_s_from_der_sig(bad)


class TestMiscHelpers(unittest.TestCase):

    def test_msg_magic(self):
        self.assertTrue(msg_magic(b"x").startswith(b"\x18Bitcoin Signed Message:\n"))
        self.assertTrue(msg_magic(b"abc").endswith(b"abc"))

    def test_construct_sig65(self):
        self.assertEqual(construct_sig65(v.SIG_STRING, 1, True)[0], 27 + 1 + 4)
        self.assertEqual(construct_sig65(v.SIG_STRING, 1, False)[0], 27 + 1)
        self.assertEqual(len(construct_sig65(v.SIG_STRING, 0, True)), 65)


if __name__ == "__main__":
    print("available backends:", BACKENDS or "(none)")
    unittest.main(verbosity=2)
