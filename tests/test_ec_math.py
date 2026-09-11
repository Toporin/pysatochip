# -*- coding: utf-8 -*-
"""Tests for the pure-python secp256k1 math and signature codecs (issue #8).

ec_math.py replaced ecdsa.ellipticcurve / ecdsa.numbertheory / ecdsa.util. It
only ever handles public data, so it does not need to be constant time -- but it
does need to be strict: a permissive DER decoder or a missing on-curve check is
a real vulnerability, and public key recovery here is on the hot path for every
card response (CardDataParser.get_pubkey_from_signature).
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import vectors as v
from pysatochip import ec_math as m


class TestCurveParameters(unittest.TestCase):

    def test_generator_is_on_curve_and_has_the_right_order(self):
        self.assertTrue(m.contains_point(m.CURVE_GX, m.CURVE_GY))
        self.assertTrue((m.GENERATOR * m.CURVE_ORDER).is_at_infinity())
        self.assertFalse((m.GENERATOR * (m.CURVE_ORDER - 1)).is_at_infinity())

    def test_known_secp256k1_constants(self):
        self.assertEqual(m.CURVE_A, 0)
        self.assertEqual(m.CURVE_B, 7)
        self.assertEqual(m.CURVE_P % 4, 3)   # lets modular_sqrt take the fast path
        self.assertEqual(m.CURVE_ORDER.bit_length(), 256)


class TestInverseMod(unittest.TestCase):

    def test_randomized(self):
        rng = random.Random(20260910)
        for _ in range(200):
            a = rng.randrange(1, m.CURVE_P)
            self.assertEqual((a * m.inverse_mod(a, m.CURVE_P)) % m.CURVE_P, 1)
            b = rng.randrange(1, m.CURVE_ORDER)
            self.assertEqual((b * m.inverse_mod(b, m.CURVE_ORDER)) % m.CURVE_ORDER, 1)

    def test_zero_has_no_inverse(self):
        with self.assertRaises(ZeroDivisionError):
            m.inverse_mod(0, m.CURVE_P)

    def test_non_coprime_has_no_inverse(self):
        with self.assertRaises(ZeroDivisionError):
            m.inverse_mod(4, 8)


class TestPointArithmetic(unittest.TestCase):

    def test_scalar_mult_matches_frozen_pubkey(self):
        scalar = m.string_to_number(v.PRIV_A)
        self.assertEqual(m.point_to_ser(m.GENERATOR * scalar, False),
                         v.PUB_A_UNCOMPRESSED)

    def test_addition_is_commutative_and_associative(self):
        a = m.ser_to_point_obj(v.PUB_A_UNCOMPRESSED)
        b = m.ser_to_point_obj(v.PUB_B_UNCOMPRESSED)
        g = m.GENERATOR
        self.assertEqual(a + b, b + a)
        self.assertEqual((a + b) + g, a + (b + g))

    def test_infinity_is_the_identity(self):
        a = m.ser_to_point_obj(v.PUB_A_UNCOMPRESSED)
        self.assertEqual(a + m.INFINITY, a)
        self.assertEqual(m.INFINITY + a, a)
        self.assertTrue((a * 0).is_at_infinity())
        self.assertTrue((m.INFINITY * 5).is_at_infinity())

    def test_negation(self):
        a = m.ser_to_point_obj(v.PUB_A_UNCOMPRESSED)
        self.assertTrue((a + (-a)).is_at_infinity())
        self.assertEqual(-(-a), a)

    def test_doubling_agrees_with_addition(self):
        a = m.ser_to_point_obj(v.PUB_A_UNCOMPRESSED)
        self.assertEqual(a + a, a * 2)
        self.assertEqual(a * 3, a + a + a)

    def test_negative_and_reduced_scalars(self):
        a = m.ser_to_point_obj(v.PUB_A_UNCOMPRESSED)
        self.assertEqual(a * -1, -a)
        self.assertEqual(a * (m.CURVE_ORDER + 7), a * 7)

    def test_rejects_point_off_curve(self):
        x, y = m.ser_to_point(v.PUB_A_UNCOMPRESSED)
        with self.assertRaises(m.InvalidECPointException):
            m.Point(x, (y + 1) % m.CURVE_P)

    def test_contains_point_bounds(self):
        self.assertFalse(m.contains_point(None, None))
        self.assertFalse(m.contains_point(m.CURVE_P, 1))
        self.assertFalse(m.contains_point(-1, 1))


class TestSerialization(unittest.TestCase):

    def test_roundtrips(self):
        for ser in (v.PUB_A_UNCOMPRESSED, v.PUB_B_UNCOMPRESSED):
            point = m.ser_to_point_obj(ser)
            self.assertEqual(m.point_to_ser(point, False), ser)
        self.assertEqual(
            m.point_to_ser(m.ser_to_point_obj(v.PUB_A_COMPRESSED), True),
            v.PUB_A_COMPRESSED)

    def test_compressed_and_uncompressed_describe_the_same_point(self):
        self.assertEqual(m.ser_to_point(v.PUB_A_COMPRESSED),
                         m.ser_to_point(v.PUB_A_UNCOMPRESSED))

    def test_point_to_ser_accepts_tuple(self):
        xy = m.ser_to_point(v.PUB_A_UNCOMPRESSED)
        self.assertEqual(m.point_to_ser(xy, False), v.PUB_A_UNCOMPRESSED)

    def test_infinity_serializes_to_none(self):
        self.assertIsNone(m.point_to_ser(m.INFINITY))

    def test_rejects_malformed_encodings(self):
        cases = [
            b"",                                  # empty
            b"\x04",                              # prefix only
            b"\x05" + bytes(64),                  # bad prefix
            b"\x04" + bytes(63),                  # uncompressed too short
            b"\x04" + bytes(65),                  # uncompressed too long
            b"\x02" + bytes(31),                  # compressed too short
            b"\x02" + bytes(33),                  # compressed too long
            b"\x04" + m.CURVE_P.to_bytes(32, "big") + bytes(32),   # x == p
            b"\x04" + bytes(64),                  # (0,0) is not on the curve
        ]
        for bad in cases:
            with self.subTest(data=bad[:6].hex()):
                with self.assertRaises(Exception):
                    m.ser_to_point_obj(bad)

    def test_number_to_string_range(self):
        self.assertEqual(len(m.number_to_string(1)), 32)
        with self.assertRaises(ValueError):
            m.number_to_string(m.CURVE_ORDER)
        with self.assertRaises(ValueError):
            m.number_to_string(-1)


class TestSignatureCodecs(unittest.TestCase):

    def test_der_matches_frozen_vectors(self):
        self.assertEqual(m.decode_der(v.SIG_DER_LOWS), (v.SIG_R, v.SIG_S))
        self.assertEqual(m.encode_der(v.SIG_R, v.SIG_S), v.SIG_DER_LOWS)
        self.assertEqual(m.decode_der(v.SIG_DER_HIGHS),
                         (v.SIG_R, m.CURVE_ORDER - v.SIG_S))

    def test_compact_matches_frozen_vectors(self):
        self.assertEqual(m.decode_string(v.SIG_STRING), (v.SIG_R, v.SIG_S))
        self.assertEqual(m.encode_string(v.SIG_R, v.SIG_S), v.SIG_STRING)

    def test_der_roundtrip_randomized(self):
        rng = random.Random(7)
        for _ in range(200):
            r = rng.randrange(1, m.CURVE_ORDER)
            s = rng.randrange(1, m.CURVE_ORDER)
            self.assertEqual(m.decode_der(m.encode_der(r, s)), (r, s))
            self.assertEqual(m.decode_string(m.encode_string(r, s)), (r, s))

    def test_der_decoder_is_strict(self):
        """A permissive decoder is a signature-malleability risk."""
        cases = {
            "trailing byte": b"\x30\x06\x02\x01\x01\x02\x01\x01\x00",
            "excess zero padding": b"\x30\x06\x02\x02\x00\x01\x02\x01\x01",
            "negative integer": b"\x30\x06\x02\x01\x81\x02\x01\x01",
            "zero-length integer": b"\x30\x06\x02\x00\x02\x01\x01",
            "wrong outer tag": b"\x31\x06\x02\x01\x01\x02\x01\x01",
            "bad sequence length": b"\x30\x07\x02\x01\x01\x02\x01\x01",
            "empty": b"",
            "truncated": v.SIG_DER_LOWS[:-1],
        }
        for desc, bad in cases.items():
            with self.subTest(case=desc):
                with self.assertRaises(Exception):
                    m.decode_der(bad)

    def test_compact_decoder_rejects_wrong_length(self):
        for length in (0, 63, 65, 128):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    m.decode_string(bytes(length))

    def test_canonicalize_s(self):
        half = m.CURVE_ORDER // 2
        self.assertEqual(m.canonicalize_s(1), 1)
        self.assertEqual(m.canonicalize_s(half), half)
        self.assertEqual(m.canonicalize_s(half + 1), m.CURVE_ORDER - half - 1)
        for s in (1, half, half + 1, m.CURVE_ORDER - 1):
            c = m.canonicalize_s(s)
            self.assertLessEqual(c, half)
            self.assertEqual(m.canonicalize_s(c), c, "not idempotent")


class TestRecovery(unittest.TestCase):

    def test_matches_frozen_vectors(self):
        for recid, expected in v.RECOVERY.items():
            with self.subTest(recid=recid):
                if expected is None:
                    with self.assertRaises(Exception):
                        m.recover_pubkey(v.SIG_STRING, recid, v.DIGEST)
                else:
                    self.assertEqual(
                        m.recover_pubkey(v.SIG_STRING, recid, v.DIGEST), expected)

    def test_rejects_bad_recid(self):
        for recid in (-1, 4, 100):
            with self.subTest(recid=recid):
                with self.assertRaises(ValueError):
                    m.recover_pubkey(v.SIG_STRING, recid, v.DIGEST)

    def test_rejects_wrong_length_signature(self):
        for length in (63, 65):
            with self.subTest(length=length):
                with self.assertRaises(Exception):
                    m.recover_pubkey(bytes(length), 0, v.DIGEST)

    def test_rejects_out_of_range_r_or_s(self):
        for r, s in ((0, v.SIG_S), (v.SIG_R, 0)):
            with self.subTest(r=r, s=s):
                sig = (r.to_bytes(32, "big") + s.to_bytes(32, "big"))
                with self.assertRaises(m.InvalidECPointException):
                    m.recover_pubkey(sig, 0, v.DIGEST)


class TestSecretRangeCheck(unittest.TestCase):

    def test_accepts_valid_and_rejects_invalid(self):
        self.assertTrue(m.is_secret_within_curve_range(v.PRIV_A))
        self.assertTrue(m.is_secret_within_curve_range(1))
        self.assertTrue(m.is_secret_within_curve_range(m.CURVE_ORDER - 1))
        self.assertFalse(m.is_secret_within_curve_range(0))
        self.assertFalse(m.is_secret_within_curve_range(bytes(32)))
        self.assertFalse(m.is_secret_within_curve_range(m.CURVE_ORDER))
        self.assertFalse(m.is_secret_within_curve_range(-1))


class TestModularSqrt(unittest.TestCase):

    def test_roundtrip(self):
        rng = random.Random(11)
        for _ in range(100):
            a = rng.randrange(1, m.CURVE_P)
            sq = (a * a) % m.CURVE_P
            root = m.modular_sqrt(sq, m.CURVE_P)
            self.assertIn(root, (a, m.CURVE_P - a))

    def test_non_residue_returns_zero(self):
        non_residues = [x for x in range(2, 60)
                        if m.legendre_symbol(x, m.CURVE_P) == -1]
        self.assertTrue(non_residues, "expected to find a non-residue")
        self.assertEqual(m.modular_sqrt(non_residues[0], m.CURVE_P), 0)

    def test_y_from_x_parity(self):
        x, y = m.ser_to_point(v.PUB_A_UNCOMPRESSED)
        self.assertEqual(m.get_y_coord_from_x(x, bool(y & 1)), y)
        self.assertEqual(m.get_y_coord_from_x(x, not bool(y & 1)), m.CURVE_P - y)

    def test_y_from_x_rejects_x_not_on_curve(self):
        # x = 0 has no y on secp256k1 (y^2 = 7 is not a QR mod p)
        with self.assertRaises(m.InvalidECPointException):
            m.get_y_coord_from_x(0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
