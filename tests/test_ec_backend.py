# -*- coding: utf-8 -*-
"""Regression tests for the side-channel-hardened EC backends (issue #8).

These run without a smartcard. The vectors in vectors.py were captured from the
pre-0.18.0 `ecdsa` implementation, so every assertion here is a compatibility
check against the code this replaced -- most importantly ECDH_SHARED_X, which
fixes the card secure-channel wire format.

Every test is parametrized over each backend actually available in the
environment, so CI on a desktop exercises cryptography while an embedded build
exercises libsecp256k1.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import vectors as v
from pysatochip import ec_backend, ec_math

BACKENDS = ec_backend.available_backends()


class ECBackendTestCase(unittest.TestCase):
    """Base class that runs each test once per available backend."""

    def setUp(self):
        self._saved_backend = ec_backend.BACKEND

    def tearDown(self):
        ec_backend.BACKEND = self._saved_backend

    def for_each_backend(self):
        if not BACKENDS:
            self.skipTest("no hardened EC backend available")
        for backend in BACKENDS:
            ec_backend.set_backend(backend)
            with self.subTest(backend=backend):
                yield backend


class TestECDH(ECBackendTestCase):
    """ECDH is the wire-format-critical path: the secure channel and the
    SeedKeeper encrypted export both derive their AES/MAC keys from it."""

    def test_shared_secret_matches_frozen_vector(self):
        for _ in self.for_each_backend():
            self.assertEqual(
                ec_backend.ecdh_shared_x(v.PRIV_A, v.PUB_B_UNCOMPRESSED),
                v.ECDH_SHARED_X)

    def test_shared_secret_is_symmetric(self):
        for _ in self.for_each_backend():
            self.assertEqual(
                ec_backend.ecdh_shared_x(v.PRIV_B, v.PUB_A_UNCOMPRESSED),
                v.ECDH_SHARED_X)

    def test_accepts_compressed_peer_pubkey(self):
        for _ in self.for_each_backend():
            self.assertEqual(
                ec_backend.ecdh_shared_x(v.PRIV_A, v.PUB_B_COMPRESSED),
                v.ECDH_SHARED_X)

    def test_rejects_point_not_on_curve(self):
        for _ in self.for_each_backend():
            with self.assertRaises(ec_math.InvalidECPointException):
                ec_backend.ecdh_shared_x(v.PRIV_A, b"\x04" + bytes(64))

    def test_rejects_out_of_range_privkey(self):
        for _ in self.for_each_backend():
            with self.assertRaises(ec_math.InvalidECPointException):
                ec_backend.ecdh_shared_x(bytes(32), v.PUB_B_UNCOMPRESSED)


class TestKeyDerivation(ECBackendTestCase):

    def test_privkey_to_pubkey_matches_frozen_vectors(self):
        for _ in self.for_each_backend():
            self.assertEqual(
                ec_backend.privkey_to_pubkey(v.PRIV_A, False), v.PUB_A_UNCOMPRESSED)
            self.assertEqual(
                ec_backend.privkey_to_pubkey(v.PRIV_A, True), v.PUB_A_COMPRESSED)
            self.assertEqual(
                ec_backend.privkey_to_pubkey(v.PRIV_B, False), v.PUB_B_UNCOMPRESSED)
            self.assertEqual(
                ec_backend.privkey_to_pubkey(v.PRIV_B, True), v.PUB_B_COMPRESSED)

    def test_rejects_wrong_length_privkey(self):
        for _ in self.for_each_backend():
            with self.assertRaises(ValueError):
                ec_backend.privkey_to_pubkey(b"\x01" * 31)

    def test_generate_keypair_is_self_consistent(self):
        for _ in self.for_each_backend():
            priv, pub = ec_backend.generate_keypair()
            self.assertEqual(len(priv), 32)
            self.assertEqual(len(pub), 65)
            self.assertEqual(pub[0], 0x04)
            self.assertTrue(ec_math.is_secret_within_curve_range(priv))
            self.assertEqual(ec_backend.privkey_to_pubkey(priv, False), pub)

    def test_generate_keypair_does_not_repeat(self):
        for _ in self.for_each_backend():
            keys = {ec_backend.generate_keypair()[0] for _i in range(16)}
            self.assertEqual(len(keys), 16)


class TestVerification(ECBackendTestCase):

    def test_verifies_signature_from_old_implementation(self):
        for _ in self.for_each_backend():
            self.assertTrue(ec_backend.verify_digest(
                v.PUB_A_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST))

    def test_accepts_high_s_signature(self):
        """libsecp256k1 rejects high-S by policy; ec_backend must normalize
        first, since certificate authorities are not bound by the low-S rule."""
        for _ in self.for_each_backend():
            self.assertTrue(ec_backend.verify_digest(
                v.PUB_A_UNCOMPRESSED, v.SIG_DER_HIGHS, v.DIGEST))

    def test_rejects_wrong_pubkey(self):
        for _ in self.for_each_backend():
            self.assertFalse(ec_backend.verify_digest(
                v.PUB_B_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST))

    def test_rejects_tampered_digest(self):
        for _ in self.for_each_backend():
            bad = bytearray(v.DIGEST); bad[0] ^= 0x01
            self.assertFalse(ec_backend.verify_digest(
                v.PUB_A_UNCOMPRESSED, v.SIG_DER_LOWS, bytes(bad)))

    def test_rejects_malformed_der(self):
        for _ in self.for_each_backend():
            self.assertFalse(ec_backend.verify_digest(
                v.PUB_A_UNCOMPRESSED, b"\x30\x00", v.DIGEST))

    def test_sha512_over_secp256k1(self):
        """The subCA -> device certificate link. libsecp256k1 takes a 32-byte
        hash, so the SHA-512 digest must be truncated to its leftmost 32 bytes."""
        for _ in self.for_each_backend():
            self.assertTrue(ec_backend.verify_message(
                v.PUB_A_UNCOMPRESSED, v.SHA512_MSG, v.SHA512_SIG_DER, "sha512"))
            self.assertFalse(ec_backend.verify_message(
                v.PUB_B_UNCOMPRESSED, v.SHA512_MSG, v.SHA512_SIG_DER, "sha512"))

    def test_pure_python_verifier_agrees(self):
        """The no-backend fallback must reach the same verdicts."""
        pure = ec_backend._verify_digest_pure
        self.assertTrue(pure(v.PUB_A_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST))
        self.assertTrue(pure(v.PUB_A_UNCOMPRESSED, v.SIG_DER_HIGHS, v.DIGEST))
        self.assertFalse(pure(v.PUB_B_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST))
        self.assertTrue(pure(v.PUB_A_UNCOMPRESSED, v.SHA512_SIG_DER,
                             hashlib.sha512(v.SHA512_MSG).digest()))


class TestSigning(ECBackendTestCase):

    def test_sign_verify_roundtrip(self):
        for _ in self.for_each_backend():
            r, s = ec_backend.sign_digest(v.PRIV_A, v.DIGEST)
            self.assertTrue(ec_backend.verify_digest(
                v.PUB_A_UNCOMPRESSED, ec_math.encode_der(r, s), v.DIGEST))

    def test_signature_is_low_s(self):
        for _ in self.for_each_backend():
            for _i in range(8):
                _r, s = ec_backend.sign_digest(v.PRIV_A, os.urandom(32))
                self.assertLessEqual(s, ec_math.CURVE_ORDER // 2)

    def test_signature_does_not_verify_under_other_key(self):
        for _ in self.for_each_backend():
            r, s = ec_backend.sign_digest(v.PRIV_A, v.DIGEST)
            self.assertFalse(ec_backend.verify_digest(
                v.PUB_B_UNCOMPRESSED, ec_math.encode_der(r, s), v.DIGEST))


class TestRecovery(ECBackendTestCase):
    """pyca/cryptography has no recovery API, so this is ec_math's pure-python
    implementation there and libsecp256k1's secp256k1_ecdsa_recover on embit."""

    def test_matches_frozen_vectors_for_every_recid(self):
        for _ in self.for_each_backend():
            for recid, expected in v.RECOVERY.items():
                if expected is None:
                    with self.assertRaises(Exception):
                        ec_backend.recover_pubkey(v.SIG_STRING, recid, v.DIGEST)
                else:
                    self.assertEqual(
                        ec_backend.recover_pubkey(v.SIG_STRING, recid, v.DIGEST),
                        expected)

    def test_recovers_freshly_signed_message(self):
        for _ in self.for_each_backend():
            digest = hashlib.sha256(b"recover me").digest()
            r, s = ec_backend.sign_digest(v.PRIV_A, digest)
            sig_string = ec_math.encode_string(r, s)
            found = []
            for recid in range(4):
                try:
                    if ec_backend.recover_pubkey(sig_string, recid, digest) == \
                            v.PUB_A_UNCOMPRESSED:
                        found.append(recid)
                except Exception:
                    continue
            self.assertTrue(found, "no recid recovered the signing key")

    def test_rejects_out_of_range_recid(self):
        for _ in self.for_each_backend():
            for recid in (-1, 4):
                with self.assertRaises(ValueError):
                    ec_backend.recover_pubkey(v.SIG_STRING, recid, v.DIGEST)


class TestCrossBackendAgreement(unittest.TestCase):
    """Where both backends exist, they must produce identical results."""

    def setUp(self):
        if len(BACKENDS) < 2:
            self.skipTest("needs both cryptography and embit")
        self._saved = ec_backend.BACKEND

    def tearDown(self):
        ec_backend.BACKEND = self._saved

    def _per_backend(self, fn):
        results = []
        for backend in BACKENDS:
            ec_backend.set_backend(backend)
            results.append(fn())
        return results

    def test_ecdh_agrees(self):
        out = self._per_backend(
            lambda: ec_backend.ecdh_shared_x(v.PRIV_A, v.PUB_B_UNCOMPRESSED))
        self.assertEqual(len(set(out)), 1)
        self.assertEqual(out[0], v.ECDH_SHARED_X)

    def test_pubkey_derivation_agrees(self):
        out = self._per_backend(
            lambda: ec_backend.privkey_to_pubkey(v.PRIV_A, False))
        self.assertEqual(len(set(out)), 1)

    def test_recovery_agrees(self):
        out = self._per_backend(
            lambda: ec_backend.recover_pubkey(v.SIG_STRING, v.RECID_FOR_PUB_A, v.DIGEST))
        self.assertEqual(len(set(out)), 1)

    def test_signatures_are_cross_verifiable(self):
        """Nonces differ between backends, but each must verify the other's
        signature."""
        sigs = self._per_backend(
            lambda: ec_math.encode_der(*ec_backend.sign_digest(v.PRIV_A, v.DIGEST)))
        for backend in BACKENDS:
            ec_backend.set_backend(backend)
            for sig in sigs:
                self.assertTrue(ec_backend.verify_digest(
                    v.PUB_A_UNCOMPRESSED, sig, v.DIGEST))


class TestNoBackend(unittest.TestCase):
    """With no hardened backend, private-key operations must fail loudly rather
    than silently using a vulnerable implementation."""

    def setUp(self):
        self._saved = ec_backend.BACKEND
        ec_backend.BACKEND = None

    def tearDown(self):
        ec_backend.BACKEND = self._saved

    def test_private_key_operations_raise(self):
        with self.assertRaises(ec_backend.NoECBackendError):
            ec_backend.generate_keypair()
        with self.assertRaises(ec_backend.NoECBackendError):
            ec_backend.privkey_to_pubkey(v.PRIV_A)
        with self.assertRaises(ec_backend.NoECBackendError):
            ec_backend.ecdh_shared_x(v.PRIV_A, v.PUB_B_UNCOMPRESSED)
        with self.assertRaises(ec_backend.NoECBackendError):
            ec_backend.sign_digest(v.PRIV_A, v.DIGEST)

    def test_verification_still_works(self):
        self.assertTrue(ec_backend.verify_digest(
            v.PUB_A_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST))
        self.assertFalse(ec_backend.verify_digest(
            v.PUB_B_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST))

    def test_recovery_still_works(self):
        self.assertEqual(
            ec_backend.recover_pubkey(v.SIG_STRING, v.RECID_FOR_PUB_A, v.DIGEST),
            v.PUB_A_UNCOMPRESSED)

    def test_set_backend_rejects_unknown(self):
        with self.assertRaises(ValueError):
            ec_backend.set_backend("libsodium")


class TestNoEcdsaDependency(unittest.TestCase):

    def test_ecdsa_is_not_imported(self):
        """Importing pysatochip must not pull in the ecdsa package, even when
        it happens to be installed in the environment."""
        for name in list(sys.modules):
            if name == "ecdsa" or name.startswith("ecdsa."):
                del sys.modules[name]
        import pysatochip.CardConnector  # noqa: F401
        import pysatochip.ecc  # noqa: F401
        import pysatochip.SecureChannel  # noqa: F401
        import pysatochip.certificate_validator  # noqa: F401
        leaked = [n for n in sys.modules if n == "ecdsa" or n.startswith("ecdsa.")]
        self.assertEqual(leaked, [], "pysatochip still imports ecdsa: %s" % leaked)


if __name__ == "__main__":
    print("available backends:", BACKENDS or "(none)")
    unittest.main(verbosity=2)
