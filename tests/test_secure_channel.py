# -*- coding: utf-8 -*-
"""Secure channel tests that do not need a smartcard (issue #8).

The ECDH handshake here is the single most wire-sensitive thing in pysatochip:
the applet derives the same shared secret on its side, so if our derivation
changes by one byte every card session breaks. A second keypair stands in for
the applet.
"""

import hashlib
import hmac
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import vectors as v
from pysatochip import ec_backend
from pysatochip.SecureChannel import SecureChannel, UninitializedSecureChannelError

BACKENDS = ec_backend.available_backends()


class SecureChannelTestCase(unittest.TestCase):

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


class TestHandshake(SecureChannelTestCase):

    def test_ephemeral_pubkey_is_uncompressed_65_bytes(self):
        """card_initiate_secure_channel() sends this as a 65-byte APDU payload."""
        for _ in self.for_each_backend():
            sc = SecureChannel()
            self.assertEqual(len(sc.sc_pubkey_serialized), 65)
            self.assertEqual(sc.sc_pubkey_serialized[0], 0x04)
            self.assertEqual(
                ec_backend.privkey_to_pubkey(sc.sc_privkey, False),
                sc.sc_pubkey_serialized)

    def test_shared_secret_agrees_with_peer(self):
        for _ in self.for_each_backend():
            card_priv, card_pub = ec_backend.generate_keypair()
            sc = SecureChannel()
            sc.initiate_secure_channel(card_pub)
            self.assertEqual(
                sc.shared_key,
                ec_backend.ecdh_shared_x(card_priv, sc.sc_pubkey_serialized))

    def test_key_derivation_is_unchanged(self):
        """hmac-sha1 over the shared secret, exactly as before the port."""
        for _ in self.for_each_backend():
            _card_priv, card_pub = ec_backend.generate_keypair()
            sc = SecureChannel()
            sc.initiate_secure_channel(card_pub)
            self.assertEqual(sc.derived_key,
                             hmac.new(sc.shared_key, b"sc_key", hashlib.sha1).digest()[:16])
            self.assertEqual(sc.mac_key,
                             hmac.new(sc.shared_key, b"sc_mac", hashlib.sha1).digest())
            self.assertEqual(len(sc.derived_key), 16)
            self.assertEqual(len(sc.mac_key), 20)
            self.assertTrue(sc.initialized_secure_channel)

    def test_each_session_uses_a_fresh_ephemeral_key(self):
        for _ in self.for_each_backend():
            keys = {SecureChannel().sc_privkey for _i in range(8)}
            self.assertEqual(len(keys), 8)

    def test_rejects_peer_pubkey_off_curve(self):
        for _ in self.for_each_backend():
            sc = SecureChannel()
            with self.assertRaises(Exception):
                sc.initiate_secure_channel(b"\x04" + bytes(64))
            self.assertFalse(sc.initialized_secure_channel)

    def test_derivation_matches_frozen_vector(self):
        """Pin the derivation against the pre-0.18.0 implementation using the
        frozen keypair, rather than a randomly generated one."""
        for _ in self.for_each_backend():
            sc = SecureChannel()
            sc.sc_privkey = v.PRIV_A
            sc.sc_pubkey_serialized = ec_backend.privkey_to_pubkey(v.PRIV_A, False)
            sc.initiate_secure_channel(v.PUB_B_UNCOMPRESSED)
            self.assertEqual(sc.shared_key, v.ECDH_SHARED_X)
            self.assertEqual(
                sc.derived_key,
                hmac.new(v.ECDH_SHARED_X, b"sc_key", hashlib.sha1).digest()[:16])


class TestEncryption(SecureChannelTestCase):

    def _channel(self):
        _priv, pub = ec_backend.generate_keypair()
        sc = SecureChannel()
        sc.initiate_secure_channel(pub)
        return sc

    def test_encrypt_decrypt_roundtrip(self):
        for _ in self.for_each_backend():
            sc = self._channel()
            for size in (0, 1, 15, 16, 17, 200):
                payload = os.urandom(size)
                iv, ciphertext, mac = sc.encrypt_secure_channel(payload)
                self.assertEqual(bytes(sc.decrypt_secure_channel(iv, ciphertext)),
                                 payload)
                self.assertEqual(len(iv), 16)
                self.assertEqual(len(mac), 20)

    def test_mac_covers_iv_and_length(self):
        for _ in self.for_each_backend():
            sc = self._channel()
            iv, ciphertext, mac = sc.encrypt_secure_channel(b"payload")
            expected = hmac.new(
                sc.mac_key,
                iv + len(ciphertext).to_bytes(2, "big") + ciphertext,
                hashlib.sha1).digest()
            self.assertEqual(mac, expected)

    def test_iv_counter_advances(self):
        for _ in self.for_each_backend():
            sc = self._channel()
            self.assertEqual(sc.sc_IVcounter, 1)
            iv1, _c, _m = sc.encrypt_secure_channel(b"a")
            self.assertEqual(sc.sc_IVcounter, 3)
            iv2, _c, _m = sc.encrypt_secure_channel(b"a")
            self.assertEqual(sc.sc_IVcounter, 5)
            self.assertNotEqual(iv1, iv2)
            # last 4 bytes of the IV carry the counter
            self.assertEqual(int.from_bytes(iv1[12:], "big"), 1)
            self.assertEqual(int.from_bytes(iv2[12:], "big"), 3)

    def test_requires_initialization(self):
        for _ in self.for_each_backend():
            sc = SecureChannel()
            with self.assertRaises(UninitializedSecureChannelError):
                sc.encrypt_secure_channel(b"x")
            with self.assertRaises(UninitializedSecureChannelError):
                sc.decrypt_secure_channel(bytes(16), bytes(16))


if __name__ == "__main__":
    print("available backends:", BACKENDS or "(none)")
    unittest.main(verbosity=2)
