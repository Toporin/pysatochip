# -*- coding: utf-8 -*-
"""Regression tests for the AES backends used by the card secure channel.

pyaes (pure-python, table-driven, cache-timing observable) was demoted to a
last-resort fallback behind cryptography and pycryptodomex. The wire format is
fixed by the applet, so the critical property is that every backend produces
*byte-identical* ciphertext -- a frozen vector pins that, exactly as
vectors.ECDH_SHARED_X pins the handshake.

Every test is parametrized over each backend actually available in the
environment.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip import aes_backend

BACKENDS = aes_backend.available_backends()

# Frozen AES-128-CBC + PKCS#7 vector, captured from the pre-0.18.5 pyaes code
# path (pyaes.Encrypter with PADDING_DEFAULT). It therefore pins backward
# compatibility with every card session in the field, not merely self
# consistency: if a backend swap changes this, the secure channel has silently
# become incompatible with the applet.
KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
IV = bytes.fromhex('101112131415161718191a1b1c1d1e1f')
PLAINTEXT = bytes.fromhex('b0a40000')  # a short C-APDU header
CIPHERTEXT = bytes.fromhex('6458e03c5f21bb8504164d62f8204051')


class AESBackendTestCase(unittest.TestCase):
    """Base class that runs each test once per available backend."""

    def setUp(self):
        self._saved_backend = aes_backend.BACKEND

    def tearDown(self):
        aes_backend.BACKEND = self._saved_backend

    def for_each_backend(self):
        if not BACKENDS:
            self.skipTest("no AES backend available")
        for backend in BACKENDS:
            aes_backend.set_backend(backend)
            with self.subTest(backend=backend):
                yield backend


class TestWireFormat(AESBackendTestCase):

    def test_matches_frozen_vector(self):
        """The applet decrypts this on its side; it must not move."""
        for _ in self.for_each_backend():
            self.assertEqual(aes_backend.cbc_encrypt(KEY, IV, PLAINTEXT), CIPHERTEXT)

    def test_decrypts_frozen_vector(self):
        for _ in self.for_each_backend():
            self.assertEqual(aes_backend.cbc_decrypt(KEY, IV, CIPHERTEXT), PLAINTEXT)

    def test_all_backends_agree(self):
        if len(BACKENDS) < 2:
            self.skipTest("need at least two AES backends to cross-check")
        key, iv = os.urandom(16), os.urandom(16)
        for size in (0, 1, 15, 16, 17, 64, 255):
            plaintext = os.urandom(size)
            results = []
            for backend in BACKENDS:
                aes_backend.set_backend(backend)
                results.append(aes_backend.cbc_encrypt(key, iv, plaintext))
            self.assertEqual(len(set(results)), 1,
                             "backends disagree for plaintext of %d bytes" % size)

    def test_roundtrip(self):
        for _ in self.for_each_backend():
            key, iv = os.urandom(16), os.urandom(16)
            for size in (0, 1, 15, 16, 17, 1000):
                plaintext = os.urandom(size)
                ct = aes_backend.cbc_encrypt(key, iv, plaintext)
                self.assertEqual(len(ct) % aes_backend.AES_BLOCK_SIZE, 0)
                self.assertEqual(aes_backend.cbc_decrypt(key, iv, ct), plaintext)


class TestPadding(AESBackendTestCase):
    """pyaes's PADDING_DEFAULT only checked `pad <= 16`, so a trailing 0x00
    silently decoded to b'' and the pad bytes themselves were never compared.
    On a channel whose responses carry no MAC that is a silent-truncation
    primitive; all backends must now reject it."""

    def test_pad_is_always_added(self):
        self.assertEqual(aes_backend.pkcs7_pad(b''), bytes([16]) * 16)
        self.assertEqual(aes_backend.pkcs7_pad(b'A' * 16), b'A' * 16 + bytes([16]) * 16)
        self.assertEqual(aes_backend.pkcs7_pad(b'A' * 15), b'A' * 15 + b'\x01')

    def test_rejects_zero_pad_byte(self):
        with self.assertRaises(aes_backend.InvalidPaddingError):
            aes_backend.pkcs7_unpad(b'A' * 15 + b'\x00')

    def test_rejects_inconsistent_padding(self):
        with self.assertRaises(aes_backend.InvalidPaddingError):
            aes_backend.pkcs7_unpad(b'A' * 13 + b'\x09\x09\x03')

    def test_rejects_oversized_pad_byte(self):
        with self.assertRaises(aes_backend.InvalidPaddingError):
            aes_backend.pkcs7_unpad(b'A' * 15 + bytes([17]))

    def test_rejects_empty_and_misaligned(self):
        for bad in (b'', b'A' * 15, b'A' * 17):
            with self.assertRaises(aes_backend.InvalidPaddingError):
                aes_backend.pkcs7_unpad(bad)

    def test_decrypt_rejects_misaligned_ciphertext(self):
        for _ in self.for_each_backend():
            with self.assertRaises(aes_backend.InvalidPaddingError):
                aes_backend.cbc_decrypt(KEY, IV, b'\x00' * 17)
            with self.assertRaises(aes_backend.InvalidPaddingError):
                aes_backend.cbc_decrypt(KEY, IV, b'')


class TestArgumentValidation(AESBackendTestCase):

    def test_rejects_bad_key_length(self):
        for _ in self.for_each_backend():
            with self.assertRaises(ValueError):
                aes_backend.cbc_encrypt(b'\x00' * 15, IV, b'x')

    def test_rejects_bad_iv_length(self):
        for _ in self.for_each_backend():
            with self.assertRaises(ValueError):
                aes_backend.cbc_encrypt(KEY, b'\x00' * 12, b'x')


class TestBackendSelection(AESBackendTestCase):

    def test_prefers_hardened_backend_over_pyaes(self):
        """pyaes must never be chosen while a hardened backend is importable."""
        aes_backend.set_backend("auto")
        if aes_backend.HAS_CRYPTOGRAPHY:
            self.assertEqual(aes_backend.BACKEND, aes_backend.BACKEND_CRYPTOGRAPHY)
        elif aes_backend.HAS_PYCRYPTODOMEX:
            self.assertEqual(aes_backend.BACKEND, aes_backend.BACKEND_PYCRYPTODOMEX)

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ValueError):
            aes_backend.set_backend("rot13")


if __name__ == "__main__":
    unittest.main(verbosity=2)
