# -*- coding: utf-8 -*-
"""get_trusted_pubkey() must fail closed (audit finding B1.1).

The card's authentikey signature is the only thing binding the trusted pubkey
to that card, and the trusted pubkey is what a secure secret import
(SeedKeeper -> Satochip) encrypts a seed to. Before 0.18.5 the verification
result was caught, logged and discarded:

    try:
        self.verify_signature(data, sig, self.authentikey)
    except Exception as ex:
        logger.error('Exception in get_trusted_pubkey: ' + str(ex))
    return pubkey_hex          # returned even when verification FAILED

so a substituted key was accepted and reported to the user as imported. These
tests build real signatures with real keys rather than mocking verification, so
they exercise the actual recovery path.
"""

import os
import sys
import unittest
from hashlib import sha256

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardDataParser import CardDataParser
from pysatochip.ecc import ECPubkey, der_sig_from_r_and_s
from pysatochip import ec_backend

# deterministic test keys -- test-only values, never use on a device
AUTHENTIKEY_SECRET = bytes.fromhex(
    '0101010101010101010101010101010101010101010101010101010101010101')
ATTACKER_SECRET = bytes.fromhex(
    '0202020202020202020202020202020202020202020202020202020202020202')
TRUSTED_PUBKEY = bytes.fromhex(
    '04' + 'a1' * 32 + 'b2' * 32)           # opaque 65-byte payload


def build_response(pubkey_bytes, signer_privkey, sig_size_override=None):
    """Build the card response: [pubkey_size(2) | pubkey(65) | sig_size(2) | sig]

    The signature covers `pubkey_size || pubkey`, exactly as verify_signature()
    recomputes it.
    """
    payload = [len(pubkey_bytes) >> 8, len(pubkey_bytes) & 0xff] + list(pubkey_bytes)
    if signer_privkey is None:
        sig = []
    else:
        digest = sha256(bytes(payload)).digest()
        r, s = ec_backend.sign_digest(signer_privkey, digest)
        sig = list(der_sig_from_r_and_s(r, s))
    size = len(sig) if sig_size_override is None else sig_size_override
    return payload + [size >> 8, size & 0xff] + sig


class TrustedPubkeyTestCase(unittest.TestCase):

    def setUp(self):
        if not ec_backend.available_backends():
            self.skipTest("no hardened EC backend available")
        self.parser = CardDataParser()
        self.authentikey_priv = AUTHENTIKEY_SECRET
        self.parser.authentikey = ECPubkey(
            ec_backend.privkey_to_pubkey(AUTHENTIKEY_SECRET, compressed=False))


class TestAcceptsGenuine(TrustedPubkeyTestCase):

    def test_accepts_pubkey_signed_by_the_authentikey(self):
        response = build_response(TRUSTED_PUBKEY, self.authentikey_priv)
        self.assertEqual(self.parser.get_trusted_pubkey(response),
                         TRUSTED_PUBKEY.hex())


class TestRejectsForged(TrustedPubkeyTestCase):
    """Each of these returned an attacker-chosen pubkey before the fix."""

    def test_rejects_pubkey_signed_by_another_key(self):
        """The key-substitution attack: a seed would be exported to it."""
        response = build_response(TRUSTED_PUBKEY, ATTACKER_SECRET)
        with self.assertRaises(ValueError):
            self.parser.get_trusted_pubkey(response)

    def test_rejects_empty_signature(self):
        """The card picks sig_size; 0 must not skip verification."""
        response = build_response(TRUSTED_PUBKEY, None)
        with self.assertRaises(ValueError):
            self.parser.get_trusted_pubkey(response)

    def test_rejects_garbage_signature(self):
        response = build_response(TRUSTED_PUBKEY, self.authentikey_priv)
        response[-1] ^= 0xff
        with self.assertRaises(Exception):
            self.parser.get_trusted_pubkey(response)

    def test_rejects_signature_over_a_different_pubkey(self):
        """Signature is valid, but for another payload."""
        genuine = build_response(TRUSTED_PUBKEY, self.authentikey_priv)
        other = bytes.fromhex('04' + 'cc' * 32 + 'dd' * 32)
        sig_start = 2 + 65 + 2
        forged = ([len(other) >> 8, len(other) & 0xff] + list(other)
                  + genuine[2 + 65:sig_start] + genuine[sig_start:])
        with self.assertRaises(Exception):
            self.parser.get_trusted_pubkey(forged)

    def test_rejects_truncated_signature(self):
        """sig_size larger than the bytes present: slicing silently truncates."""
        response = build_response(TRUSTED_PUBKEY, self.authentikey_priv)
        response = response[:-10]
        with self.assertRaises(Exception):
            self.parser.get_trusted_pubkey(response)

    def test_rejects_when_authentikey_is_not_set(self):
        """Previously an AttributeError from the debug log, before any check."""
        self.parser.authentikey = None
        response = build_response(TRUSTED_PUBKEY, self.authentikey_priv)
        with self.assertRaises(ValueError):
            self.parser.get_trusted_pubkey(response)

    def test_rejects_wrong_pubkey_size(self):
        response = build_response(TRUSTED_PUBKEY[:33], self.authentikey_priv)
        with self.assertRaises(RuntimeError):
            self.parser.get_trusted_pubkey(response)

    def test_never_returns_a_value_on_failure(self):
        """The regression itself: no failure path may return a pubkey."""
        for name, response in (
                ("other signer", build_response(TRUSTED_PUBKEY, ATTACKER_SECRET)),
                ("empty sig", build_response(TRUSTED_PUBKEY, None)),
        ):
            with self.subTest(case=name):
                try:
                    result = self.parser.get_trusted_pubkey(response)
                except Exception:
                    continue
                self.fail("returned %r instead of raising" % result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
