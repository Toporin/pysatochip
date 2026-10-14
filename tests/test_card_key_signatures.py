# -*- coding: utf-8 -*-
"""Key material returned by the card must be signature-checked (B1.3).

Two commands returned key material with a `# todo verify signature` where the
check belonged:

  * card_bip32_get_liquid_master_blinding_key() -- a hostile or swapped card
    chose the SLIP-77 master blinding key for every confidential Liquid address
    the wallet derives from it.
  * satocash_get_bip32_extendedkey() -- the "compressed pubkey" was rebuilt from
    the card's claimed uncompressed point with no on-curve check either.

The signed message is not guesswork: both applets sign buffer[0..offset), i.e.
everything written before the signature's own length field. For the blinding key
that is getBIP32LiquidMasterBlindingKey() -> appendAuthentikeySignature() in
SatochipApplet; the double-signature layout is the same one used by
parse_initiate_secure_channel() and parse_bip32_get_extendedkey().
"""

import os
import sys
import unittest
from hashlib import sha256

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip import ec_backend
from pysatochip.CardConnector import CardConnector
from pysatochip.CardDataParser import CardDataParser
from pysatochip.ecc import ECPubkey, der_sig_from_r_and_s

AUTHENTIKEY_SECRET = bytes.fromhex('05' * 32)
ATTACKER_SECRET = bytes.fromhex('06' * 32)
EPHEMERAL_SECRET = bytes.fromhex('07' * 32)

BLINDING_KEY = list(bytes.fromhex('ab' * 32))


def der_sign(secret, payload):
    r, s = ec_backend.sign_digest(secret, sha256(bytes(payload)).digest())
    return list(der_sig_from_r_and_s(r, s))


class CardKeyTestCase(unittest.TestCase):

    def setUp(self):
        if not ec_backend.available_backends():
            self.skipTest("no hardened EC backend available")
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        self.cc.parser.authentikey = ECPubkey(
            ec_backend.privkey_to_pubkey(AUTHENTIKEY_SECRET, compressed=False))
        self.response = []
        self.cc.card_transmit = lambda apdu: (self.response, 0x90, 0x00)


class TestLiquidBlindingKey(CardKeyTestCase):
    """response = [keySize(2) | blindingKey | sigSize(2) | sig]"""

    def build(self, signer=AUTHENTIKEY_SECRET, key=None, sig_override=None):
        key = BLINDING_KEY if key is None else key
        signed = [0x00, len(key)] + key
        sig = [] if signer is None else der_sign(signer, signed)
        if sig_override is not None:
            sig = sig_override
        self.response = signed + [len(sig) >> 8, len(sig) & 0xff] + sig
        return signed

    def test_accepts_a_genuine_signature(self):
        self.build()
        self.assertEqual(
            self.cc.card_bip32_get_liquid_master_blinding_key(), BLINDING_KEY)

    def test_rejects_a_signature_from_another_key(self):
        """A swapped card would otherwise choose your Liquid blinding key."""
        self.build(signer=ATTACKER_SECRET)
        with self.assertRaises(Exception):
            self.cc.card_bip32_get_liquid_master_blinding_key()

    def test_rejects_empty_signature(self):
        self.build(signer=None)
        with self.assertRaises(ValueError):
            self.cc.card_bip32_get_liquid_master_blinding_key()

    def test_rejects_signature_over_a_different_key(self):
        """Valid signature, but for a blinding key we were not given."""
        other = list(bytes.fromhex('cd' * 32))
        good_sig = der_sign(AUTHENTIKEY_SECRET, [0x00, len(other)] + other)
        self.build(sig_override=good_sig)
        with self.assertRaises(Exception):
            self.cc.card_bip32_get_liquid_master_blinding_key()

    def test_never_returns_an_unverified_key(self):
        for name, kwargs in (("other signer", {"signer": ATTACKER_SECRET}),
                             ("no signature", {"signer": None}),
                             ("garbage", {"sig_override": list(range(71))})):
            with self.subTest(case=name):
                self.build(**kwargs)
                try:
                    key = self.cc.card_bip32_get_liquid_master_blinding_key()
                except Exception:
                    continue
                self.fail("returned blinding key %s unverified" % bytes(key).hex())


class TestSatocashExtendedKey(CardKeyTestCase):
    """response = [counter(4) | pubkey(65) | sig_size(2) | self-sig
                   | sig2_size(2) | authentikey-sig]"""

    COUNTER = [0x00, 0x00, 0x00, 0x2a]

    def build(self, signer=AUTHENTIKEY_SECRET, pubkey=None):
        if pubkey is None:
            pubkey = list(ec_backend.privkey_to_pubkey(
                EPHEMERAL_SECRET, compressed=False))
        msg = self.COUNTER + pubkey
        self_sig = der_sign(EPHEMERAL_SECRET, msg)
        msg2 = msg + [len(self_sig) >> 8, len(self_sig) & 0xff] + self_sig
        sig2 = [] if signer is None else der_sign(signer, msg2)
        self.response = msg2 + [len(sig2) >> 8, len(sig2) & 0xff] + sig2

    def test_accepts_a_genuine_signature(self):
        self.build()
        counter, pubkey_comp = self.cc.satocash_get_bip32_extendedkey()
        self.assertEqual(counter, bytes(self.COUNTER))
        self.assertEqual(len(pubkey_comp), 33)
        self.assertIn(pubkey_comp[0], (0x02, 0x03))

    def test_compressed_form_matches_the_backend(self):
        self.build()
        _, pubkey_comp = self.cc.satocash_get_bip32_extendedkey()
        self.assertEqual(
            pubkey_comp,
            ec_backend.privkey_to_pubkey(EPHEMERAL_SECRET, compressed=True))

    def test_rejects_a_signature_from_another_key(self):
        self.build(signer=ATTACKER_SECRET)
        with self.assertRaises(Exception):
            self.cc.satocash_get_bip32_extendedkey()

    def test_rejects_empty_authentikey_signature(self):
        """A card choosing sig2_size=0 must not skip the only real check."""
        self.build(signer=None)
        with self.assertRaises(ValueError):
            self.cc.satocash_get_bip32_extendedkey()

    def test_rejects_an_off_curve_pubkey(self):
        """Compression keeps only x, so a bad y would go unnoticed."""
        self.build(pubkey=[0x04] + [0x11] * 64)
        with self.assertRaises(Exception):
            self.cc.satocash_get_bip32_extendedkey()

    def test_rejects_a_truncated_response(self):
        self.build()
        for cut in (0, 10, 60, 72):
            with self.subTest(length=cut):
                full = self.response
                self.response = full[:cut]
                with self.assertRaises(Exception):
                    self.cc.satocash_get_bip32_extendedkey()
                self.response = full


if __name__ == "__main__":
    unittest.main(verbosity=2)
