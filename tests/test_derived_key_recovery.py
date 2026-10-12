# -*- coding: utf-8 -*-
"""Recovery of the transient derived keys, without a smartcard.

Since applet v0.16-0.0, the BIP32 extended key (keynbr 0xFF) and the taproot tweaked key
are cleared on deselect and card reset. card_transmit() silently reopens the secure channel
and verifies the cached PIN, but the signing command then fails with 0x9C13: CardConnector
replays the last derivation (and tweak) and resends the command, but only if the card gives
back the same public key. A fake card stands in for the applet: it signs with the key it
holds, so that each test can check which key was used.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

try:
    from pysatochip.CardConnector import CardConnector
    from pysatochip.CardDataParser import CardDataParser
except ImportError as e: # pyscard is not installed
    CardConnector = None
    IMPORT_ERROR = e

SW_OK = (0x90, 0x00)
SW_INCORRECT_INITIALIZATION = (0x9C, 0x13)
PATH_A = "m/86'/0'/0'/0/0"
PATH_B = "m/84'/0'/0'/0/0"


def h(*parts):
    return hashlib.sha256(b"|".join(parts)).digest()


class FakePubkey:
    def __init__(self, data):
        self.data = data

    def get_public_key_bytes(self, compressed=True):
        return self.data


class FakeCard:
    """Applet state: the seed, and the transient derived keys."""

    def __init__(self):
        self.seed = b"seed 1"
        self.bip32_key = None # derivation path (bytes) of the extended key
        self.tweaked_key = None
        self.log = [] # INS of each apdu received
        self.seeded = True

    def reset(self):
        """Deselect or card reset: the transient keys are cleared."""
        self.bip32_key = None
        self.tweaked_key = None

    def transmit(self, apdu):
        ins, p1, data = apdu[1], apdu[2], bytes(apdu[5:])
        self.log.append(ins)
        if ins == 0x6D: # GetBIP32ExtendedKey
            if not self.seeded:
                return [], 0x9C, 0x14
            self.bip32_key = h(self.seed, data)
            # [chaincode(32b) | 0x00 | pubkey(33b)], parsed by fake_parse_extendedkey()
            return list(h(b"chaincode", self.bip32_key)) + [0x00] + list(h(b"pub", self.bip32_key)), 0x90, 0x00
        if ins == 0x7C: # TaprootTweakPrivateKey
            if p1 == 0xFF and self.bip32_key is None:
                return [], 0x9C, 0x13
            source = self.bip32_key if p1 == 0xFF else b"keyslot %d" % p1
            self.tweaked_key = h(b"tweak", source, data)
            # [pubkey_size(2b) | pubkey(65b) | sig_size(2b) | sig], the authentikey sig is random
            return [0x00, 0x41] + list(h(b"pub", self.tweaked_key)) + [0] * 33 + [0x00, 0x08] + list(os.urandom(8)), 0x90, 0x00
        if ins == 0x7A: # SignTransactionHash
            key = self.bip32_key if p1 == 0xFF else b"keyslot %d" % p1
            if key is None:
                return [], 0x9C, 0x13
            return list(h(b"ecdsa", key, data[:32])), 0x90, 0x00
        if ins == 0x7B: # SignSchnorrHash
            if self.tweaked_key is None:
                return [], 0x9C, 0x13
            return list(h(b"schnorr", self.tweaked_key, data[:32])), 0x90, 0x00
        raise AssertionError("unexpected INS %#x" % ins)


@unittest.skipIf(CardConnector is None, "pyscard is not installed")
class TestDerivedKeyRecovery(unittest.TestCase):

    def setUp(self):
        self.card = FakeCard()
        # no card reader: skip __init__, and set the attributes used by the tested methods
        cc = CardConnector.__new__(CardConnector)
        cc.parser = CardDataParser()
        cc.parser.authentikey = object() # skip card_bip32_get_authentikey()
        cc.parser.parse_bip32_get_extendedkey = lambda r: (FakePubkey(bytes(r[33:65])), bytearray(r[0:32]))
        cc._last_bip32_derivation = None
        cc._last_taproot_tweak = None
        cc.card_transmit = self.card.transmit
        self.cc = cc
        self.hash = list(h(b"tx hash"))

    def expected_ecdsa(self, path):
        (depth, path_bytes) = self.cc.parser.bip32path2bytes(path)
        return list(h(b"ecdsa", h(self.card.seed, bytes(path_bytes)), bytes(self.hash)))

    def test_sign_after_reset_derives_again(self):
        self.cc.card_bip32_get_extendedkey(PATH_A)
        self.card.reset()
        response, sw1, sw2 = self.cc.card_sign_transaction_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_OK)
        self.assertEqual(response, self.expected_ecdsa(PATH_A))
        self.assertEqual(self.card.log, [0x6D, 0x7A, 0x6D, 0x7A])

    def test_no_derivation_returns_the_error(self):
        response, sw1, sw2 = self.cc.card_sign_transaction_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_INCORRECT_INITIALIZATION)
        self.assertEqual(self.card.log, [0x7A])

    def test_other_seed_is_not_used(self):
        # e.g. another card in the reader, or a seed reset and import by another application
        self.cc.card_bip32_get_extendedkey(PATH_A)
        self.card.seed = b"seed 2"
        self.card.reset()
        response, sw1, sw2 = self.cc.card_sign_transaction_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_INCORRECT_INITIALIZATION)
        self.assertEqual(self.card.log, [0x6D, 0x7A, 0x6D], "the hash must not be signed again")

    def test_failed_derivation_returns_the_error(self):
        self.cc.card_bip32_get_extendedkey(PATH_A)
        self.card.seeded = False
        self.card.reset()
        response, sw1, sw2 = self.cc.card_sign_transaction_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_INCORRECT_INITIALIZATION)
        self.assertEqual(self.card.log, [0x6D, 0x7A, 0x6D])

    def test_keyslot_is_not_retried(self):
        response, sw1, sw2 = self.cc.card_sign_transaction_hash(0x00, self.hash, None)
        self.assertEqual((sw1, sw2), SW_OK)
        self.card.log.clear()
        self.cc.card_bip32_get_extendedkey(PATH_A)
        self.assertEqual(self.card.log, [0x6D])

    def test_schnorr_after_reset_restores_both_keys(self):
        # tweak the key of PATH_A, then derive PATH_B for an ECDSA input
        self.cc.card_bip32_get_extendedkey(PATH_A)
        response, sw1, sw2 = self.cc.card_taproot_tweak_privkey(0xFF)
        self.assertEqual((sw1, sw2), SW_OK)
        tweaked_key = self.card.tweaked_key
        self.cc.card_bip32_get_extendedkey(PATH_B)
        self.card.reset()

        response, sw1, sw2 = self.cc.card_sign_schnorr_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_OK)
        self.assertEqual(response, list(h(b"schnorr", tweaked_key, bytes(self.hash))))
        # the BIP32 key is PATH_B again, as before the reset
        self.card.log.clear()
        response, sw1, sw2 = self.cc.card_sign_transaction_hash(0xFF, self.hash, None)
        self.assertEqual(response, self.expected_ecdsa(PATH_B))
        self.assertEqual(self.card.log, [0x7A])

    def test_tweak_after_reset_derives_again(self):
        self.cc.card_bip32_get_extendedkey(PATH_A)
        self.card.reset()
        response, sw1, sw2 = self.cc.card_taproot_tweak_privkey(0xFF, bytes(32))
        self.assertEqual((sw1, sw2), SW_OK)
        self.assertEqual(self.card.log, [0x6D, 0x7C, 0x6D, 0x7C])

    def test_failed_restore_keeps_the_client_keys(self):
        self.cc.card_bip32_get_extendedkey(PATH_A)
        self.cc.card_taproot_tweak_privkey(0xFF)
        self.cc.card_bip32_get_extendedkey(PATH_B)
        recorded = (self.cc._last_bip32_derivation, self.cc._last_taproot_tweak)
        self.card.seed = b"seed 2"
        self.card.reset()
        response, sw1, sw2 = self.cc.card_sign_schnorr_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_INCORRECT_INITIALIZATION)
        self.assertEqual((self.cc._last_bip32_derivation, self.cc._last_taproot_tweak), recorded,
                         "the keys derived by the client must still be the ones replayed")

    def test_tweak_of_a_key_derived_elsewhere_is_not_replayed(self):
        # the card holds a BIP32 key that was not derived through this CardConnector
        self.card.bip32_key = h(self.card.seed, b"elsewhere")
        response, sw1, sw2 = self.cc.card_taproot_tweak_privkey(0xFF)
        self.assertEqual((sw1, sw2), SW_OK)
        self.card.reset()
        response, sw1, sw2 = self.cc.card_sign_schnorr_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_INCORRECT_INITIALIZATION)

    def test_schnorr_without_tweak_returns_the_error(self):
        self.cc.card_bip32_get_extendedkey(PATH_A)
        self.card.reset()
        response, sw1, sw2 = self.cc.card_sign_schnorr_hash(0xFF, self.hash, None)
        self.assertEqual((sw1, sw2), SW_INCORRECT_INITIALIZATION)
        self.assertEqual(self.card.log, [0x6D, 0x7B])


if __name__ == "__main__":
    unittest.main()
