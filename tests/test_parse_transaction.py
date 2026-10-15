# -*- coding: utf-8 -*-
"""Backward-compatibility tests for the deprecated card_parse_transaction().

TxParser was removed in 0.18.5. It only ever accumulated the bytes it walked
over, so `get_tx_double_hash()` was always the plain double-sha256 of its input
-- verified over 500 generated transactions before the removal, on both the
legacy and the segwit code path.

The vectors below were captured from the *old* TxParser implementation, so they
pin real backward compatibility rather than self-consistency: a caller that fed
a prepared transaction in and signed the resulting hash must keep getting the
same hash.
"""

import hashlib
import os
import sys
import unittest
import warnings

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector
from pysatochip.util import sha256d

# 1 input (scriptCode in place of scriptSig), 2 outputs, locktime, sighash type
LEGACY_TX = bytes.fromhex(
    '0100000001' + 'aa' * 32 + '00000000' + '19' + '76a914' + 'bb' * 20 + '88ac'
    + 'ffffffff' + '02'
    + '8096980000000000' + '19' + '76a914' + 'cc' * 20 + '88ac'
    + '00e1f50500000000' + '16' + '0014' + 'dd' * 20
    + '00000000' + '01000000')
LEGACY_HASH = bytes.fromhex(
    '8e7b7097beb61cdbe2b91159a09825f6c68117721093c44746b80483691e174c')

# BIP143 preimage
SEGWIT_TX = bytes.fromhex(
    '01000000' + '11' * 32 + '22' * 32 + '33' * 32 + '00000000'
    + '19' + '76a914' + 'ee' * 20 + '88ac'
    + '0046c32300000000' + 'ffffffff' + '44' * 32
    + '00000000' + '01000000')
SEGWIT_HASH = bytes.fromhex(
    'd36ebe36c155609b4a1739535c0a9ebce35d2e1a8a4a8f09fdaef734bedcee5e')

# 2 inputs whose scripts straddle the old parser's 128-byte CHUNK_SIZE and the
# 0xfd varint boundary -- the cases most likely to expose a chunking difference
CHUNKED_TX = bytes.fromhex(
    '0100000002' + '01' * 32 + '00000000' + 'fd2c01' + '99' * 300 + 'ffffffff'
    + '02' * 32 + '01000000' + '81' + '88' * 129 + 'ffffffff'
    + '01' + '0046c32300000000' + 'fd0501' + '77' * 261
    + '00000000' + '01000000')
CHUNKED_HASH = bytes.fromhex(
    '97883581fd1d3f98ec2f702ffb30eb3669aae3531403039f3444b95268906033')


class ParseTransactionTestCase(unittest.TestCase):

    def setUp(self):
        # no card needed: the function no longer exchanges any APDU
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.needs_2FA = False

    def parse(self, *args, **kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return self.cc.card_parse_transaction(*args, **kwargs)


class TestFrozenVectors(ParseTransactionTestCase):
    """Captured from the removed TxParser: these must not move."""

    def test_legacy_vector(self):
        self.assertEqual(bytes(self.parse(LEGACY_TX)[3]), LEGACY_HASH)

    def test_segwit_vector(self):
        self.assertEqual(bytes(self.parse(SEGWIT_TX, True)[3]), SEGWIT_HASH)

    def test_chunked_vector(self):
        """Scripts crossing the old 128-byte chunk size still hash the same."""
        self.assertEqual(bytes(self.parse(CHUNKED_TX)[3]), CHUNKED_HASH)

    def test_vectors_are_plain_double_sha256(self):
        """Documents why dropping the parser was safe."""
        for tx, want in ((LEGACY_TX, LEGACY_HASH), (SEGWIT_TX, SEGWIT_HASH),
                         (CHUNKED_TX, CHUNKED_HASH)):
            with self.subTest(length=len(tx)):
                self.assertEqual(
                    hashlib.sha256(hashlib.sha256(tx).digest()).digest(), want)


class TestBackwardCompatibleApi(ParseTransactionTestCase):

    def test_return_shape_is_unchanged(self):
        response, sw1, sw2, tx_hash, needs_2fa = self.parse(LEGACY_TX)
        self.assertEqual(response, [])
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIsInstance(tx_hash, list)
        self.assertEqual(len(tx_hash), 32)
        self.assertTrue(all(isinstance(b, int) for b in tx_hash))
        self.assertIsInstance(needs_2fa, bool)

    def test_needs_2fa_is_reported(self):
        self.cc.needs_2FA = True
        self.assertIs(self.parse(LEGACY_TX)[4], True)
        self.cc.needs_2FA = None
        self.assertIs(self.parse(LEGACY_TX)[4], False)

    def test_is_segwit_is_accepted_and_ignored(self):
        """It only ever selected a parsing path; the hash was the same."""
        positional = self.parse(LEGACY_TX, True)[3]
        keyword = self.parse(LEGACY_TX, is_segwit=True)[3]
        omitted = self.parse(LEGACY_TX)[3]
        self.assertEqual(positional, keyword)
        self.assertEqual(positional, omitted)

    def test_matches_the_util_helper(self):
        """sha256d() is the documented replacement."""
        self.assertEqual(bytes(self.parse(CHUNKED_TX)[3]), sha256d(CHUNKED_TX))

    def test_emits_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.cc.card_parse_transaction(LEGACY_TX)
        self.assertTrue(
            any(issubclass(c.category, DeprecationWarning) for c in caught),
            "card_parse_transaction() must warn that it is deprecated")


class TestNoLongerParses(ParseTransactionTestCase):
    """The old parser raised IndexError or span forever on malformed input
    (it was an unbounded loop: a signing DoS). Hashing cannot fail."""

    def test_accepts_arbitrary_bytes(self):
        for blob in (b'', b'\x00', b'not a transaction at all', os.urandom(777),
                     LEGACY_TX[:7], LEGACY_TX + b'trailing garbage'):
            with self.subTest(length=len(blob)):
                self.assertEqual(bytes(self.parse(blob)[3]), sha256d(blob))

    def test_truncated_transaction_does_not_raise_or_hang(self):
        for cut in range(0, len(LEGACY_TX), 7):
            with self.subTest(cut=cut):
                self.assertEqual(len(self.parse(LEGACY_TX[:cut])[3]), 32)


class TestTxParserIsGone(unittest.TestCase):

    def test_module_is_removed(self):
        with self.assertRaises(ImportError):
            __import__('pysatochip.TxParser')

    def test_card_connector_does_not_import_it(self):
        import pysatochip.CardConnector as cc_mod
        self.assertFalse(hasattr(cc_mod, 'TxParser'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
