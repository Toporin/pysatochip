# -*- coding: utf-8 -*-
"""Two APDU-construction bugs in card_bip32_get_extendedkey (audit finding B5).

  * `[len(coordy)&0xFF00, len(coordy)&0x00FF]` masked the high byte instead of
    shifting it, so any length of 256 or more put a value above 255 into a byte
    list. Harmless only because coordy is always 32 bytes today.
  * The out-of-memory retry did `apdu[3] = apdu[3] ^ 0x80`, which *toggles* the
    erase flag: a caller that had already set bit 7 had it cleared instead. The
    following `apdu[3] &= 0x7f` then cleared bit 7 unconditionally, discarding a
    flag the caller had asked for.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector, UnexpectedSW12Error
from pysatochip.CardDataParser import CardDataParser

ERASE_FLAG = 0x80


def encode_len_old(n):
    return [n & 0xFF00, n & 0x00FF]


def encode_len_new(n):
    return [(n >> 8) & 0xFF, n & 0xFF]


class TestLengthEncoding(unittest.TestCase):

    def test_both_agree_for_the_only_length_used_today(self):
        """coordy is 32 bytes, which is why the bug never showed up."""
        self.assertEqual(encode_len_old(32), encode_len_new(32))

    def test_old_encoding_overflows_a_byte(self):
        for n in (256, 300, 65535):
            with self.subTest(length=n):
                self.assertGreater(max(encode_len_old(n)), 0xFF)
                self.assertLessEqual(max(encode_len_new(n)), 0xFF)

    def test_new_encoding_round_trips(self):
        for n in (0, 1, 32, 255, 256, 4096, 65535):
            with self.subTest(length=n):
                hi, lo = encode_len_new(n)
                self.assertEqual((hi << 8) + lo, n)

    def test_source_uses_a_shift(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'pysatochip', 'CardConnector.py')
        src = open(path, encoding='utf-8').read()
        self.assertNotIn("len(coordy)&0xFF00", src,
                         "coordy length still masks the high byte instead of shifting")


class TestEraseFlagRetry(unittest.TestCase):
    """Drive the 0x9C01 retry and inspect the p2 byte the card actually sees."""

    def make_cc(self):
        cc = CardConnector.__new__(CardConnector)
        cc.parser = CardDataParser()
        cc.parser.authentikey = object()
        self.seen_p2 = []
        self.apdus = []

        def transmit(apdu):
            self.seen_p2.append(apdu[3])
            self.apdus.append(apdu)
            if len(self.seen_p2) == 1:
                return [], 0x9C, 0x01        # no memory left -> triggers the retry
            return [], 0x6D, 0x00            # stop here; we only inspect the APDUs

        cc.card_transmit = transmit
        return cc

    def run_once(self, option_flags):
        cc = self.make_cc()
        with self.assertRaises(UnexpectedSW12Error):
            cc.card_bip32_get_extendedkey(bytes(4), option_flags=option_flags)
        return cc

    def test_retry_sets_the_erase_flag(self):
        self.run_once(0x40)
        self.assertEqual(self.seen_p2[0], 0x40)
        self.assertEqual(self.seen_p2[1], 0x40 | ERASE_FLAG)

    def test_retry_does_not_toggle_a_flag_the_caller_set(self):
        """The regression: XOR cleared the erase flag the caller had asked for."""
        self.run_once(0x40 | ERASE_FLAG)
        self.assertEqual(self.seen_p2[0], 0x40 | ERASE_FLAG)
        self.assertEqual(self.seen_p2[1] & ERASE_FLAG, ERASE_FLAG,
                         "retry cleared the erase flag instead of setting it")

    def test_callers_flags_are_restored_afterwards(self):
        """`&= 0x7f` used to strip bit 7 even when the caller had set it."""
        cc = self.run_once(0x40 | ERASE_FLAG)
        self.assertEqual(self.apdus[-1][3], 0x40 | ERASE_FLAG)

    def test_no_retry_when_memory_is_fine(self):
        cc = CardConnector.__new__(CardConnector)
        cc.parser = CardDataParser()
        cc.parser.authentikey = object()
        seen = []
        cc.card_transmit = lambda apdu: (seen.append(apdu[3]), ([], 0x6D, 0x00))[1]
        with self.assertRaises(UnexpectedSW12Error):
            cc.card_bip32_get_extendedkey(bytes(4), option_flags=0x40)
        self.assertEqual(seen, [0x40], "a single exchange was expected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
