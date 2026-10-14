# -*- coding: utf-8 -*-
"""Never parse a response body before checking its status word (B1.5).

Three call sites handed the response straight to a parser without looking at
sw1/sw2. On an error status the body is an error payload or empty, so the
parsers indexed into bytes that were never a valid answer. The worst case was
card_initiate_secure_channel(), which would derive the session key from
whatever came back.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector, UnexpectedSW12Error
from pysatochip.CardDataParser import CardDataParser

# a few error statuses the card really returns
ERROR_SWS = [(0x6D, 0x00),   # instruction not supported
             (0x9C, 0x04),   # setup not done
             (0x9C, 0x05),   # unsupported feature
             (0x6A, 0x82),   # file not found
             (0x9C, 0x0F)]   # invalid parameter


class InitiateSecureChannelTestCase(unittest.TestCase):
    """The session key must never be derived from an error payload."""

    def setUp(self):
        import threading
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        self.cc._sc_lock = threading.RLock()
        self.cc._sc_initializing = False
        self.cc.sc = None
        self.sw = (0x90, 0x00)
        self.body = []
        self.cc.card_transmit = lambda apdu: (self.body, self.sw[0], self.sw[1])

    def test_error_status_raises(self):
        for sw in ERROR_SWS:
            with self.subTest(sw="%02X%02X" % sw):
                self.sw = sw
                self.body = []
                with self.assertRaises(UnexpectedSW12Error):
                    self.cc.card_initiate_secure_channel()

    def test_error_status_raises_even_with_a_plausible_body(self):
        """An attacker-supplied body must not be parsed just because it parses."""
        self.sw = (0x6D, 0x00)
        self.body = [0x00, 0x41] + [0x04] + [0xAA] * 64 + [0x00, 0x00]
        with self.assertRaises(UnexpectedSW12Error):
            self.cc.card_initiate_secure_channel()

    def test_channel_is_not_published_on_error(self):
        """self.sc must stay None so no later command uses a bogus channel."""
        self.sw = (0x6D, 0x00)
        self.body = []
        try:
            self.cc.card_initiate_secure_channel()
        except UnexpectedSW12Error:
            pass
        self.assertIsNone(self.cc.sc)

    def test_initializing_flag_is_cleared_on_error(self):
        self.sw = (0x6D, 0x00)
        try:
            self.cc.card_initiate_secure_channel()
        except UnexpectedSW12Error:
            pass
        self.assertFalse(self.cc._sc_initializing)


class SatodimeGetPubkeyTestCase(unittest.TestCase):
    """Matches satodime_seal_key()/unseal_key()/get_privkey(), which already
    returned early rather than parsing an error payload."""

    def setUp(self):
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        self.cc.parser.authentikey = object()
        self.sw = (0x90, 0x00)
        self.cc.card_transmit = lambda apdu: ([0xFF] * 4, self.sw[0], self.sw[1])

    def test_error_status_returns_empty_without_parsing(self):
        for sw in ERROR_SWS:
            with self.subTest(sw="%02X%02X" % sw):
                self.sw = sw
                response, sw1, sw2, pubkey, pubkey_comp = \
                    self.cc.satodime_get_pubkey(0)
                self.assertEqual((sw1, sw2), sw)
                self.assertEqual(pubkey, [])
                self.assertEqual(pubkey_comp, [])

    def test_tuple_shape_is_preserved(self):
        """The CLI unpacks five values and does not catch exceptions."""
        self.sw = (0x6D, 0x00)
        result = self.cc.satodime_get_pubkey(0)
        self.assertEqual(len(result), 5)


class SetAuthentikeyPubkeyTestCase(unittest.TestCase):
    """This one is an optimization: the authentikey it returns comes from the
    caller's already-verified response, not from the 0x75 command, and older
    applets may not implement 0x75 at all. It must warn, not raise."""

    def setUp(self):
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        self.sentinel = object()
        self.cc.parser.parse_bip32_get_authentikey = lambda r: self.fake_key
        self.sw = (0x90, 0x00)
        self.cc.card_transmit = lambda apdu: ([], self.sw[0], self.sw[1])

    class FakeKey:
        def get_public_key_bytes(self, compressed=False):
            return bytes(65)

    fake_key = FakeKey()

    def test_returns_the_authentikey_even_if_caching_fails(self):
        self.sw = (0x6D, 0x00)
        with self.assertLogs('pysatochip.CardConnector', level='WARNING') as logs:
            result = self.cc.card_bip32_set_authentikey_pubkey([0x00] * 70)
        self.assertIs(result, self.fake_key)
        self.assertTrue(any('coordy' in m for m in logs.output))

    def test_success_path_is_silent(self):
        self.sw = (0x90, 0x00)
        result = self.cc.card_bip32_set_authentikey_pubkey([0x00] * 70)
        self.assertIs(result, self.fake_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
