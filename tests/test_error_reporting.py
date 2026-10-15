# -*- coding: utf-8 -*-
"""Status words must be reported and acted on correctly (audit finding B5).

Four separate defects, all of which made a failure look like something else:

  * get_sw12() returned 16*sw1+sw2, interleaving the nibbles, so (0x9C, 0x01)
    came out as 0x9C1 and never matched a JCconstants SW_* value.
  * one raise passed sw1 twice, so UnexpectedSW12Error.sw2 was wrong.
  * card_change_PIN() had no catch-all branch: on any unexpected status it
    returned normally while self.pin still held the old value, so a caller that
    did not re-check sw1/sw2 believed the PIN had been changed.
  * card_import_trusted_pubkey() / card_export_trusted_pubkey() handled a few
    specific statuses and then fell through to the parser with whatever the card
    had returned, without ever asserting 0x9000.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import (CardConnector, UnexpectedSW12Error,
                                      WrongPinError, PinBlockedError)
from pysatochip.CardDataParser import CardDataParser
from pysatochip.JCconstants import JCconstants


class TestGetSw12(unittest.TestCase):

    def setUp(self):
        self.cc = CardConnector.__new__(CardConnector)

    def test_combines_the_bytes_as_a_16_bit_word(self):
        for sw1, sw2, want in ((0x90, 0x00, 0x9000), (0x9C, 0x01, 0x9C01),
                               (0x6D, 0x00, 0x6D00), (0x63, 0xC2, 0x63C2)):
            with self.subTest(sw="%02X%02X" % (sw1, sw2)):
                self.assertEqual(self.cc.get_sw12(sw1, sw2), want)

    def test_matches_the_jcconstants_values(self):
        """The whole point of the helper, and what the old radix broke."""
        self.assertEqual(self.cc.get_sw12(0x9C, 0x13),
                         JCconstants.SW_INCORRECT_INITIALIZATION)

    def test_old_radix_would_not_match(self):
        self.assertNotEqual(16 * 0x9C + 0x13, JCconstants.SW_INCORRECT_INITIALIZATION)


class TestChangePinReportsFailure(unittest.TestCase):

    def make_cc(self, sw):
        cc = CardConnector.__new__(CardConnector)
        cc.pin_nbr = 0
        cc.pin = list(b'oldpin')
        cc.card_transmit = lambda apdu: ([], sw[0], sw[1])
        return cc

    def change(self, cc):
        return cc.card_change_PIN(0, list(b'oldpin'), list(b'newpin'))

    def test_success_caches_the_new_pin(self):
        cc = self.make_cc((0x90, 0x00))
        self.change(cc)
        self.assertEqual(cc.pin, list(b'newpin'))

    def test_unexpected_status_raises(self):
        """The regression: it used to return normally, pin unchanged."""
        for sw in ((0x6D, 0x00), (0x9C, 0x04), (0x6A, 0x82), (0x9C, 0x06)):
            with self.subTest(sw="%02X%02X" % sw):
                cc = self.make_cc(sw)
                with self.assertRaises(UnexpectedSW12Error):
                    self.change(cc)

    def test_unexpected_status_does_not_cache_a_new_pin(self):
        cc = self.make_cc((0x6D, 0x00))
        try:
            self.change(cc)
        except UnexpectedSW12Error:
            pass
        self.assertEqual(cc.pin, list(b'oldpin'),
                         "cached PIN must not look changed when the card refused")

    def test_known_pin_errors_still_raise_their_own_types(self):
        cc = self.make_cc((0x63, 0xC2))
        with self.assertRaises(WrongPinError):
            self.change(cc)
        cc = self.make_cc((0x9C, 0x0C))
        with self.assertRaises(PinBlockedError):
            self.change(cc)


class TestTrustedPubkeyChecksStatus(unittest.TestCase):

    def make_cc(self, sw):
        cc = CardConnector.__new__(CardConnector)
        cc.parser = CardDataParser()
        cc.parser.authentikey = object()
        cc.card_transmit = lambda apdu: ([0xFF] * 8, sw[0], sw[1])
        return cc

    def test_export_raises_on_an_unexpected_status(self):
        for sw in ((0x9C, 0x04), (0x6A, 0x82), (0x9C, 0x0F)):
            with self.subTest(sw="%02X%02X" % sw):
                with self.assertRaises(UnexpectedSW12Error):
                    self.make_cc(sw).card_export_trusted_pubkey()

    def test_export_keeps_its_documented_special_cases(self):
        self.assertEqual(self.make_cc((0x9C, 0x35)).card_export_trusted_pubkey(), 65 * '00')
        self.assertEqual(self.make_cc((0x6D, 0x00)).card_export_trusted_pubkey(), 65 * 'FF')

    def test_import_raises_on_an_unexpected_status(self):
        for sw in ((0x9C, 0x04), (0x6A, 0x82)):
            with self.subTest(sw="%02X%02X" % sw):
                with self.assertRaises(UnexpectedSW12Error):
                    self.make_cc(sw).card_import_trusted_pubkey(bytes(65))


class TestStatusWordIsReportedFaithfully(unittest.TestCase):

    def test_factory_reset_v3_reports_both_bytes(self):
        """It used to pass sw1 twice, so ex.sw2 echoed sw1."""
        cc = CardConnector.__new__(CardConnector)
        cc.card_transmit = lambda apdu: ([], 0x6A, 0x82)
        with self.assertRaises(UnexpectedSW12Error) as caught:
            cc.card_reset_factory_v3()
        self.assertEqual((caught.exception.sw1, caught.exception.sw2), (0x6A, 0x82))

    def test_factory_reset_v3_keeps_its_named_errors(self):
        from pysatochip.CardConnector import CardSetupNotDoneError, UnsupportedFeatureError
        for sw, exc in (((0x9C, 0x04), CardSetupNotDoneError),
                        ((0x6D, 0x00), UnsupportedFeatureError)):
            with self.subTest(sw="%02X%02X" % sw):
                cc = CardConnector.__new__(CardConnector)
                cc.card_transmit = lambda apdu, sw=sw: ([], sw[0], sw[1])
                with self.assertRaises(exc):
                    cc.card_reset_factory_v3()


if __name__ == "__main__":
    unittest.main(verbosity=2)
