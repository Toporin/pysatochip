# -*- coding: utf-8 -*-
"""Card serial number (CPLC || IIN || CIN) used as certificate subject.

On a card where no applet is implicitly selected at power-up (seen on a
Seedkeeper Pro with several applets installed), GET DATA CPLC/IIN/CIN failed
with 0x6D00. The status words were not checked, so the serial number was the
empty string and card_verify_authenticity() reported the SHA1 of nothing
(da39a3ee...) as not matching the certificate subject. The ISD must now be
selected first, and failures must leave UID_SHA1 unset.
"""

import hashlib
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector

CPLC = [0x9F, 0x7F, 0x2A] + list(range(42))
SELECT_EMPTY = [0x00, 0xA4, 0x04, 0x00, 0x00]
EMPTY_SHA1 = hashlib.sha1(b"").hexdigest()


class FakeCard:
    """Answers GET DATA only once the ISD is selected (no implicit selection)."""

    def __init__(self, isd_selected=False, empty_select_ok=True, iin_cin_sw=(0x6A, 0x88)):
        self.isd_selected = isd_selected
        self.empty_select_ok = empty_select_ok
        self.iin_cin_sw = iin_cin_sw
        self.apdus = []

    def transmit(self, apdu):
        self.apdus.append(list(apdu))
        if apdu[:4] == [0x00, 0xA4, 0x04, 0x00]:
            aid = apdu[5:5 + apdu[4]]
            ok = (aid == [] and self.empty_select_ok) or aid == CardConnector.ISD_AIDS[1]
            self.isd_selected = ok
            return ([0x6F, 0x00], 0x90, 0x00) if ok else ([], 0x6A, 0x82)
        if apdu[:2] == [0x80, 0xCA]:
            if not self.isd_selected:
                return ([], 0x6D, 0x00)
            if apdu[2:4] == [0x9F, 0x7F]:
                return (CPLC, 0x90, 0x00)
            return ([], *self.iin_cin_sw)
        return ([], 0x6D, 0x00)


def make_cc(card):
    cc = CardConnector.__new__(CardConnector)
    cc.cardservice = SimpleNamespace(connection=card)
    cc.UID = cc.UID_SHA1 = "stale"
    return cc


class TestCardSerialNumber(unittest.TestCase):

    def test_isd_is_selected_before_get_data(self):
        card = FakeCard(isd_selected=False)
        cc = make_cc(card)
        self.assertEqual(cc.card_read_serial_number(), hashlib.sha1(bytes(CPLC)).hexdigest())
        self.assertEqual(card.apdus[0], SELECT_EMPTY)
        self.assertEqual(cc.UID, CPLC)

    def test_missing_iin_cin_are_empty(self):
        """0x6A88 for IIN/CIN must give the same hash as previously issued certificates."""
        cc = make_cc(FakeCard(iin_cin_sw=(0x6A, 0x88)))
        self.assertEqual(cc.card_read_serial_number(), hashlib.sha1(bytes(CPLC)).hexdigest())

    def test_explicit_isd_aid_fallback(self):
        card = FakeCard(empty_select_ok=False)
        cc = make_cc(card)
        self.assertEqual(cc.card_read_serial_number(), hashlib.sha1(bytes(CPLC)).hexdigest())
        self.assertEqual(card.apdus[1][5:13], CardConnector.ISD_AIDS[1])

    def test_unreadable_cplc_leaves_serial_unset(self):
        card = FakeCard(empty_select_ok=False)
        card.transmit = lambda apdu: ([], 0x6D, 0x00)
        cc = make_cc(card)
        self.assertIsNone(cc.card_read_serial_number())
        self.assertIsNone(cc.UID)
        self.assertIsNone(cc.UID_SHA1)

    def test_transmit_error_leaves_serial_unset(self):
        card = FakeCard()

        def boom(apdu):
            raise RuntimeError("reader error")
        card.transmit = boom
        cc = make_cc(card)
        self.assertIsNone(cc.card_read_serial_number())
        self.assertIsNone(cc.UID_SHA1)

    def test_verify_authenticity_reports_unreadable_serial(self):
        cc = make_cc(FakeCard())
        cc.UID_SHA1 = None
        cc.card_export_perso_certificate = lambda: "-----BEGIN CERTIFICATE-----"
        is_ok, _, _, _, txt_error = cc.card_verify_authenticity()
        self.assertFalse(is_ok)
        self.assertIn("Unable to read the card serial number", txt_error)
        self.assertNotIn(EMPTY_SHA1, txt_error)


if __name__ == "__main__":
    unittest.main()
