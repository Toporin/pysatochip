# -*- coding: utf-8 -*-
"""A fingerprint mismatch must be an error, not a log line (audit finding B1.4).

The SeedKeeper stores a 4-byte fingerprint -- sha256(secret)[0:8] in hex -- next
to each secret. It exists for exactly one purpose: to detect that the bytes on
the card are not the bytes that were meant to be there. Before 0.18.5 both the
import and the export path compared it and only logged on mismatch:

    if (fingerprint_from_secret == fingerprint_from_seedkeeper):
        logger.debug("Fingerprints match !")
    else:
        logger.error(f"Fingerprint mismatch: ...")
    return id, fingerprint_from_seedkeeper        # success

so a masterseed that the card had stored incorrectly, or an export corrupted in
transit, was returned to the caller as a normal result. For a seed that means
funds derived from it are unrecoverable.

The formula is pinned by the hardware suite (test_seedkeeper.py:568 asserts the
card's fingerprint equals sha256(secret)[0:8]), so a mismatch is never expected
in a healthy flow.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector, SeedKeeperError
from pysatochip.CardDataParser import CardDataParser

SECRET = list(b'a-masterseed-that-must-round-trip-intact')
LABEL = b'my-secret'


def fingerprint_of(secret):
    return hashlib.sha256(bytes(secret)).hexdigest()[0:8]


def build_header(label=LABEL, fingerprint=b'\x00\x00\x00\x00'):
    """[id(2)|type|origin|rights|nbplain|nbsecure|counter|fp(4)|rfu1|rfu2|label_size|label]"""
    return ([0x01, 0x02, 0x30, 0x01, 0x01, 0x00, 0x00, 0x00]
            + list(fingerprint) + [0x00, 0x00, len(label)] + list(label))


class ImportFingerprintTestCase(unittest.TestCase):
    """seedkeeper_import_secret() with a stubbed transport.

    OP_INIT and OP_PROCESS return nothing useful; OP_FINAL returns
    [id(2) | fingerprint(4)], which is what gets checked.
    """

    def setUp(self):
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        self.final_fingerprint = None
        self.cc.card_transmit = self._transmit

    def _transmit(self, apdu):
        p2 = apdu[3]
        if p2 == 0x03:   # OP_FINAL
            return [0x00, 0x07] + list(self.final_fingerprint), 0x90, 0x00
        return [], 0x90, 0x00

    def do_import(self, card_fingerprint):
        self.final_fingerprint = card_fingerprint
        header_hex = bytes(build_header()).hex()
        return self.cc.seedkeeper_import_secret(
            {'header': '0000' + header_hex, 'secret_list': SECRET})

    def test_matching_fingerprint_is_accepted(self):
        good = bytes.fromhex(fingerprint_of(SECRET))
        sid, fingerprint = self.do_import(good)
        self.assertEqual(sid, 7)
        self.assertEqual(fingerprint, fingerprint_of(SECRET))

    def test_mismatching_fingerprint_raises(self):
        """The card stored something other than what we sent."""
        with self.assertRaises(SeedKeeperError):
            self.do_import(bytes.fromhex('deadbeef'))

    def test_zero_fingerprint_raises(self):
        """A card that simply reports nothing must not look like success."""
        with self.assertRaises(SeedKeeperError):
            self.do_import(b'\x00\x00\x00\x00')

    def test_error_names_the_stored_id(self):
        """The secret is already on the card: the caller needs its id."""
        try:
            self.do_import(bytes.fromhex('deadbeef'))
        except SeedKeeperError as ex:
            self.assertIn('deadbeef', str(ex))
            self.assertIn('id 7', str(ex))
        else:
            self.fail("no exception raised")

    def test_never_returns_on_mismatch(self):
        for bad in ('deadbeef', '00000000', fingerprint_of(SECRET)[:-1] + '0'):
            with self.subTest(fingerprint=bad):
                try:
                    result = self.do_import(bytes.fromhex(bad))
                except SeedKeeperError:
                    continue
                self.fail("returned %r for a mismatching fingerprint" % (result,))


class ExportFingerprintTestCase(unittest.TestCase):
    """seedkeeper_export_secret(): INIT returns the header, UPDATE the secret."""

    def setUp(self):
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        # skip the authentikey signature check; this test is about the digest
        self.cc.parser.verify_signature = lambda *a, **kw: None
        self.cc.parser.authentikey = object()
        self.responses = []
        self.cc.card_transmit = lambda apdu: (self.responses.pop(0), 0x90, 0x00)

    def do_export(self, header_fingerprint):
        header = build_header(fingerprint=bytes.fromhex(header_fingerprint))
        sign = list(range(71))      # length != 20 -> plain-export branch
        update = ([len(SECRET) >> 8, len(SECRET) & 0xff] + SECRET
                  + [len(sign) >> 8, len(sign) & 0xff] + sign)
        self.responses = [header, update]
        return self.cc.seedkeeper_export_secret(0x0001)

    def test_matching_fingerprint_is_accepted(self):
        out = self.do_export(fingerprint_of(SECRET))
        self.assertEqual(out['secret'], bytes(SECRET).hex())

    def test_mismatching_fingerprint_raises(self):
        """A corrupt or tampered export must not be returned as a good secret."""
        with self.assertRaises(SeedKeeperError):
            self.do_export('deadbeef')

    def test_never_returns_a_corrupt_secret(self):
        for bad in ('deadbeef', '00000000'):
            with self.subTest(fingerprint=bad):
                try:
                    out = self.do_export(bad)
                except SeedKeeperError:
                    continue
                self.fail("returned secret %r despite a fingerprint mismatch"
                          % out.get('secret'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
