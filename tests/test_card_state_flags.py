# -*- coding: utf-8 -*-
"""Two state flags recorded the wrong thing (audit finding B5).

  * satocash_get_status() wrote the Satocash PIN flag into self.is_seeded, the
    Satochip "a BIP32 seed is loaded" flag, clobbering it with an unrelated
    value. CardConnector.__init__ already declares self.needsPIN for it.
  * satodime_set_unlock_secret() set self.is_owner = False when given no
    secret and then immediately overwrote it with an unconditional = True, so
    the client believed it was the owner while every unlock code it computed
    was keyed with the all-zero placeholder.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector
from pysatochip.JCconstants import SIZE_UNLOCK_SECRET


class TestSatodimeOwnership(unittest.TestCase):

    def setUp(self):
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.is_owner = False

    def test_no_secret_means_not_owner(self):
        self.cc.satodime_set_unlock_secret()
        self.assertFalse(self.cc.is_owner)

    def test_no_secret_still_installs_the_zero_placeholder(self):
        self.cc.satodime_set_unlock_secret()
        self.assertEqual(len(self.cc.unlock_secret), SIZE_UNLOCK_SECRET)
        self.assertEqual(set(self.cc.unlock_secret), {0})

    def test_a_real_secret_means_owner(self):
        self.cc.satodime_set_unlock_secret(list(range(SIZE_UNLOCK_SECRET)))
        self.assertTrue(self.cc.is_owner)
        self.assertEqual(self.cc.unlock_secret, list(range(SIZE_UNLOCK_SECRET)))

    def test_ownership_is_dropped_again(self):
        """Clearing the secret must clear ownership, not leave it stale."""
        self.cc.satodime_set_unlock_secret(list(range(SIZE_UNLOCK_SECRET)))
        self.cc.satodime_set_unlock_secret()
        self.assertFalse(self.cc.is_owner)


class TestSatocashStatusFlags(unittest.TestCase):
    """satocash_get_status() must not touch the seed flag."""

    def make_cc(self, response):
        cc = CardConnector.__new__(CardConnector)
        cc.is_seeded = "untouched"
        cc.needsPIN = None
        cc.needs_2FA = None
        cc.setup_done = None
        cc.card_transmit = lambda apdu: (response, 0x90, 0x00)
        return cc

    def status_response(self, needs_pin):
        """A full 25-byte Satocash status: the parser indexes up to byte 24."""
        resp = [0x00] * 25
        resp[1] = 0x0C                              # protocol minor
        resp[8] = 0x00                              # needs2FA
        resp[9] = 0x01 if needs_pin else 0x00       # needs_pin  <- the flag under test
        resp[10] = 0x01                             # setup_done
        return resp

    def test_pin_flag_lands_in_needsPIN(self):
        for needs_pin in (True, False):
            with self.subTest(needs_pin=needs_pin):
                cc = self.make_cc(self.status_response(needs_pin))
                response, sw1, sw2, d = cc.satocash_get_status()
                self.assertEqual(d['needs_pin'], needs_pin)
                self.assertEqual(cc.needsPIN, needs_pin)

    def test_seed_flag_is_left_alone(self):
        """The regression: is_seeded used to be overwritten with the PIN flag."""
        for needs_pin in (True, False):
            with self.subTest(needs_pin=needs_pin):
                cc = self.make_cc(self.status_response(needs_pin))
                cc.satocash_get_status()
                self.assertEqual(cc.is_seeded, "untouched",
                                 "satocash_get_status() clobbered is_seeded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
