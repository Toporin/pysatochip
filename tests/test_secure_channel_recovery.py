# -*- coding: utf-8 -*-
"""Recovery from a lost secure channel session, without a smartcard.

The card keeps the secure-channel session keys in transient memory, so an
applet deselect, a card reset or a reader power-off during an idle period
wipes them while the client keeps its own session. Old applets also keep the
"initialized" flag persistent, so the next command can fail with 0x9C22/0x9C23
(IV/MAC desync) or 0x9C20 instead of the recoverable 0x9C21. card_transmit()
must re-initiate the channel and retry the command once with fresh keys --
and only once, since a persistent 0x9C22/0x9C23 can also indicate tampering
on the PC/SC path.

A fake connection stands in for the card: it fails while its session is
"lost" and succeeds again once the fake channel initiation restores it.
"""

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

try:
    from pysatochip.CardConnector import CardConnector
except ImportError as e: # pyscard is not installed
    CardConnector = None
    IMPORT_ERROR = e

SW_OK = (0x90, 0x00)
SW_SC_REQUIRED = (0x9C, 0x20)
SW_SC_UNINITIALIZED = (0x9C, 0x21)
SW_SC_WRONG_IV = (0x9C, 0x22)
SW_SC_WRONG_MAC = (0x9C, 0x23)

# GetBIP32ExtendedKey and InitiateSecureChannel, as sent by the corresponding commands
APDU_GET_XKEY = [0xB0, 0x6D, 0x03, 0x40, 0x0C] + [0] * 12
APDU_INITIATE_SC = [0xB0, 0x81, 0x00, 0x00, 0x41] + [0] * 65


class FakeConnection:
    """The card: rejects everything while its session is lost."""

    def __init__(self):
        self.session_lost = False
        self.sw_when_lost = SW_SC_WRONG_MAC
        self.requires_encryption = False
        self.log = [] # apdus received

    def transmit(self, apdu):
        self.log.append(list(apdu))
        if self.session_lost:
            return [], self.sw_when_lost[0], self.sw_when_lost[1]
        if self.requires_encryption and apdu[1] != 0x82:
            return [], SW_SC_REQUIRED[0], SW_SC_REQUIRED[1]
        return [0xAA], SW_OK[0], SW_OK[1]


@unittest.skipIf(CardConnector is None, "pyscard is not installed")
class TestSecureChannelRecovery(unittest.TestCase):

    def setUp(self):
        self.card = FakeConnection()
        # no card reader: skip __init__, and set the attributes used by card_transmit
        cc = CardConnector.__new__(CardConnector)
        cc.card_present = True
        cc.cardservice = SimpleNamespace(connection=self.card)
        cc.needs_secure_channel = True
        cc.n_encrypt = 0
        cc.n_initiate = 0
        cc.recoverable = True

        def fake_encrypt(apdu):
            cc.n_encrypt += 1
            # mark the apdu as encrypted: encrypted commands carry ins 0x82
            return [0xB0, 0x82, 0x00, 0x00, len(apdu)] + list(apdu)

        def fake_initiate():
            cc.n_initiate += 1
            if cc.recoverable:
                self.card.session_lost = False

        cc.card_encrypt_secure_channel = fake_encrypt
        cc.card_decrypt_secure_channel = lambda response, ins: response
        cc.card_initiate_secure_channel = fake_initiate
        self.cc = cc

    def recovery(self, sw_when_lost):
        self.card.session_lost = True
        self.card.sw_when_lost = sw_when_lost
        return self.cc.card_transmit(APDU_GET_XKEY)

    def test_wrong_mac_recovers_and_retries(self):
        response, sw1, sw2 = self.recovery(SW_SC_WRONG_MAC)
        self.assertEqual((sw1, sw2), SW_OK)
        self.assertEqual(response, [0xAA])
        self.assertEqual(self.cc.n_initiate, 1)
        # the command is re-encrypted with the fresh channel, not resent as-is
        self.assertEqual(self.cc.n_encrypt, 2)
        self.assertEqual([apdu[1] for apdu in self.card.log], [0x82, 0x82])

    def test_wrong_iv_recovers_and_retries(self):
        response, sw1, sw2 = self.recovery(SW_SC_WRONG_IV)
        self.assertEqual((sw1, sw2), SW_OK)
        self.assertEqual(self.cc.n_initiate, 1)

    def test_uninitialized_recovers_and_retries(self):
        response, sw1, sw2 = self.recovery(SW_SC_UNINITIALIZED)
        self.assertEqual((sw1, sw2), SW_OK)
        self.assertEqual(self.cc.n_initiate, 1)

    def test_persistent_error_surfaces_after_one_retry(self):
        # the card keeps failing (or the PC/SC path is tampered with): the
        # command must fail loudly rather than loop through re-initiations
        self.cc.recoverable = False
        response, sw1, sw2 = self.recovery(SW_SC_WRONG_MAC)
        self.assertEqual((sw1, sw2), SW_SC_WRONG_MAC)
        self.assertEqual(self.cc.n_initiate, 1)
        self.assertEqual(len(self.card.log), 2)

    def test_secure_channel_required_switches_to_encrypted(self):
        # a plaintext command is rejected with 0x9C20: the client learns that
        # the card requires a secure channel and retries encrypted
        self.cc.needs_secure_channel = False
        self.card.requires_encryption = True
        response, sw1, sw2 = self.cc.card_transmit(APDU_GET_XKEY)
        self.assertEqual((sw1, sw2), SW_OK)
        self.assertTrue(self.cc.needs_secure_channel)
        self.assertEqual(self.cc.n_initiate, 1)
        self.assertEqual(self.cc.n_encrypt, 1)
        self.assertEqual([apdu[1] for apdu in self.card.log], [0x6D, 0x82])

    def test_initiate_command_is_not_reinitiated(self):
        # an error status on the 0x81 exchange itself must come back to the
        # caller (card_initiate_secure_channel raises), not recurse
        self.card.session_lost = True
        self.card.sw_when_lost = SW_SC_UNINITIALIZED
        response, sw1, sw2 = self.cc.card_transmit(APDU_INITIATE_SC)
        self.assertEqual((sw1, sw2), SW_SC_UNINITIALIZED)
        self.assertEqual(self.cc.n_initiate, 0)
        self.assertEqual(len(self.card.log), 1)


if __name__ == "__main__":
    unittest.main()
