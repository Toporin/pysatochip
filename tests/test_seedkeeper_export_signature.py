# -*- coding: utf-8 -*-
"""SeedKeeper export signatures must be checked (audit finding B1.2).

Two call sites picked their verification branch from `sign_size`, a length the
*card* chooses:

    if (sign_size==20):
        secret_dict['hmac_list']=sign      # stored, never verified
    else:
        self.parser.verify_signature(...)

A 20-byte hmac is legitimate -- but only for a *secure* export, where the hmac
is keyed with the secret shared with the destination device and only that device
can check it. For a plain export the card must sign with its authentikey, so a
card that simply returned 20 bytes skipped verification altogether. The branch
is now driven by `is_secure_export`, which the host decides.

`seedkeeper_derive_master_password()` additionally swallowed a verification
failure into `dic['error_msg']` and returned the derived master password anyway.

These tests drive the real methods with a stubbed transport, and build real
signatures with real keys rather than mocking verification.
"""

import os
import sys
import unittest
import hashlib
from hashlib import sha256

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip import ec_backend
from pysatochip.CardConnector import CardConnector, SeedKeeperError
from pysatochip.CardDataParser import CardDataParser
from pysatochip.ecc import ECPubkey, der_sig_from_r_and_s

AUTHENTIKEY_SECRET = bytes.fromhex('03' * 32)
ATTACKER_SECRET = bytes.fromhex('04' * 32)

DERIVED = bytes(range(64))            # 64-byte HmacSha512 result
SALT = "some-salt"
SID = 0x0102


def der_sign(secret, payload):
    r, s = ec_backend.sign_digest(secret, sha256(bytes(payload)).digest())
    return list(der_sig_from_r_and_s(r, s))


class DeriveMasterPasswordTestCase(unittest.TestCase):
    """seedkeeper_derive_master_password() with a stubbed card_transmit()."""

    def setUp(self):
        if not ec_backend.available_backends():
            self.skipTest("no hardened EC backend available")
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        self.cc.parser.authentikey = ECPubkey(
            ec_backend.privkey_to_pubkey(AUTHENTIKEY_SECRET, compressed=False))
        self.response = None
        self.cc.card_transmit = lambda apdu: (self.response, 0x90, 0x00)

    def build(self, sign):
        """response = [derived_size(2) | derived(64) | sign_size(2) | sign]"""
        full_data = [len(DERIVED) >> 8, len(DERIVED) & 0xff] + list(DERIVED)
        self.response = full_data + [len(sign) >> 8, len(sign) & 0xff] + list(sign)
        return full_data

    def derive(self):
        return self.cc.seedkeeper_derive_master_password(SALT, SID)

    def test_accepts_a_genuine_signature(self):
        full_data = self.build([])
        self.build(der_sign(AUTHENTIKEY_SECRET, full_data))
        response, sw1, sw2, dic = self.derive()
        self.assertEqual(dic['derived_data'], DERIVED.hex())
        self.assertIn('sign', dic)

    def test_rejects_a_signature_from_another_key(self):
        full_data = self.build([])
        self.build(der_sign(ATTACKER_SECRET, full_data))
        with self.assertRaises(Exception):
            self.derive()

    def test_twenty_bytes_no_longer_skips_verification(self):
        """The bypass: any 20 bytes used to be accepted as an 'hmac'."""
        self.build(list(range(20)))
        with self.assertRaises(Exception):
            self.derive()

    def test_failure_is_not_swallowed_into_error_msg(self):
        """It used to return the derived password with dic['error_msg'] set."""
        full_data = self.build([])
        self.build(der_sign(ATTACKER_SECRET, full_data))
        try:
            response, sw1, sw2, dic = self.derive()
        except Exception:
            return
        self.fail("returned a derived master password with an unverified "
                  "signature: %r" % dic.get('error_msg'))

    def test_rejects_empty_signature(self):
        self.build([])
        with self.assertRaises(Exception):
            self.derive()


class ExportSecretTestCase(unittest.TestCase):
    """seedkeeper_export_secret() driven end to end with a stubbed transport.

    The card answers twice: an INIT call returning the secret header, then an
    UPDATE call returning [chunk_size(2) | chunk | sign_size(2) | sign]. The
    last chunk is signalled by chunk_size+2 < len(response).
    """

    LABEL = b'my-secret'
    SECRET = list(b'the-masterseed-bytes')

    def setUp(self):
        if not ec_backend.available_backends():
            self.skipTest("no hardened EC backend available")
        self.cc = CardConnector.__new__(CardConnector)
        self.cc.parser = CardDataParser()
        self.cc.parser.authentikey = ECPubkey(
            ec_backend.privkey_to_pubkey(AUTHENTIKEY_SECRET, compressed=False))
        self.header = self.build_header()
        self.responses = []
        self.cc.card_transmit = lambda apdu: (self.responses.pop(0), 0x90, 0x00)

    def build_header(self, with_iv=False):
        """[id(2)|type|origin|rights|nbplain|nbsecure|counter|fp(4)|rfu1|rfu2|label_size|label]"""
        # the fingerprint must be sha256(secret)[0:8]: seedkeeper_export_secret()
        # verifies it and raises on a mismatch (see test_seedkeeper_fingerprint)
        fingerprint = list(hashlib.sha256(bytes(self.SECRET)).digest()[0:4])
        header = ([0x01, 0x02], [0x30], [0x01], [0x01], [0x00], [0x00], [0x00],
                  fingerprint, [0x00], [0x00], [len(self.LABEL)])
        out = [b for part in header for b in part] + list(self.LABEL)
        return out + ([0x11] * 16 if with_iv else [])

    def run_export(self, sign, is_secure_export=False, header=None):
        header = self.header if header is None else header
        chunk = self.SECRET
        update = ([len(chunk) >> 8, len(chunk) & 0xff] + chunk
                  + [len(sign) >> 8, len(sign) & 0xff] + list(sign))
        self.responses = [header, update]
        sid_pubkey = 0x0003 if is_secure_export else None
        return self.cc.seedkeeper_export_secret(0x0001, sid_pubkey)

    def full_data_for(self, header):
        """What the card signs: header_list || secret."""
        label_size = header[14]
        return header[0:15 + label_size] + self.SECRET

    def test_plain_export_accepts_a_genuine_signature(self):
        sign = der_sign(AUTHENTIKEY_SECRET, self.full_data_for(self.header))
        out = self.run_export(sign)
        self.assertEqual(out['secret'], bytes(self.SECRET).hex())
        self.assertIn('sign', out)

    def test_plain_export_rejects_a_twenty_byte_hmac(self):
        """The bypass: 20 bytes used to be stored unverified as an 'hmac'."""
        with self.assertRaises(Exception):
            self.run_export(list(range(20)))

    def test_plain_export_rejects_a_signature_from_another_key(self):
        sign = der_sign(ATTACKER_SECRET, self.full_data_for(self.header))
        with self.assertRaises(Exception):
            self.run_export(sign)

    def test_plain_export_rejects_a_signature_over_other_data(self):
        sign = der_sign(AUTHENTIKEY_SECRET, list(b'something else entirely'))
        with self.assertRaises(Exception):
            self.run_export(sign)

    def test_plain_export_never_returns_an_unverified_secret(self):
        """The property that matters: no bad-signature path may return."""
        for name, sign in (
                ("20-byte hmac", list(range(20))),
                ("wrong signer", der_sign(ATTACKER_SECRET, self.full_data_for(self.header))),
                ("empty", []),
        ):
            with self.subTest(case=name):
                try:
                    out = self.run_export(sign)
                except Exception:
                    continue
                self.fail("returned secret %r with an unverified signature"
                          % out.get('secret'))

    def test_secure_export_accepts_the_hmac(self):
        """A 20-byte hmac is correct here: only the destination can check it."""
        header = self.build_header(with_iv=True)
        out = self.run_export(list(range(20)), is_secure_export=True, header=header)
        self.assertEqual(out['hmac'], bytes(range(20)).hex())
        self.assertIn('secret_encrypted', out)

    def test_secure_export_rejects_a_wrong_length_hmac(self):
        header = self.build_header(with_iv=True)
        for bad in (0, 19, 21, 71):
            with self.subTest(sign_size=bad):
                with self.assertRaises(SeedKeeperError):
                    self.run_export(list(range(bad)), is_secure_export=True,
                                    header=header)


if __name__ == "__main__":
    unittest.main(verbosity=2)
