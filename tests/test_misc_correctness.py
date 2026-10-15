# -*- coding: utf-8 -*-
"""The last three B5 correctness bugs.

  * card_bip32_get_xpub()/card_bip32_get_xprv() documented `path: str | bytes`
    but bound `depth`/`bytepath` only in the str branch, so a bytes path raised
    UnboundLocalError on the very next line.
  * Satochip2FA.do_challenge_response() used `continue` in its exception
    handler, skipping both the sleep and the timeout decrement, so an
    unreachable server produced an infinite full-speed retry that never
    returned.
  * parse_to_compact_sig() read sigin[4+lr-1-i] *before* checking `lr>=(i+1)`,
    so for i >= lr the index went negative and Python wrapped it round to the
    end of the buffer.
"""

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip import Satochip2FA as sat2fa
from pysatochip.CardConnector import CardConnector
from pysatochip.CardDataParser import CardDataParser


class TestBip32PathAcceptsBytes(unittest.TestCase):
    """The docstring promises str | bytes; both must bind depth and bytepath."""

    def setUp(self):
        self.parser = CardDataParser()
        self.depth, self.bytepath = self.parser.bip32path2bytes("m/44'/0'/1'")

    def make_cc(self):
        cc = CardConnector.__new__(CardConnector)
        cc.parser = self.parser
        self.seen = []

        def fake_extendedkey(path, sid=None, option_flags=0x40):
            self.seen.append(bytes(path))
            raise RuntimeError("stop after the path has been resolved")

        cc.card_bip32_get_extendedkey = fake_extendedkey
        return cc

    def test_xpub_accepts_a_bytes_path(self):
        cc = self.make_cc()
        with self.assertRaises(RuntimeError):
            cc.card_bip32_get_xpub(self.bytepath, 'standard', True)
        self.assertEqual(self.seen[0], self.bytepath)

    def test_xprv_accepts_a_bytes_path(self):
        cc = self.make_cc()
        with self.assertRaises(RuntimeError):
            cc.card_bip32_get_xprv(self.bytepath, 'standard', True)
        self.assertEqual(self.seen[0], self.bytepath)

    def test_bytes_and_str_resolve_to_the_same_path(self):
        for arg in (self.bytepath, bytearray(self.bytepath), list(self.bytepath)):
            with self.subTest(kind=type(arg).__name__):
                cc = self.make_cc()
                with self.assertRaises(RuntimeError):
                    cc.card_bip32_get_xpub(arg, 'standard', True)
                self.assertEqual(self.seen[0], self.bytepath)

    def test_depth_matches_the_string_form(self):
        self.assertEqual(self.depth, len(self.bytepath) // 4)


class TestTwoFactorRetryTerminates(unittest.TestCase):

    def setUp(self):
        self._proxy = sat2fa.ServerProxy
        self._sleep = time.sleep
        time.sleep = lambda s: None          # keep the test quick; decrement still runs

    def tearDown(self):
        sat2fa.ServerProxy = self._proxy
        time.sleep = self._sleep

    def install(self, get):
        class Server:
            def delete(self, *a): pass
            def put(self, *a): pass
        Server.get = lambda self, *a: get()
        sat2fa.ServerProxy = lambda *a, **kw: Server()

    def run_bounded(self, d, secs=10.0):
        box = {}
        def target():
            try:
                box['r'] = sat2fa.Satochip2FA.do_challenge_response(d)
            except BaseException as ex:
                box['e'] = ex
        th = threading.Thread(target=target, daemon=True)
        th.start()
        th.join(secs)
        if th.is_alive():
            self.fail("do_challenge_response() did not terminate: the retry is unbounded")
        return box

    def test_unreachable_server_times_out(self):
        def boom():
            raise OSError("connection refused")
        self.install(boom)
        d = {'id_2FA': 'abc', 'msg_encrypt': 'x'}
        self.run_bounded(d)
        self.assertIsNone(d['reply_encrypt'])

    def test_empty_reply_still_sets_the_key(self):
        """An empty (falsy, non-None) reply used to leave the key unset."""
        self.install(lambda: '')
        d = {'id_2FA': 'abc', 'msg_encrypt': 'x'}
        self.run_bounded(d)
        self.assertIn('reply_encrypt', d)
        self.assertIsNone(d['reply_encrypt'])


class TestCompactSigIndexing(unittest.TestCase):

    def setUp(self):
        self.parser = CardDataParser()

    def der(self, r, s):
        return bytearray([0x30, len(r) + len(s) + 4, 0x02, len(r)] + list(r)
                         + [0x02, len(s)] + list(s))

    def test_short_r_and_s_do_not_wrap_the_index(self):
        out = self.parser.parse_to_compact_sig(self.der(b'\xaa', b'\xbb'), 0, True)
        self.assertEqual(len(out), 65)
        self.assertEqual(out[32], 0xAA)
        self.assertEqual(out[64], 0xBB)

    def test_padding_is_zero_not_wrapped_bytes(self):
        """Wrapping used to read unrelated bytes from the end of the buffer."""
        out = self.parser.parse_to_compact_sig(self.der(b'\xaa', b'\xbb'), 0, True)
        self.assertEqual(set(out[1:32]), {0})
        self.assertEqual(set(out[33:64]), {0})

    def test_full_length_signature_is_unchanged(self):
        r = bytes(range(1, 33))
        s = bytes(range(33, 65))
        out = self.parser.parse_to_compact_sig(self.der(r, s), 1, True)
        self.assertEqual(bytes(out[1:33]), r)
        self.assertEqual(bytes(out[33:65]), s)

    def test_various_short_lengths(self):
        for lr in range(1, 33):
            with self.subTest(lr=lr):
                out = self.parser.parse_to_compact_sig(
                    self.der(bytes([0xAA] * lr), b'\xbb'), 0, True)
                self.assertEqual(bytes(out[33 - lr:33]), bytes([0xAA] * lr))
                self.assertEqual(set(out[1:33 - lr]), {0} if lr < 32 else set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
