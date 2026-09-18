#!/usr/bin/env python3
#
# Copyright (c) 2026 Toporin - https://github.com/Toporin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Run with: python3 -B -m unittest -v test_satochip_taproot.py
#
# On-card tests for the Satochip taproot/schnorr support, i.e. the applet's
# TaprootTweakPrivateKey() (INS 0x7C) and SignSchnorrHash() (INS 0x7B).
#
# For running these tests, you need a Satochip inserted in a card reader,
# ideally non-initialized. If the card is initialized, the PIN should be set to
# 123456 otherwise it will fail. A card with 2FA enabled is skipped: the schnorr
# 2FA HMAC is keyed by the paired 2FA device, which is not available here.
#
# No debug firmware is needed, unlike test_satochip_musig2.py. SignSchnorrHash()
# draws its BIP340 aux_rand on-card, so its signatures are not reproducible and
# cannot be compared to the official BIP340 vectors byte for byte -- but they do
# not need to be: a schnorr signature is checked by VERIFYING it against the
# public key. What is fully deterministic, and therefore compared value by
# value, is the BIP341 tweak.
#
# The expected values come from tests/bip340_ref.py, which is itself pinned to
# the official BIP340/BIP341/BIP86 vectors by tests/test_bip340.py. Run that
# (offline) suite first: if it fails, nothing here means anything.
#
# Applet version: taproot needs protocol v0.14 or later, and the BIP341-correct
# tweak (tweak_size 0, hash over the concatenation x(P) || h) needs v0.16-0.0 or
# later. On an older applet the BIP341 comparisons are expected to fail for a
# non-zero merkle root -- see test_report_which_tweak_the_applet_implements,
# which identifies the tweak the card actually implements.

import logging
import os
import sys
import time
import unittest
from os import urandom

from pysatochip.CardConnector import CardConnector, UninitializedSeedError
from pysatochip.JCconstants import JCconstants
from pysatochip.version import SATOCHIP_PROTOCOL_VERSION

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests"))
import bip340_ref as ref
import vectors_bip340 as v

logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
logger.warning("loglevel: " + str(logger.getEffectiveLevel()))

# applet constants
INS_TAPROOT_TWEAK_PRIVKEY = 0x7C
INS_SIGN_SCHNORR_HASH = 0x7B
TAPROOT_TWEAK = 0x00
TAPROOT_BYPASS_TWEAK = 0x01
KEY_NBR_BIP32 = 0xFF          # use the last derived BIP32 extended key

FEATURE_ID_SCHNORR = 0
FEATURE_ID_NOSTR = 1
FEATURE_ENABLED = 0

SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_INCORRECT_P1 = 0x9C10
SW_INCORRECT_P2 = 0x9C11
SW_INCORRECT_INITIALIZATION = 0x9C13
SW_BIP32_UNINITIALIZED_SEED = 0x9C14
SW_FEATURE_DISABLED = 0x9C4A

# keyslots used by these tests
SLOT_TEST_KEY = 0             # holds CARD_TEST_PRIVKEY
SLOT_EMPTY = 5                # deliberately left uninitialized


class TaprootTest(unittest.TestCase):

    cc = None
    authentikey = None
    pin = list(bytes("123456", "utf-8"))
    skip_reason = None
    schnorr_enabled = False
    nostr_enabled = False

    #
    # setup / teardown
    #

    @classmethod
    def setUpClass(cls):
        logger.info("Initialize new CardConnector...")
        try:
            cls.cc = CardConnector(None, logger.getEffectiveLevel())
            time.sleep(1)  # give some time to initialize reader...
            logger.info("ATR: " + str(cls.cc.card_get_ATR()))
        except Exception as ex:
            # no reader plugged in, or no card: skip instead of erroring out, so
            # that running the whole repository test suite stays possible on a
            # machine without a Satochip
            cls.skip_reason = "unable to connect to a card reader: %r" % (ex,)
            return

        if not cls.cc.card_present:
            cls.skip_reason = "no card in the reader"
            return

        (response, sw1, sw2, d) = cls.cc.card_get_status()
        if cls.cc.card_type != "Satochip":
            cls.skip_reason = "not a Satochip (card_type=%s)" % cls.cc.card_type
            return

        logger.info(f"Satochip version={d['protocol_version']}")
        logger.info(f"Pysatochip supported version={SATOCHIP_PROTOCOL_VERSION}")

        if not cls.cc.setup_done:
            cls._setup_card()
            (response, sw1, sw2, d) = cls.cc.card_get_status()

        if cls.cc.needs_secure_channel:
            cls.cc.card_initiate_secure_channel()

        try:
            cls.cc.card_verify_PIN_deprecated(0, cls.pin)
        except RuntimeError as ex:
            cls.skip_reason = "unable to verify the PIN: %r" % (ex,)
            return

        if cls.cc.needs_2FA:
            # the schnorr 2FA HMAC is keyed by the paired 2FA device
            cls.skip_reason = "2FA is enabled on this card"
            return

        try:
            cls.authentikey = cls.cc.card_export_authentikey()
        except UninitializedSeedError as ex:
            cls.authentikey = None
            logger.warning(f"Unable to export the authentikey: {ex!r}")

        # the tweak (and schnorr signing) honours feature_schnorr_policy, and
        # the bypass path honours feature_nostr_policy: enable both if needed
        cls.schnorr_enabled = cls._enable_feature(FEATURE_ID_SCHNORR, "schnorr")
        cls.nostr_enabled = cls._enable_feature(FEATURE_ID_NOSTR, "nostr")
        if not cls.schnorr_enabled:
            cls.skip_reason = ("the schnorr feature is disabled or blocked on "
                               "this card (a blocked feature needs a factory "
                               "reset)")
            return

        # import the test private key used by the keyslot tests
        try:
            # the slot may still hold the key from an aborted run; importing
            # over an existing key fails with 0x9C10
            try:
                cls.cc.satochip_reset_privkey(SLOT_TEST_KEY)
            except Exception:
                pass  # slot already empty
            cls.cc.satochip_import_privkey(
                SLOT_TEST_KEY, bytes.fromhex(v.CARD_TEST_PRIVKEY))
            logger.info(f"Imported the test privkey in keyslot {SLOT_TEST_KEY}")
        except Exception as ex:
            cls.skip_reason = "unable to import the test privkey: %r" % (ex,)

    @classmethod
    def _setup_card(cls):
        logger.info("Setting up the applet (first use)...")
        (response, sw1, sw2) = cls.cc.card_setup(
            0x05, 0x01, cls.pin, list(urandom(16)),
            0x01, 0x01, list(urandom(16)), list(urandom(16)),
            32, 0x0000, 0x01, 0x01, 0x01)
        if sw1 != 0x90 or sw2 != 0x00:
            cls.skip_reason = "unable to set up the applet (sw12=%s)" % hex(
                256 * sw1 + sw2)

    @classmethod
    def _enable_feature(cls, feature_id, name):
        """Return True if the feature is (now) enabled. A BLOCKED feature is
        not recoverable without a factory reset, so it is only reported."""
        policy = {FEATURE_ID_SCHNORR: cls.cc.feature_schnorr_policy,
                  FEATURE_ID_NOSTR: cls.cc.feature_nostr_policy}[feature_id]
        if policy is None:
            # applet predates the feature policies: the feature is always on
            return True
        if policy == FEATURE_ENABLED:
            return True
        logger.info(f"Enabling the {name} feature (policy was {policy})...")
        (response, sw1, sw2) = cls.cc.card_set_feature_policy(
            feature_id, FEATURE_ENABLED)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.warning(f"Unable to enable the {name} feature "
                           f"(sw12={hex(256 * sw1 + sw2)})")
            return False
        cls.cc.card_get_status()
        return True

    @classmethod
    def tearDownClass(cls):
        if cls.cc is None or cls.skip_reason is not None:
            return
        try:
            cls.cc.card_verify_PIN_deprecated(0, cls.pin)
            cls.cc.satochip_reset_privkey(SLOT_TEST_KEY)
        except Exception as ex:
            logger.warning(f"In tearDownClass: unable to reset the test "
                           f"privkey: {ex!r}")

    def setUp(self):
        if TaprootTest.skip_reason is not None:
            self.skipTest(TaprootTest.skip_reason)
        # the applet logs the user out after a seed reset, so the PIN is
        # verified again before each test
        (response, sw1, sw2) = self.cc.card_verify_PIN_deprecated(0, self.pin)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))

    def tearDown(self):
        # Leave the card unseeded whatever the test did, so that a test failing
        # before its own card_reset_seed() does not cascade into the next one as
        # 'card is already seeded' (0x9C17). Errors here are logged rather than
        # raised, so they cannot mask the failure of the test itself.
        if TaprootTest.skip_reason is not None:
            return
        try:
            self.cc.card_get_status()  # refresh is_seeded
            if self.cc.is_seeded:
                (response, sw1, sw2) = self.cc.card_reset_seed(self.pin)
                if sw1 != 0x90 or sw2 != 0x00:
                    logger.warning(f"In tearDown: unable to reset the seed "
                                   f"(sw12={hex(sw1)} {hex(sw2)})")
        except Exception as ex:
            logger.warning(f"In tearDown: error while resetting the seed: "
                           f"{ex!r}")

    #
    # raw APDU helpers
    #
    # CardConnector.card_taproot_tweak_privkey() cannot express every case
    # these tests need: it always sends a 32-byte tweak, so it can produce
    # neither the BIP341 'no script tree' form (tweak_size 0) nor the invalid
    # sizes and p2 values the applet must reject. The APDU is built here
    # instead, which also keeps the tests independent of client-side changes.
    #

    def _tweak_apdu(self, key_nbr, tweak, p2=TAPROOT_TWEAK):
        """Send INS_TAPROOT_TWEAK_PRIVKEY. `tweak` is the merkle root h as
        bytes (b'' for 'no script tree'), or None to send no data at all."""
        if tweak is None:
            data = []
        else:
            data = [len(tweak)] + list(tweak)
        apdu = [JCconstants.CardEdge_CLA, INS_TAPROOT_TWEAK_PRIVKEY,
                key_nbr, p2, len(data)] + data
        return self.cc.card_transmit(apdu)

    def _tweak(self, key_nbr, tweak, p2=TAPROOT_TWEAK):
        """Tweak and return the 65-byte uncompressed tweaked pubkey."""
        (response, sw1, sw2) = self._tweak_apdu(key_nbr, tweak, p2)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK),
                         "TaprootTweakPrivateKey failed")
        return self._parse_tweak_response(response)

    def _parse_tweak_response(self, response):
        """response: [pubkey_size(2b) | uncompressed_pubkey(65b) |
                      sig_size(2b) | sig_authentikey]

        The authentikey signature is verified here too: it is the only thing
        binding the returned pubkey to this card, and a client that derives a
        taproot address from an unauthenticated pubkey would happily pay to a
        pubkey injected by a malicious reader.
        """
        pubkey_size = (response[0] << 8) + response[1]
        self.assertEqual(pubkey_size, 65)
        pubkey = bytes(response[2:2 + pubkey_size])
        self.assertEqual(pubkey[0], 0x04)

        offset = 2 + pubkey_size
        sig_size = (response[offset] << 8) + response[offset + 1]
        sig = bytes(response[offset + 2:offset + 2 + sig_size])
        self.assertGreater(sig_size, 0)
        if self.authentikey is not None:
            # the applet signs [pubkey_size(2b) | pubkey(65b)]
            self.cc.parser.verify_signature(
                bytes(response[0:offset]), sig, self.authentikey)
        return pubkey

    def _sign_schnorr(self, txhash):
        """Sign a 32-byte hash with the currently staged tweaked key."""
        (response, sw1, sw2) = self.cc.card_sign_schnorr_hash(
            0x00, list(txhash), None)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK),
                         "SignSchnorrHash failed")
        sig = bytes(response)
        self.assertEqual(len(sig), 64)
        return sig

    def _sign_schnorr_apdu(self, data):
        apdu = [JCconstants.CardEdge_CLA, INS_SIGN_SCHNORR_HASH,
                0x00, 0x00, len(data)] + list(data)
        return self.cc.card_transmit(apdu)

    def _import_bip86_seed(self):
        # the card may still be seeded from an aborted run: importing over an
        # existing seed fails with 0x9C17, which would hide the real failure
        self.cc.card_get_status()
        if self.cc.is_seeded:
            (response, sw1, sw2) = self.cc.card_reset_seed(self.pin)
            self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))
            self.cc.card_verify_PIN_deprecated(0, self.pin)
        self.cc.card_bip32_import_seed(bytes.fromhex(v.BIP86_SEED))

    #
    # BIP341 / BIP86 tweak, against the official vectors
    #

    def test_taproot_tweak_bip86_key_path_only(self):
        """BIP86: internal key from the seed, tweaked with an EMPTY merkle root.

        This is the whole key-path-only spending flow, and the only test here
        whose expected values are published: a mismatch means the card cannot
        produce a standard taproot address.

        Needs applet v0.16-0.0 or later (tweak_size 0).
        """
        print("\n\n[test_satochip_taproot] test_taproot_tweak_bip86_key_path_only:")
        self._import_bip86_seed()

        for vec in v.BIP86_KEYS:
            with self.subTest(path=vec["path"]):
                (pubkey, chaincode) = self.cc.card_bip32_get_extendedkey(
                    vec["path"])
                internal = pubkey.get_public_key_bytes(compressed=False)
                self.assertEqual(ref.x_only(internal).hex(),
                                 vec["internal_key"],
                                 "the card derived the wrong internal key")

                tweaked = self._tweak(KEY_NBR_BIP32, b"")
                self.assertEqual(ref.x_only(tweaked).hex(), vec["output_key"],
                                 "the card computed a non-BIP86 output key")
                # the scriptPubKey/address a wallet would show for it
                self.assertEqual("5120" + ref.x_only(tweaked).hex(),
                                 vec["script_pubkey"])

        (response, sw1, sw2) = self.cc.card_reset_seed(self.pin)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))

    def test_taproot_tweak_matches_reference_for_every_merkle_root(self):
        """The tweak is deterministic, so compare it value by value.

        Covers both shapes of h the applet accepts: empty (no script tree) and
        a 32-byte merkle root, the latter taken from the BIP341 wallet vectors
        plus the two extremes.
        """
        print("\n\n[test_satochip_taproot] test_taproot_tweak_matches_reference_for_every_merkle_root:")
        seckey = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        internal = ref.pubkey_gen(seckey)

        pubkey = self.cc.satochip_get_pubkey_from_keyslot(SLOT_TEST_KEY)
        self.assertEqual(
            ref.x_only(pubkey.get_public_key_bytes(compressed=False)),
            internal, "keyslot %d does not hold the test key" % SLOT_TEST_KEY)

        merkle_roots = [b""]
        merkle_roots += [bytes.fromhex(vec["merkle_root"])
                         for vec in v.BIP341_TWEAK_VECTORS[1:]]
        merkle_roots += [b"\x00" * 32, b"\xff" * 32]

        for h in merkle_roots:
            with self.subTest(h=h.hex() or "(empty)"):
                _, expected = ref.taproot_tweak_pubkey(internal, h)
                tweaked = self._tweak(SLOT_TEST_KEY, h)
                self.assertEqual(ref.x_only(tweaked), expected)
                # the card returns the full point of the tweaked seckey, so the
                # y coordinate must be consistent too (x_only would hide a
                # wrong parity, and the parity is what BIP341 commits to)
                self.assertEqual(
                    tweaked,
                    ref.m.point_to_ser(
                        ref.G * int.from_bytes(
                            ref.taproot_tweak_seckey(seckey, h), "big"),
                        False))

    def test_empty_and_zero_merkle_roots_give_different_keys(self):
        """tweak_size=0 and 32 zero bytes are NOT the same tweak.

        BIP341 hashes x(P) || h, so an empty h hashes 32 bytes and an all-zero
        h hashes 64. Only the former is the BIP86 key. A client that sends 32
        zero bytes for a key-path-only output gets a key no standard signer can
        spend, which is exactly the mistake
        CardConnector.card_taproot_tweak_privkey() makes today -- see
        test_client_helper_computes_the_bip86_key.
        """
        print("\n\n[test_satochip_taproot] test_empty_and_zero_merkle_roots_give_different_keys:")
        from_empty = self._tweak(SLOT_TEST_KEY, b"")
        from_zeros = self._tweak(SLOT_TEST_KEY, b"\x00" * 32)
        self.assertNotEqual(from_empty, from_zeros)

        internal = ref.pubkey_gen(bytes.fromhex(v.CARD_TEST_PRIVKEY))
        self.assertEqual(ref.x_only(from_empty),
                         ref.taproot_tweak_pubkey(internal, b"")[1])
        self.assertEqual(ref.x_only(from_zeros),
                         ref.taproot_tweak_pubkey(internal, b"\x00" * 32)[1])

    def test_client_helper_computes_the_bip86_key(self):
        """CardConnector.card_taproot_tweak_privkey() must reach BIP86.

        Regression guard for pysatochip 0.18.2. The helper used to pad a
        missing tweak to 32 zero bytes and reject anything shorter, so it could
        not send tweak_size=0, and satochip_cli.py 'satochip-sign-schnorr-hash'
        (which passes tweak=None) signed under a non-BIP341 key on a v0.16
        card. tweak=None now means "no script tree".
        """
        print("\n\n[test_satochip_taproot] test_client_helper_computes_the_bip86_key:")
        internal = ref.pubkey_gen(bytes.fromhex(v.CARD_TEST_PRIVKEY))
        _, expected = ref.taproot_tweak_pubkey(internal, b"")

        (response, sw1, sw2) = self.cc.card_taproot_tweak_privkey(
            SLOT_TEST_KEY, None, bypass_flag=False)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))
        tweaked = self._parse_tweak_response(response)
        self.assertEqual(
            ref.x_only(tweaked), expected,
            "card_taproot_tweak_privkey(tweak=None) does not produce the "
            "key-path-only (BIP86) key: it sends 32 zero bytes where the "
            "applet expects tweak_size=0")

    def test_taproot_tweak_from_bip32_key_matches_reference(self):
        """Same comparison as above, but for the BIP32 path (key_nbr 0xFF)."""
        print("\n\n[test_satochip_taproot] test_taproot_tweak_from_bip32_key_matches_reference:")
        self._import_bip86_seed()
        (pubkey, chaincode) = self.cc.card_bip32_get_extendedkey(
            v.BIP86_KEYS[0]["path"])
        internal = ref.x_only(pubkey.get_public_key_bytes(compressed=False))

        for h in (b"", bytes.fromhex(v.BIP341_TWEAK_VECTORS[1]["merkle_root"])):
            with self.subTest(h=h.hex() or "(empty)"):
                # re-derive: the tweak consumes the staged extended key
                self.cc.card_bip32_get_extendedkey(v.BIP86_KEYS[0]["path"])
                tweaked = self._tweak(KEY_NBR_BIP32, h)
                self.assertEqual(ref.x_only(tweaked),
                                 ref.taproot_tweak_pubkey(internal, h)[1])

        (response, sw1, sw2) = self.cc.card_reset_seed(self.pin)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))

    #
    # BIP340 signing
    #

    def test_sign_schnorr_hash_verifies_under_the_tweaked_key(self):
        """The signature must verify under the TWEAKED x-only pubkey."""
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_verifies_under_the_tweaked_key:")
        # the distinct 32-byte messages of the official BIP340 vectors, plus a
        # random one: the card signs a hash, so the interesting inputs are the
        # edge values (all-zero, all-ff) rather than the lengths
        hashes = list(dict.fromkeys(
            bytes.fromhex(vec["msg"]) for vec in v.BIP340_VECTORS
            if len(vec["msg"]) == 64))
        hashes.append(urandom(32))

        for h in (b"", bytes.fromhex(v.BIP341_TWEAK_VECTORS[1]["merkle_root"])):
            x_only_pubkey = ref.x_only(self._tweak(SLOT_TEST_KEY, h))
            for txhash in hashes:
                with self.subTest(h=h.hex() or "(empty)", msg=txhash.hex()):
                    sig = self._sign_schnorr(txhash)
                    self.assertTrue(
                        ref.schnorr_verify(x_only_pubkey, txhash, sig),
                        "invalid BIP340 signature: sig=%s pubkey=%s msg=%s"
                        % (sig.hex(), x_only_pubkey.hex(), txhash.hex()))

    def test_sign_schnorr_hash_does_not_verify_under_the_internal_key(self):
        """A signature under the untweaked key would mean the tweak was skipped.

        Applet versions before v0.16-0.0 silently bypassed the tweak for any p2
        other than 0x00, so this is a regression guard, not a theoretical one.
        """
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_does_not_verify_under_the_internal_key:")
        internal = ref.pubkey_gen(bytes.fromhex(v.CARD_TEST_PRIVKEY))
        txhash = urandom(32)

        tweaked = self._tweak(SLOT_TEST_KEY, b"")
        self.assertNotEqual(ref.x_only(tweaked), internal)
        sig = self._sign_schnorr(txhash)
        self.assertTrue(ref.schnorr_verify(ref.x_only(tweaked), txhash, sig))
        self.assertFalse(ref.schnorr_verify(internal, txhash, sig),
                         "the card signed with the UNTWEAKED key")

    def test_sign_schnorr_hash_is_randomized(self):
        """Signing the same hash twice must give two different nonces.

        SignSchnorrHash() draws aux_rand on-card. If that ever regressed to a
        fixed value the nonce would become deterministic for a given (key, m);
        a nonce repeated across two different messages leaks the private key
        outright, so a card that returns the same R twice is a critical failure
        and not a cosmetic one.
        """
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_is_randomized:")
        txhash = urandom(32)
        x_only_pubkey = ref.x_only(self._tweak(SLOT_TEST_KEY, b""))

        sigs = []
        for _ in range(4):
            sig = self._sign_schnorr(txhash)
            self.assertTrue(ref.schnorr_verify(x_only_pubkey, txhash, sig))
            sigs.append(sig)

        nonces = {sig[0:32] for sig in sigs}
        self.assertEqual(len(nonces), len(sigs),
                         "the card reused a schnorr nonce R")

    def test_sign_schnorr_hash_twice_after_one_tweak(self):
        """Two signatures after a single tweak must both use the tweaked key.

        Regression guard for the applet fix. SignSchnorrHash() borrows the
        `taproot_tweakedkey` object as scratch storage to compute R = rand*G

            taproot_tweakedkey.setS(recvBuffer, OFFSET_BIP340_t, (short)32);
            keyAgreement.init(taproot_tweakedkey);
            keyAgreement.generateSecret(...);  // R = rand*G

        (CardEdge.java, SignSchnorrHash) and used not to restore it. The
        tweaked private key was therefore destroyed by the first signature, and
        every later signature was made with the PREVIOUS signature's nonce as
        its private key -- silently, returning a well-formed 64-byte signature
        that simply does not verify under the taproot output key.

        Why this matters beyond 'sign twice fails': signing several inputs of
        one transaction from a single tweaked key is the normal taproot flow,
        and the card gave no error. It also meant s1 = k1 + e1*d was published
        alongside a second signature whose secret is exactly k1, which puts the
        tweaked private key one solved discrete log away instead of two.

        Signing again after re-tweaking always worked, which is why
        satochip_cli.py (one tweak per signature) never hit this.

        A failure here means the card is running an applet older than the fix;
        the other signing tests will fail with it too.
        """
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_twice_after_one_tweak:")
        x_only_pubkey = ref.x_only(self._tweak(SLOT_TEST_KEY, b""))
        txhash = urandom(32)

        sig1 = self._sign_schnorr(txhash)
        self.assertTrue(ref.schnorr_verify(x_only_pubkey, txhash, sig1),
                        "even the first signature is invalid")

        sig2 = self._sign_schnorr(txhash)
        if not ref.schnorr_verify(x_only_pubkey, txhash, sig2):
            clobbered = ref.schnorr_verify(sig1[0:32], txhash, sig2)
            self.fail(
                "the second signature does not verify under the tweaked key "
                "%s (sig2=%s); it verifies under x(R) of the first signature "
                "instead: %s -- the tweaked key was overwritten by the first "
                "signature's nonce"
                % (x_only_pubkey.hex(), sig2.hex(), clobbered))

    def test_sign_schnorr_hash_signs_the_hash_it_was_given(self):
        """A signature over one hash must not verify against another."""
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_signs_the_hash_it_was_given:")
        tweaked = self._tweak(SLOT_TEST_KEY, b"")
        x_only_pubkey = ref.x_only(tweaked)
        txhash = urandom(32)
        other = urandom(32)

        sig = self._sign_schnorr(txhash)
        self.assertTrue(ref.schnorr_verify(x_only_pubkey, txhash, sig))
        self.assertFalse(ref.schnorr_verify(x_only_pubkey, other, sig))

    def test_sign_schnorr_hash_after_bip32_tweak(self):
        """End to end: seed -> BIP86 key -> tweak -> sign -> verify."""
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_after_bip32_tweak:")
        self._import_bip86_seed()
        vec = v.BIP86_KEYS[0]
        self.cc.card_bip32_get_extendedkey(vec["path"])
        tweaked = self._tweak(KEY_NBR_BIP32, b"")
        self.assertEqual(ref.x_only(tweaked).hex(), vec["output_key"])

        txhash = urandom(32)
        sig = self._sign_schnorr(txhash)
        self.assertTrue(
            ref.schnorr_verify(bytes.fromhex(vec["output_key"]), txhash, sig))

        (response, sw1, sw2) = self.cc.card_reset_seed(self.pin)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))

    #
    # the bypass (Nostr) path
    #

    def test_bypass_tweak_signs_under_the_untweaked_key(self):
        """p2=0x01 copies the private key as is: used for Nostr, not taproot."""
        print("\n\n[test_satochip_taproot] test_bypass_tweak_signs_under_the_untweaked_key:")
        if not TaprootTest.nostr_enabled:
            self.skipTest("the nostr feature is disabled or blocked")
        internal = ref.pubkey_gen(bytes.fromhex(v.CARD_TEST_PRIVKEY))

        # this is the path satochip_cli.py 'satochip-sign-nostr-event' takes
        (response, sw1, sw2) = self.cc.card_taproot_tweak_privkey(
            SLOT_TEST_KEY, None, bypass_flag=True)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))
        pubkey = self._parse_tweak_response(response)
        self.assertEqual(ref.x_only(pubkey), internal,
                         "the bypass path must not tweak the key")

        txhash = urandom(32)
        sig = self._sign_schnorr(txhash)
        self.assertTrue(ref.schnorr_verify(internal, txhash, sig))

    #
    # input validation
    #

    def test_taproot_tweak_rejects_invalid_tweak_sizes(self):
        """Only tweak_size 0 and 32 are valid (applet v0.16-0.0 and later)."""
        print("\n\n[test_satochip_taproot] test_taproot_tweak_rejects_invalid_tweak_sizes:")
        for size in (1, 16, 31, 33, 64):
            with self.subTest(tweak_size=size):
                (response, sw1, sw2) = self._tweak_apdu(
                    SLOT_TEST_KEY, b"\x11" * size)
                self.assertEqual(hex(256 * sw1 + sw2), hex(SW_WRONG_LENGTH))

    def test_taproot_tweak_rejects_a_truncated_tweak(self):
        """An announced tweak_size larger than the data must be rejected."""
        print("\n\n[test_satochip_taproot] test_taproot_tweak_rejects_a_truncated_tweak:")
        # data = [32 | 16 bytes only]
        data = [32] + list(b"\x11" * 16)
        apdu = [JCconstants.CardEdge_CLA, INS_TAPROOT_TWEAK_PRIVKEY,
                SLOT_TEST_KEY, TAPROOT_TWEAK, len(data)] + data
        (response, sw1, sw2) = self.cc.card_transmit(apdu)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_WRONG_LENGTH))

    def test_taproot_tweak_rejects_empty_data(self):
        """p2=0x00 needs at least the tweak_size byte."""
        print("\n\n[test_satochip_taproot] test_taproot_tweak_rejects_empty_data:")
        (response, sw1, sw2) = self._tweak_apdu(SLOT_TEST_KEY, None)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_WRONG_LENGTH))

    def test_taproot_tweak_rejects_unknown_p2(self):
        """An unknown p2 must not silently bypass the tweak.

        Before v0.16-0.0 any p2 other than 0x00 copied the private key as is,
        so a client sending an unexpected p2 signed with the untweaked key.
        """
        print("\n\n[test_satochip_taproot] test_taproot_tweak_rejects_unknown_p2:")
        for p2 in (0x02, 0x10, 0xFF):
            with self.subTest(p2=hex(p2)):
                (response, sw1, sw2) = self._tweak_apdu(
                    SLOT_TEST_KEY, b"", p2=p2)
                self.assertEqual(hex(256 * sw1 + sw2), hex(SW_INCORRECT_P2))

    def test_taproot_tweak_rejects_an_empty_keyslot(self):
        print("\n\n[test_satochip_taproot] test_taproot_tweak_rejects_an_empty_keyslot:")
        try:
            self.cc.satochip_reset_privkey(SLOT_EMPTY)
        except Exception:
            pass  # already empty
        (response, sw1, sw2) = self._tweak_apdu(SLOT_EMPTY, b"")
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_INCORRECT_P1))

    def test_taproot_tweak_rejects_bip32_key_without_a_seed(self):
        """key_nbr 0xFF with no seed imported."""
        print("\n\n[test_satochip_taproot] test_taproot_tweak_rejects_bip32_key_without_a_seed:")
        self.cc.card_get_status()
        if self.cc.is_seeded:
            (response, sw1, sw2) = self.cc.card_reset_seed(self.pin)
            self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))
            self.cc.card_verify_PIN_deprecated(0, self.pin)
        (response, sw1, sw2) = self._tweak_apdu(KEY_NBR_BIP32, b"")
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_BIP32_UNINITIALIZED_SEED))

    def test_sign_schnorr_hash_rejects_signing_without_a_staged_key(self):
        """Signing with no tweaked key staged must return a clean error.

        resetSeed() and resetToFactory() both clearKey() the tweaked key. The
        applet used to walk straight into keyAgreement.init() on the cleared
        key, which throws an uncaught CryptoException (0x6F00); it now answers
        SW_INCORRECT_INITIALIZATION.
        """
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_rejects_signing_without_a_staged_key:")
        # stage a key first, so the test really exercises the clearing
        self._import_bip86_seed()
        self.cc.card_bip32_get_extendedkey(v.BIP86_KEYS[0]["path"])
        self._tweak(KEY_NBR_BIP32, b"")
        self._sign_schnorr(urandom(32))

        (response, sw1, sw2) = self.cc.card_reset_seed(self.pin)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))
        self.cc.card_verify_PIN_deprecated(0, self.pin)

        (response, sw1, sw2) = self._sign_schnorr_apdu(urandom(32))
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_INCORRECT_INITIALIZATION))

    def test_sign_schnorr_hash_rejects_a_short_hash(self):
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_rejects_a_short_hash:")
        self._tweak(SLOT_TEST_KEY, b"")
        for size in (0, 1, 31):
            with self.subTest(hash_size=size):
                (response, sw1, sw2) = self._sign_schnorr_apdu(b"\x11" * size)
                self.assertEqual(hex(256 * sw1 + sw2), hex(SW_WRONG_LENGTH))

    def test_sign_schnorr_hash_rejects_a_wrong_length_hash_via_the_client(self):
        print("\n\n[test_satochip_taproot] test_sign_schnorr_hash_rejects_a_wrong_length_hash_via_the_client:")
        for bad in (list(b"\x11" * 31), list(b"\x11" * 33)):
            with self.subTest(hash_size=len(bad)):
                with self.assertRaises(ValueError):
                    self.cc.card_sign_schnorr_hash(0x00, bad, None)

    def test_taproot_tweak_honours_the_schnorr_feature_policy(self):
        """A tweaked key is only usable for schnorr, so the tweak must respect
        feature_schnorr_policy. Before v0.16-0.0 only the bypass (nostr) path
        checked a policy, so schnorr could be used while 'disabled'.

        The policy is restored in a finally block. Only FEATURE_DISABLED (1) is
        used here; FEATURE_BLOCKED (2) is deliberately never set, as it would
        need a factory reset to undo.
        """
        print("\n\n[test_satochip_taproot] test_taproot_tweak_honours_the_schnorr_feature_policy:")
        FEATURE_DISABLED = 1
        (response, sw1, sw2) = self.cc.card_set_feature_policy(
            FEATURE_ID_SCHNORR, FEATURE_DISABLED)
        self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))
        try:
            (response, sw1, sw2) = self._tweak_apdu(SLOT_TEST_KEY, b"")
            self.assertEqual(hex(256 * sw1 + sw2), hex(SW_FEATURE_DISABLED),
                             "the tweak ignored feature_schnorr_policy")

            (response, sw1, sw2) = self.cc.card_sign_schnorr_hash(
                0x00, list(urandom(32)), None)
            self.assertEqual(hex(256 * sw1 + sw2), hex(SW_FEATURE_DISABLED),
                             "signing ignored feature_schnorr_policy")

            # the bypass path answers to feature_nostr_policy instead, so it
            # must still work while schnorr is disabled
            if TaprootTest.nostr_enabled:
                (response, sw1, sw2) = self._tweak_apdu(
                    SLOT_TEST_KEY, None, p2=TAPROOT_BYPASS_TWEAK)
                self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK))
        finally:
            (response, sw1, sw2) = self.cc.card_set_feature_policy(
                FEATURE_ID_SCHNORR, FEATURE_ENABLED)
            self.assertEqual(hex(256 * sw1 + sw2), hex(SW_OK),
                             "unable to re-enable the schnorr feature")
            self.cc.card_get_status()

    #
    # applet version / legacy compatibility
    #
    # These tell apart a BIP341-compliant applet from a pre-v0.16-0.0 one, so
    # that a failure above can be read as 'old firmware' rather than 'broken
    # card', and check the compatibility claim the fix relies on.
    #

    def test_report_which_tweak_the_applet_implements(self):
        print("\n\n[test_satochip_taproot] test_report_which_tweak_the_applet_implements:")
        seckey = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        internal = ref.pubkey_gen(seckey)
        h = bytes.fromhex(v.BIP341_TWEAK_VECTORS[1]["merkle_root"])

        bip341 = ref.taproot_tweak_pubkey(internal, h)[1]
        legacy = ref.pubkey_gen(ref.legacy_xor_tweak_seckey(seckey, h))
        self.assertNotEqual(bip341, legacy)

        got = ref.x_only(self._tweak(SLOT_TEST_KEY, h))
        if got == bip341:
            logger.info("applet computes the BIP341 tweak (v0.16-0.0 or later)")
        elif got == legacy:
            self.fail("applet computes the legacy XOR tweak (v0.15-0.1 or "
                      "earlier): the BIP341 tests above are expected to fail "
                      "for a non-zero merkle root. Upgrade the applet.")
        else:
            self.fail("applet computes an unknown tweak: %s (BIP341 expects "
                      "%s)" % (got.hex(), bip341.hex()))

    def test_legacy_zero_tweak_is_still_reachable(self):
        """The 'BIP86 keys are unaffected by the fix' claim, checked on-card.

        The legacy all-zero-h tweak must equal what tweak_size=0 computes now,
        otherwise the v0.16-0.0 upgrade would strand existing key-path-only
        funds.
        """
        print("\n\n[test_satochip_taproot] test_legacy_zero_tweak_is_still_reachable:")
        seckey = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        legacy_zero = ref.pubkey_gen(
            ref.legacy_xor_tweak_seckey(seckey, b"\x00" * 32))
        tweaked = ref.x_only(self._tweak(SLOT_TEST_KEY, b""))
        self.assertEqual(tweaked, legacy_zero)


if __name__ == "__main__":
    unittest.main(verbosity=2)
