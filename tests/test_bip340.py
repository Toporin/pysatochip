# -*- coding: utf-8 -*-
"""Offline tests for the BIP340/BIP341 host-side reference (bip340_ref.py).

No card needed: run with `python tests/test_bip340.py`, or as part of
`python tests/run_all.py`.

This layer exists so that a failure of the on-card suite
(test_satochip_taproot.py) is never ambiguous. That suite compares card output
against bip340_ref; if the reference itself were wrong, the card tests would be
meaningless. Here the reference is pinned to the official vectors:

  * all 19 BIP340 vectors, signing AND verification, including the 10 malformed
    inputs a verifier must reject;
  * all 7 BIP341 tweak vectors, both the pubkey and the seckey side;
  * the BIP86 internal_key -> output_key pairs.

It also pins the two facts the Satochip taproot code depends on and that are
easy to get subtly wrong:

  * h = b'' ("no script tree") and h = 32 zero bytes are DIFFERENT tweaks;
  * the pre-0.16 XOR tweak coincides with BIP341 exactly when h is all-zero,
    which is what makes the applet's "BIP86 keys are unaffected" claim true.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import bip340_ref as ref
import vectors_bip340 as v
from pysatochip import ec_math as m


class TestTaggedHash(unittest.TestCase):

    def test_matches_the_bip340_definition(self):
        # hash_tag(msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
        import hashlib
        tag = b"TapTweak"
        th = hashlib.sha256(tag).digest()
        self.assertEqual(
            ref.tagged_hash(tag, b"hello"),
            hashlib.sha256(th + th + b"hello").digest())

    def test_str_and_bytes_tags_agree(self):
        self.assertEqual(ref.tagged_hash("TapTweak", b""),
                         ref.tagged_hash(b"TapTweak", b""))


class TestLiftX(unittest.TestCase):

    def test_returns_the_even_y_point(self):
        for vec in v.BIP341_TWEAK_VECTORS:
            x = bytes.fromhex(vec["internal_pubkey"])
            point = ref.lift_x(x)
            self.assertTrue(m.contains_point(point.x, point.y))
            self.assertTrue(ref.has_even_y(point))
            self.assertEqual(ref.x_only(point), x)

    def test_rejects_x_above_the_field_size(self):
        # BIP340 vector 14: "public key is not a valid X coordinate because it
        # exceeds the field size"
        with self.assertRaises(ref.InvalidBIP340Error):
            ref.lift_x(m.CURVE_P.to_bytes(32, "big"))
        with self.assertRaises(ref.InvalidBIP340Error):
            ref.lift_x((m.CURVE_P + 1).to_bytes(32, "big"))

    def test_rejects_x_not_on_the_curve(self):
        # BIP340 vector 5: "public key not on the curve"
        with self.assertRaises(ref.InvalidBIP340Error):
            ref.lift_x(bytes.fromhex(
                "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34"))

    def test_rejects_wrong_length(self):
        for bad in (b"", b"\x01" * 31, b"\x01" * 33):
            with self.assertRaises(ref.InvalidBIP340Error):
                ref.lift_x(bad)


class TestXOnly(unittest.TestCase):
    """x_only() has to accept the card's 65-byte uncompressed pubkey."""

    def test_accepts_every_serialization_of_the_same_point(self):
        point = m.GENERATOR * 12345
        expected = point.x.to_bytes(32, "big")
        self.assertEqual(ref.x_only(point), expected)
        self.assertEqual(ref.x_only(m.point_to_ser(point, False)), expected)
        self.assertEqual(ref.x_only(m.point_to_ser(point, True)), expected)
        self.assertEqual(ref.x_only(expected), expected)

    def test_drops_the_y_parity(self):
        # the tweaked key returned by the card may have odd y; only x matters
        point = m.GENERATOR * 12345
        self.assertEqual(ref.x_only(m.point_to_ser(point, False)),
                         ref.x_only(m.point_to_ser(-point, False)))

    def test_rejects_unexpected_length(self):
        with self.assertRaises(ref.InvalidBIP340Error):
            ref.x_only(b"\x04" * 64)


class TestBIP340Vectors(unittest.TestCase):
    """The official bip-0340/test-vectors.csv, both directions."""

    def test_all_vectors_verify_as_specified(self):
        for vec in v.BIP340_VECTORS:
            with self.subTest(index=vec["index"], comment=vec["comment"]):
                self.assertEqual(
                    ref.schnorr_verify(bytes.fromhex(vec["pubkey"]),
                                       bytes.fromhex(vec["msg"]),
                                       bytes.fromhex(vec["sig"])),
                    vec["result"])

    def test_signing_reproduces_the_expected_signatures(self):
        signed = 0
        for vec in v.BIP340_VECTORS:
            if not vec["seckey"]:
                continue
            with self.subTest(index=vec["index"], comment=vec["comment"]):
                sig = ref.schnorr_sign(bytes.fromhex(vec["seckey"]),
                                       bytes.fromhex(vec["msg"]),
                                       bytes.fromhex(vec["aux_rand"]))
                self.assertEqual(sig.hex(), vec["sig"])
                signed += 1
        self.assertEqual(signed, 8)  # vectors 0-3 and 15-18 carry a seckey

    def test_pubkey_gen_matches_the_vectors(self):
        for vec in v.BIP340_VECTORS:
            if not vec["seckey"]:
                continue
            with self.subTest(index=vec["index"]):
                self.assertEqual(
                    ref.pubkey_gen(bytes.fromhex(vec["seckey"])).hex(),
                    vec["pubkey"])

    def test_variable_length_messages(self):
        # vectors 15-18 (added 2022-12) cover messages of 0, 1, 17, 100 bytes;
        # the card only ever signs a 32-byte hash, but the reference must not
        # silently assume that
        lengths = sorted(len(bytes.fromhex(vec["msg"]))
                         for vec in v.BIP340_VECTORS if vec["index"] >= 15)
        self.assertEqual(lengths, [0, 1, 17, 100])

    def test_a_valid_signature_is_rejected_for_another_message(self):
        vec = v.BIP340_VECTORS[1]
        pubkey = bytes.fromhex(vec["pubkey"])
        sig = bytes.fromhex(vec["sig"])
        self.assertTrue(
            ref.schnorr_verify(pubkey, bytes.fromhex(vec["msg"]), sig))
        self.assertFalse(ref.schnorr_verify(pubkey, b"\x00" * 32, sig))

    def test_malformed_signature_lengths_are_rejected(self):
        vec = v.BIP340_VECTORS[1]
        pubkey = bytes.fromhex(vec["pubkey"])
        msg = bytes.fromhex(vec["msg"])
        sig = bytes.fromhex(vec["sig"])
        for bad in (sig[:63], sig + b"\x00", b""):
            self.assertFalse(ref.schnorr_verify(pubkey, msg, bad))

    def test_signing_rejects_out_of_range_private_keys(self):
        for bad in (b"\x00" * 32,
                    m.CURVE_ORDER.to_bytes(32, "big"),
                    b"\xff" * 32):
            with self.assertRaises(ref.InvalidBIP340Error):
                ref.schnorr_sign(bad, b"\x00" * 32, b"\x00" * 32)

    def test_signing_requires_32_bytes_of_aux_rand(self):
        with self.assertRaises(ref.InvalidBIP340Error):
            ref.schnorr_sign(bytes.fromhex(v.BIP340_VECTORS[1]["seckey"]),
                             b"\x00" * 32, b"\x00" * 31)


class TestBIP341TweakVectors(unittest.TestCase):
    """The official bip-0341/wallet-test-vectors.json (scriptPubKey section)."""

    def test_tweak_pubkey_matches_the_vectors(self):
        for i, vec in enumerate(v.BIP341_TWEAK_VECTORS):
            with self.subTest(i=i):
                internal = bytes.fromhex(vec["internal_pubkey"])
                h = bytes.fromhex(vec["merkle_root"])
                parity, tweaked = ref.taproot_tweak_pubkey(internal, h)
                self.assertEqual(tweaked.hex(), vec["tweaked_pubkey"])
                self.assertIn(parity, (0, 1))
                # and the tweak scalar itself, which is what the applet's
                # schnorr_hash_tag() computes on-card
                self.assertEqual(
                    ref.tagged_hash("TapTweak", internal + h).hex(),
                    vec["tweak"])

    def test_first_vector_has_no_script_tree(self):
        # the key-path-only case: h is empty, so only 32 bytes are hashed
        self.assertEqual(v.BIP341_TWEAK_VECTORS[0]["merkle_root"], "")
        for vec in v.BIP341_TWEAK_VECTORS[1:]:
            self.assertEqual(len(bytes.fromhex(vec["merkle_root"])), 32)

    def test_script_pubkey_is_the_tweaked_key(self):
        for i, vec in enumerate(v.BIP341_TWEAK_VECTORS):
            with self.subTest(i=i):
                self.assertEqual(vec["script_pubkey"],
                                 "5120" + vec["tweaked_pubkey"])

    def test_seckey_and_pubkey_tweaks_agree(self):
        # what the card actually does is taproot_tweak_seckey() and it returns
        # the resulting pubkey; that must have the x coordinate that
        # taproot_tweak_pubkey() predicts, for both parities of the internal key
        seckey = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        for h in (b"",
                  bytes.fromhex(v.BIP341_TWEAK_VECTORS[1]["merkle_root"]),
                  b"\x00" * 32,
                  b"\xff" * 32):
            with self.subTest(h=h.hex()):
                internal = ref.pubkey_gen(seckey)
                _, expected = ref.taproot_tweak_pubkey(internal, h)
                tweaked_sk = ref.taproot_tweak_seckey(seckey, h)
                self.assertEqual(ref.pubkey_gen(tweaked_sk), expected)

    def test_tweak_is_rejected_for_a_wrong_sized_h(self):
        seckey = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        for bad in (b"\x00", b"\x00" * 31, b"\x00" * 33, b"\x00" * 64):
            with self.assertRaises(ref.InvalidBIP340Error):
                ref.taproot_tweak_seckey(seckey, bad)
            with self.assertRaises(ref.InvalidBIP340Error):
                ref.taproot_tweak_pubkey(ref.pubkey_gen(seckey), bad)

    def test_tweak_binds_to_the_internal_key(self):
        # the property the pre-0.16 XOR construction did NOT have: for a fixed
        # h, two different internal keys must give two different tweaks
        h = bytes.fromhex(v.BIP341_TWEAK_VECTORS[1]["merkle_root"])
        tweaks = {ref.tagged_hash("TapTweak", ref.pubkey_gen(
            (i + 1).to_bytes(32, "big")) + h) for i in range(8)}
        self.assertEqual(len(tweaks), 8)


class TestEmptyVersusZeroTweak(unittest.TestCase):
    """h = b'' and h = 32 zero bytes are different tweaks. This is a trap.

    The applet expects tweak_size=0 for a key-path-only (BIP86) output. A client
    that sends 32 zero bytes instead gets a valid-looking but different key,
    whose address no wallet will ever watch and whose coins are not spendable
    by any standard BIP341 signer.
    """

    def test_the_two_tweaks_differ(self):
        internal = bytes.fromhex(v.BIP86_KEYS[0]["internal_key"])
        _, from_empty = ref.taproot_tweak_pubkey(internal, b"")
        _, from_zeros = ref.taproot_tweak_pubkey(internal, b"\x00" * 32)
        self.assertNotEqual(from_empty, from_zeros)
        self.assertEqual(from_empty.hex(), v.BIP86_KEYS[0]["output_key"])

    def test_the_hashed_lengths_differ(self):
        internal = bytes.fromhex(v.BIP86_KEYS[0]["internal_key"])
        self.assertEqual(len(internal + b""), 32)
        self.assertEqual(len(internal + b"\x00" * 32), 64)


class TestBIP86Vectors(unittest.TestCase):
    """BIP86 key-path-only derivation: internal_key -> output_key, h empty."""

    def test_output_keys_match(self):
        for vec in v.BIP86_KEYS:
            with self.subTest(path=vec["path"]):
                internal = bytes.fromhex(vec["internal_key"])
                parity, output = ref.taproot_tweak_pubkey(internal, b"")
                self.assertEqual(output.hex(), vec["output_key"])
                self.assertEqual(vec["script_pubkey"],
                                 "5120" + vec["output_key"])

    def test_seed_matches_the_mnemonic(self):
        # guards against a typo in the seed the card test imports
        import hashlib
        seed = hashlib.pbkdf2_hmac(
            "sha512", v.BIP86_MNEMONIC.encode("utf-8"), b"mnemonic", 2048)
        self.assertEqual(seed.hex(), v.BIP86_SEED)
        self.assertEqual(len(seed), 64)


class TestLegacyXorTweak(unittest.TestCase):
    """Pins the compatibility claim made by the applet v0.16-0.0 changelog.

    TaprootTweakPrivateKey() up to v0.15-0.1 hashed x(P) XOR h instead of
    x(P) || h. The fix is only safe to ship because the two agree when h is
    all-zero -- i.e. for every key-path-only (BIP86) key ever derived by those
    versions, which is what tweak_size=0 now computes.
    """

    def test_legacy_matches_bip341_when_h_is_zero(self):
        seckey = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        self.assertEqual(ref.legacy_xor_tweak_seckey(seckey, b"\x00" * 32),
                         ref.taproot_tweak_seckey(seckey, b""))

    def test_legacy_differs_from_bip341_when_h_is_not_zero(self):
        seckey = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        for vec in v.BIP341_TWEAK_VECTORS[1:]:
            h = bytes.fromhex(vec["merkle_root"])
            with self.subTest(h=vec["merkle_root"]):
                self.assertNotEqual(ref.legacy_xor_tweak_seckey(seckey, h),
                                    ref.taproot_tweak_seckey(seckey, h))

    def test_legacy_tweak_does_not_bind_to_the_internal_key(self):
        # for any (P, h) an attacker could find h' with the same tweak:
        # h' = x(P) XOR x(P') XOR h. This is the reason the XOR form is unsafe,
        # not merely non-standard.
        sk_a = bytes.fromhex(v.CARD_TEST_PRIVKEY)
        sk_b = (0x2222).to_bytes(32, "big")
        h = bytes.fromhex(v.BIP341_TWEAK_VECTORS[1]["merkle_root"])
        x_a = ref.pubkey_gen(sk_a)
        x_b = ref.pubkey_gen(sk_b)
        h_prime = bytes(a ^ b ^ c for a, b, c in zip(x_a, x_b, h))
        self.assertEqual(
            ref.tagged_hash("TapTweak",
                            bytes(a ^ b for a, b in zip(x_a, h))),
            ref.tagged_hash("TapTweak",
                            bytes(a ^ b for a, b in zip(x_b, h_prime))))


if __name__ == "__main__":
    unittest.main(verbosity=2)
