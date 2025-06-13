#!/usr/bin/env python3
#
# Copyright (c) 2025 Toporin - https://github.com/Toporin
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

# Run with: python3 -B -m unittest -v test_satochip_musig2.py
#
# NOTE: For testing the BIP327 vectors, a modified Satochip firmware (branch musig2-debug-test) should be used.
# This firmware uses some hardcoded values and disabled secnonce encryption.
# This firmware should only be used for testing and debugging!
#
# For running these tests, you need a Satochip inserted in a card reader, ideally non-initialized.
# If the card is initialized, the PIN should be set to 123456 otherwise it will fail

import time
import hmac
import logging
import unittest
from os import urandom
from hashlib import sha1, sha256

from pysatochip.CardConnector import CardConnector, UninitializedSeedError, SeedKeeperError
from pysatochip.JCconstants import JCconstants
from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, \
    SATOCHIP_PROTOCOL_VERSION
from pysatochip.util import msg_magic

# import unittest
# from unittest.mock import MagicMock

# #satochip
# from .CardConnector import CardConnector
# from .CardConnector import UninitializedSeedError
# from .CardDataParser import CardDataParser
# from .satochip import bip32path2bytes, SatochipClient

logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
logger.warning("loglevel: " + str(logger.getEffectiveLevel()))


class SatochipTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        # constants
        cls.INS_VERIFY_PIN = 0x42
        # initialize list of secrets
        cls.pin = list(bytes("123456", "utf-8"))

        logger.info("Initialize new CardConnector...")
        cls.cc = CardConnector(None, logger.getEffectiveLevel())
        time.sleep(1)  # give some time to initialize reader...
        logger.info("ATR: " + str(cls.cc.card_get_ATR()))

        # check setup
        while (cls.cc.card_present):
            (response, sw1, sw2, d) = cls.cc.card_get_status()
            v_supported = SATOCHIP_PROTOCOL_VERSION
            v_applet = d["protocol_version"]
            logger.info(f"Satochip version={v_applet}")
            logger.info(f"Pysatochip supported version= {v_supported}")
            # Warning: version should be at least v0.15 for MuSig2 support!

            # check version
            if (cls.cc.setup_done):

                if (cls.cc.needs_secure_channel):
                    cls.cc.card_initiate_secure_channel()
                break

                # setup device (done only once)
            else:
                # setup pin
                pin_0 = cls.pin  # bytes("123456", "utf-8")
                pin_tries_0 = 0x05;
                ublk_tries_0 = 0x01;
                # PUK code can be used when PIN is unknown and the card is locked
                # We use a random value as the PUK is not used currently and is not user friendly
                ublk_0 = list(urandom(16));
                pin_tries_1 = 0x01
                ublk_tries_1 = 0x01
                pin_1 = list(urandom(16));  # the second pin is not used currently
                ublk_1 = list(urandom(16));
                secmemsize = 32  # RFU
                memsize = 0x0000  # RFU
                create_object_ACL = 0x01  # RFU
                create_key_ACL = 0x01  # RFU
                create_pin_ACL = 0x01  # RFU

                # setup
                (response, sw1, sw2) = cls.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                                                         pin_tries_1, ublk_tries_1, pin_1, ublk_1,
                                                         secmemsize, memsize,
                                                         create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1 != 0x90 or sw2 != 0x00:
                    logger.warning(f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")
                    return
                    # raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))

                break

        # verify pin:
        try:
            # cls.cc.card_verify_PIN()
            cls.cc.card_verify_PIN_deprecated(0, cls.pin)
        except RuntimeError as ex:
            logger.error(repr(ex))
            return

        # get authentikey
        try:
            cls.authentikey = cls.cc.card_export_authentikey()
        except UninitializedSeedError as ex:
            cls.authentikey = None
            logger.error(repr(ex))
            return

        # import private keys for testing BIP327 gen_nonce()
        try:
            privkey_gen_nonce = bytes.fromhex("0202020202020202020202020202020202020202020202020202020202020202")
            slot_gen_nonce = 0
            cls.cc.satochip_import_privkey(slot_gen_nonce, privkey_gen_nonce)
            print(f"Private key imported successfully!")
        except Exception as ex:
            logger.error(repr(ex))

        # import private keys for testing BIP327 sign()
        try:
            privkey_sign = bytes.fromhex("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671")
            slot_sign = 1
            cls.cc.satochip_import_privkey(slot_sign, privkey_sign)
            print(f"Private key imported successfully!")
        except Exception as ex:
            logger.error(repr(ex))


    # setup
    def setUp(self):
        (response, sw1, sw2) = SatochipTest.cc.card_verify_PIN_deprecated(0, SatochipTest.pin)
        self.assertEqual(hex(256 * sw1 + sw2), hex(0x9000))

        # check card type!
        self.assertEqual(SatochipTest.cc.card_type, "Satochip")


    # TEST BIP327 GenNonce
    def test_bip327_gen_nonce_vector1(self):
        # BIP327 test vector, see https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/nonce_gen_vectors.json
        # WARNING: for testing this feature, DEBUG values must be hardcoded in the Satochip firmware for rand!
        # rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
        # WARNING: for testing, secnonce encryption should be disabled in firmware!

        sk= bytes.fromhex("0202020202020202020202020202020202020202020202020202020202020202")
        pk= bytes.fromhex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
        aggpk = bytes.fromhex("0707070707070707070707070707070707070707070707070707070707070707")
        msg = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        extra = bytes.fromhex("0808080808080808080808080808080808080808080808080808080808080808")

        pubnonce, encrypted_secnonce = SatochipTest.cc.card_musig2_generate_nonce(keynbr=0, aggpk=aggpk, msg=msg, extra=extra)
        pubnonce = bytes(pubnonce)
        print(f"pubnonce: {pubnonce.hex()}")
        encrypted_secnonce = bytes(encrypted_secnonce[0:97]) # remove padding, IV & MAC
        print(f"encrypted_secnonce: {encrypted_secnonce.hex()}")

        expected_secnonce = bytes.fromhex("B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
        expected_pubnonce = bytes.fromhex("02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A")

        self.assertEqual(pubnonce, expected_pubnonce)
        self.assertEqual(encrypted_secnonce, expected_secnonce)

    def test_bip327_gen_nonce_vector2(self):
        # BIP327 test vector, see https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/nonce_gen_vectors.json
        # WARNING: for testing this feature, DEBUG values must be hardcoded in the Satochip firmware for rand!
        # rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
        # WARNING: for testing, secnonce encryption should be disabled in firmware!

        sk = bytes.fromhex("0202020202020202020202020202020202020202020202020202020202020202")
        pk = bytes.fromhex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
        aggpk = bytes.fromhex("0707070707070707070707070707070707070707070707070707070707070707")
        msg = bytes.fromhex("")
        extra = bytes.fromhex("0808080808080808080808080808080808080808080808080808080808080808")

        pubnonce, encrypted_secnonce = SatochipTest.cc.card_musig2_generate_nonce(keynbr=0, aggpk=aggpk, msg=msg, extra=extra)
        print(f"pubnonce: {pubnonce.hex()}")
        encrypted_secnonce = encrypted_secnonce[0:97] # remove padding, IV & MAC
        print(f"encrypted_secnonce: {encrypted_secnonce.hex()}")

        expected_secnonce = bytes.fromhex("E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
        expected_pubnonce = bytes.fromhex("023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C503F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109")

        self.assertEqual(pubnonce, expected_pubnonce)
        self.assertEqual(encrypted_secnonce, expected_secnonce)

    # TEST BIP327 Sign
    def test_bip327_sign_vector1(self):
        # For satochip, secnonce should be encrypted. However test vectors are in plaintexts
        # WARNING: for testing, secnonce decryption should be disabled in firmware!

        # intermediate variables computed from reference.py
        # DEBUG in sign() secnonce: 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9
        # DEBUG in sign() sk: 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671
        # DEBUG in sign() SessionContext: <class '__main__.SessionContext'>
        # DEBUG in sign() Q: (107179521481969063589684955794666486814340065679032862067712787212485410932785, 108444218236247070249999960376680851616622600416447756742194847077659881744058)
        # DEBUG in sign() gacc: 1
        # DEBUG in sign() b: 111355737419625300899079166965809667958207304842585719809404504787755164228038
        # DEBUG in sign() bytes(b): f6311d2583176bb178ec12973b760a2d733544d4c72b4b3a8c260f7679f7d9c6
        # DEBUG in sign() R: (74897412985712984213095933969182414455308160036758034207997312560734431279548, 112058698359432179229097306700791850711812237856000340266398814413982217518567)
        # DEBUG in sign() has_even_y(R): False
        # DEBUG in sign() e: 49005197392351446456135975994140108602289938401517890429045164672742598367090
        # DEBUG in sign() k_1: 79360574806131354547833179675957267462780362625019103790255743120707146760928
        # DEBUG in sign() k_2: 2643221927343497044458805274668730689734893256984295384717264118049928986442
        # DEBUG in sign() bytes(k_1): af747e59ee0eff594d494d69a9a6f7660b66511781294a6c9cec8ed48c1442e0
        # DEBUG in sign() bytes(k_2): 05d802b64e2aff7a4b7ed7a1e35dfa295e2c10cb7d4943667589c6639add3f4a
        # DEBUG in sign() P: (66658882606648252401616320978147272968829919412912148913784336526768956662185, 6960230844399131691910613049996756785334915340173527185181592482524406464039)
        # DEBUG in sign() pk: b'\x03\x93_\x97-\xa0\x13\xf8\n\xe0\x11\x89\x0f\xa8\x9bg\xa2{{\xe6\xcc\xb2M2t\xd1\x8b-@g\xf2a\xa9'
        # DEBUG in sign() a: 56733896202123218411833936789565720375090351854548528202946800303968875094148
        # DEBUG in sign() bytes(a): 7d6e3f4f742a6339631446aa2243f656fd1fe3fbe2693c745ec12dfe9aeaa084
        # DEBUG in sign() ea: 111535280052834925318978806485482281305177012966243379463497738138009482245632
        # DEBUG in sign() bytes(ea): f696bb3be7fc4ee399c173813d0bddded1471cfe8acf5f729b1610d489eb3600
        # DEBUG in sign() g: 1
        # DEBUG in sign() ggacc: 1
        # DEBUG in sign() bytes(ggacc): 0000000000000000000000000000000000000000000000000000000000000001
        # DEBUG in sign() d: 57772150683316834618350770180371212572443778219113352500067129149042366379633
        # DEBUG in sign() bytes(ea * d): 00000000000000000000000000000000000000000000000000000000000000007b07d271f8522fdb00a049f203df3defd7fac32996f8c8da572efb455fb7c7cc91c95f8bbc1ef2737e659f4ff26c789660aa42fcfd2f14b7f3cb78794bb6d600
        # DEBUG in sign() bytes(ea * d % n): eff519de563f0344081d121712e8cf8455c9989282ac006ca081f54a09e40bb3
        # DEBUG in sign() bytes(e * a * d % n): eff519de563f0344081d121712e8cf8455c9989282ac006ca081f54a09e40bb3
        # DEBUG in sign() bytes(e * a * d + k_1): 00000000000000000000000000000000000000000000000000000000000000007b07d271f8522fdb00a049f203df3defd7fac32996f8c8da572efb455fb7c7cd413ddde5aa2df1cccbaeecb99c136ffc6c1094147e585f2490b8074dd7cb18e0
        # DEBUG in sign() bytes(b * k_2): 0000000000000000000000000000000000000000000000000000000000000000059eb19e0787652f74bbdbdc4406e33a49429e66a92b24675cb98378551b8e7e27b0bbc00a97b8815cf7f328db8de904c1e10bc4b0e9c9c865b35fcd5c2aad3c
        # DEBUG in sign() bytes(e * a * d + k_1 + b * k_2): 000000000000000000000000000000000000000000000000000000000000000080a6840fffd9950a755c25ce47e6212a213d61904023ed41b3e87ebdb4d3564b68ee99a5b4c5aa4e28a6dfe277a159012df19fd92f4228ecf66b671b33f5c61c
        # DEBUG in sign() bytes((k_1 + b * k_2 + e * a * d) % n): 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012abbcb52b3016ac03ad82395a1a415c48b93def78718e62a7a90052fe224fb
        # DEBUG in sign() psig: 012abbcb52b3016ac03ad82395a1a415c48b93def78718e62a7a90052fe224fb
        # DEBUG in sign() pubnonce: 0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480

        # test vector
        secnonce = bytes.fromhex(
            "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")

        secnonce = secnonce + (144 - len(secnonce)) * bytes.fromhex("00")  # pad to reach 144 bytes

        b = bytes.fromhex("f6311d2583176bb178ec12973b760a2d733544d4c72b4b3a8c260f7679f7d9c6")
        ea = bytes.fromhex("f696bb3be7fc4ee399c173813d0bddded1471cfe8acf5f729b1610d489eb3600")
        r_has_even_y = False
        ggacc_is_1 = True

        psig = SatochipTest.cc.card_musig2_sign_hash(keynbr=1, secnonce=secnonce, b=b, ea=ea,
                                                     r_has_even_y=r_has_even_y, ggacc_is_1=ggacc_is_1)
        print(f"psig: {psig.hex()}")

        expected_psig = bytes.fromhex("012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
        self.assertEqual(psig, expected_psig)

    def test_bip327_sign_vector2(self):
        # For satochip, secnonce should be encrypted. However test vectors are in plaintexts
        # WARNING: for testing, secnonce decryption should be disabled in firmware!

        # intermediate variables computed from reference.py
        # DEBUG in sign() secnonce: 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9
        # DEBUG in sign() sk: 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671
        # DEBUG in sign() SessionContext: <class '__main__.SessionContext'>
        # DEBUG in sign() Q: (67173172168548704009562617517648765955944151091604701696036191457255900894906, 26282669893891764021062077221497032980667748248376218047551147963597497304393)
        # DEBUG in sign() gacc: 1
        # DEBUG in sign() b: 35415223286730625802114241349820720955670428123950336299877966332003959540472
        # DEBUG in sign() bytes(b): 4e4c4e586e5c5428b685c34e5ea737ca3fa0af046ba1a8c275970ef2ed8d8af8
        # DEBUG in sign() R: (30263125924750142450273740459823944342882123383423648461832868617001023349029, 27550955305162928106887374283431971757744538144025006267133919108748167561398)
        # DEBUG in sign() has_even_y(R): True
        # DEBUG in sign() e: 31174298964870793907870024924275009570621714624539409177252032006625372810729
        # DEBUG in sign() k_1: 36431514431184840875737805332730640390057201654055800592349420020811014733409
        # DEBUG in sign() k_2: 113148867309972698379112179734019177163102671022090608997887899023468232507895
        # DEBUG in sign() bytes(k_1): 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61
        # DEBUG in sign() bytes(k_2): fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f7
        # DEBUG in sign() P: (66658882606648252401616320978147272968829919412912148913784336526768956662185, 6960230844399131691910613049996756785334915340173527185181592482524406464039)
        # DEBUG in sign() pk: b'\x03\x93_\x97-\xa0\x13\xf8\n\xe0\x11\x89\x0f\xa8\x9bg\xa2{{\xe6\xcc\xb2M2t\xd1\x8b-@g\xf2a\xa9'
        # DEBUG in sign() a: 1
        # DEBUG in sign() bytes(a): 0000000000000000000000000000000000000000000000000000000000000001
        # DEBUG in sign() ea: 31174298964870793907870024924275009570621714624539409177252032006625372810729
        # DEBUG in sign() bytes(ea): 44ec0726a3800c95bec591e0b37ae8cd7ac8f5427503a462fa90481593de2de9
        # DEBUG in sign() g: 115792089237316195423570985008687907852837564279074904382605163141518161494336
        # DEBUG in sign() ggacc: 115792089237316195423570985008687907852837564279074904382605163141518161494336
        # DEBUG in sign() bytes(ggacc): fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
        # DEBUG in sign() d: 58019938553999360805220214828316695280393786059961551882538033992475795114704
        # DEBUG in sign() bytes(ea * d): 00000000000000000000000000000000000000000000000000000000000000002288e47cb69fec28800b27e13bd0b091ca7b872b2612259b68ed248c35adc697ef288168cd611eb655d47d5a0a9e4873682694806041e9905881eb310cfc2750
        # DEBUG in sign() bytes(ea * d % n): 75540dc2977006f9b96bd534f148eba65ff7947e4ee1b5771733543ff7025434
        # DEBUG in sign() bytes(e * a * d % n): 75540dc2977006f9b96bd534f148eba65ff7947e4ee1b5771733543ff7025434
        # DEBUG in sign() bytes(ea * d + k_1): 00000000000000000000000000000000000000000000000000000000000000002288e47cb69fec28800b27e13bd0b091ca7b872b2612259b68ed248c35adc6983fb4030edf521f5d088b2ff060f7510c176f204f8e613f5f7b67bae9511e25b1
        # DEBUG in sign() bytes(b * k_2): 00000000000000000000000000000000000000000000000000000000000000004c82bf9a3ed29e5a84ae2fef66bff362c028cd42d1eb6923d9623dc8a648dc5a633a73f68624440889528633776821d0bb6cbbd5c562d9f8655fc50369540d48
        # DEBUG in sign() bytes(e * a * d + k_1 + b * k_2): 00000000000000000000000000000000000000000000000000000000000000006f0ba416f5728a8304b957d0a290a3f48aa4546df7fd8ebf424f6254dbf6a2f2a2ee77056576636591ddb623d85f72dcd2dbdc2553c41957e0c77fecba7232f9
        # DEBUG in sign() bytes((k_1 + b * k_2 + e * a * d) % n): 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009ff2f7aaa856150cc8819254218d3adeeb0535269051897724f9db3789513a52
        # DEBUG in sign() psig: 9ff2f7aaa856150cc8819254218d3adeeb0535269051897724f9db3789513a52
        # DEBUG in sign() pubnonce: 0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480

        # test vector
        secnonce = bytes.fromhex(
            "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")

        secnonce = secnonce + (144 - len(secnonce)) * bytes.fromhex("00")  # pad to reach 144 bytes

        b = bytes.fromhex("4e4c4e586e5c5428b685c34e5ea737ca3fa0af046ba1a8c275970ef2ed8d8af8")
        ea = bytes.fromhex("44ec0726a3800c95bec591e0b37ae8cd7ac8f5427503a462fa90481593de2de9")
        r_has_even_y = True
        ggacc_is_1 = False

        psig = SatochipTest.cc.card_musig2_sign_hash(keynbr=1, secnonce=secnonce, b=b, ea=ea, r_has_even_y=r_has_even_y, ggacc_is_1=ggacc_is_1)
        print(f"psig: {psig.hex()}")

        expected_psig = bytes.fromhex("9ff2f7aaa856150cc8819254218d3adeeb0535269051897724f9db3789513a52")
        self.assertEqual(psig, expected_psig)

    def test_bip327_sign_vector3(self):
        # For satochip, secnonce should be encrypted. However test vectors are in plaintexts
        # WARNING: for testing, secnonce decryption should be disabled in firmware!

        # intermediate variables
        # DEBUG in sign() secnonce: 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9
        # DEBUG in sign() sk: 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671
        # DEBUG in sign() SessionContext: <class '__main__.SessionContext'>
        # DEBUG in sign() Q: (94580389211844189502771655412200223511714051013264126611490102837917891047065, 33952688939238102935891455587990152586541677844669023821842301078314607611060)
        # DEBUG in sign() gacc: 1
        # DEBUG in sign() b: 25443556285188795457292622038430908303095279621660912043043235954962629410275
        # DEBUG in sign() bytes(b): 38408ae2af100f0ba7392911a4fb4b02df935101101776ad42de055a45303de3
        # DEBUG in sign() R: (32900700936603376433696791589785386736003697831438216313854713056375653312999, 67622265459378859000684661944081586293079146479007349214292471378311428658344)
        # DEBUG in sign() has_even_y(R): True
        # DEBUG in sign() e: 63212687766096399529243454038857648533650652214538747734296093901114163688854
        # DEBUG in sign() k_1: 36431514431184840875737805332730640390057201654055800592349420020811014733409
        # DEBUG in sign() k_2: 113148867309972698379112179734019177163102671022090608997887899023468232507895
        # DEBUG in sign() bytes(k_1): 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61
        # DEBUG in sign() bytes(k_2): fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f7
        # DEBUG in sign() P: (66658882606648252401616320978147272968829919412912148913784336526768956662185, 6960230844399131691910613049996756785334915340173527185181592482524406464039)
        # DEBUG in sign() pk: b'\x03\x93_\x97-\xa0\x13\xf8\n\xe0\x11\x89\x0f\xa8\x9bg\xa2{{\xe6\xcc\xb2M2t\xd1\x8b-@g\xf2a\xa9'
        # DEBUG in sign() a: 18861968130562698181358615397400907012387444841458994003810684653101503615213
        # DEBUG in sign() bytes(a): 29b37ee20a1ed2e1eb6b11c16c877edd7c2005ec3255222f3c2368d5fdc610ed
        # DEBUG in sign() ea: 17463750423728965024359606916668017006605026371401380338035919356477520032984
        # DEBUG in sign() bytes(ea): 269c21e8db8f4da69461df29d73c666a1cbf9e0c2b97e6d2dfd84d195e7534d8
        # DEBUG in sign() g: 1
        # DEBUG in sign() ggacc: 1
        # DEBUG in sign() bytes(ggacc): 0000000000000000000000000000000000000000000000000000000000000001
        # DEBUG in sign() d: 57772150683316834618350770180371212572443778219113352500067129149042366379633
        # DEBUG in sign() bytes(ea * d): 000000000000000000000000000000000000000000000000000000000000000013437d92689b7f385130d5ca7149d8cb4468e5797ca009276809990b9ef01729bcb391f8ef6d78127705ef4cb570333f30195fc284685bf545dec6111017e358
        # DEBUG in sign() bytes(ea * d % n): 346fefe1a88dbe70971e01129c63bc5242a15474ceece0b2cf6b21255b216185
        # DEBUG in sign() bytes(e * a * d % n): 346fefe1a88dbe70971e01129c63bc5242a15474ceece0b2cf6b21255b216185
        # DEBUG in sign() bytes(ea * d + k_1): 000000000000000000000000000000000000000000000000000000000000000013437d92689b7f385130d5ca7149d8cb4468e5797ca009276809990b9ef0172a0d3f139f015e78b929bca1e30bc93bd7df61eb91b287b1c468c495c95439e1b9
        # DEBUG in sign() bytes(b * k_2): 000000000000000000000000000000000000000000000000000000000000000036f7d11e823b69a2215ec7fb535bbe33440bc3e56f94443f0f5ed360fc3119963f67e48404bfb228cdff5bb5089d87e46becf111e0cc5297ae42404e74b49905
        # DEBUG in sign() bytes(e * a * d + k_1 + b * k_2): 00000000000000000000000000000000000000000000000000000000000000004a3b4eb0ead6e8da728f9dc5c4a596fe8874a95eec344d6677686c6c9b2130c04ca6f823061e2ae1f7bbfd981466c3bc4b4edca39354045c1706d617c8ee7abe
        # DEBUG in sign() bytes((k_1 + b * k_2 + e * a * d) % n): 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fa23c359f6fac4e7796bb93bc9f0532a95468c539ba20ff86d7c76ed92227900
        # DEBUG in sign() psig: fa23c359f6fac4e7796bb93bc9f0532a95468c539ba20ff86d7c76ed92227900
        # DEBUG in sign() pubnonce: 0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480
        # test vector
        secnonce = bytes.fromhex(
            "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")

        secnonce = secnonce + (144 - len(secnonce)) * bytes.fromhex("00")  # pad to reach 144 bytes

        b = bytes.fromhex("38408ae2af100f0ba7392911a4fb4b02df935101101776ad42de055a45303de3")
        ea = bytes.fromhex("269c21e8db8f4da69461df29d73c666a1cbf9e0c2b97e6d2dfd84d195e7534d8")
        r_has_even_y = True
        ggacc_is_1 = True

        psig = SatochipTest.cc.card_musig2_sign_hash(keynbr=1, secnonce=secnonce, b=b, ea=ea, r_has_even_y=r_has_even_y, ggacc_is_1=ggacc_is_1)
        print(f"psig: {psig.hex()}")

        expected_psig = bytes.fromhex("fa23c359f6fac4e7796bb93bc9f0532a95468c539ba20ff86d7c76ed92227900")
        self.assertEqual(psig, expected_psig)


    def test_bip327_sign_vector4(self):
        # For satochip, secnonce should be encrypted. However test vectors are in plaintexts
        # WARNING: for testing, secnonce decryption should be disabled in firmware!

        # intermediate variables
        # DEBUG in sign() secnonce: 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9
        # DEBUG in sign() sk: 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671
        # DEBUG in sign() SessionContext: <class '__main__.SessionContext'>
        # DEBUG in sign() Q: (38057971797033528135845594387265833341396222324506796088280442063831026831139, 114784761811014931077218113337186665356005297593391287732994958275951450233625)
        # DEBUG in sign() gacc: 1
        # DEBUG in sign() b: 28657693249852023451256119998138516902005256308507978640026328721331373113616
        # DEBUG in sign() bytes(b): 3f5badf8ab2c557b406c286005f141fabc51dd01aad15ff86137add044be8110
        # DEBUG in sign() R: (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)
        # DEBUG in sign() has_even_y(R): True
        # DEBUG in sign() e: 64942742969115207309081356490422937894696358357776050977707638741516075771855
        # DEBUG in sign() k_1: 36431514431184840875737805332730640390057201654055800592349420020811014733409
        # DEBUG in sign() k_2: 113148867309972698379112179734019177163102671022090608997887899023468232507895
        # DEBUG in sign() bytes(k_1): 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61
        # DEBUG in sign() bytes(k_2): fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f7
        # DEBUG in sign() P: (66658882606648252401616320978147272968829919412912148913784336526768956662185, 6960230844399131691910613049996756785334915340173527185181592482524406464039)
        # DEBUG in sign() pk: b'\x03\x93_\x97-\xa0\x13\xf8\n\xe0\x11\x89\x0f\xa8\x9bg\xa2{{\xe6\xcc\xb2M2t\xd1\x8b-@g\xf2a\xa9'
        # DEBUG in sign() a: 105986368111003297219696448646937101202467828261253099227326667478331356201035
        # DEBUG in sign() bytes(a): ea522894dd115b3c88fa634aacb084e4343379044462555aaf841aaedff9c04b
        # DEBUG in sign() ea: 77981705685862419185472223786954552851692951045148083337097199738844519584511
        # DEBUG in sign() bytes(ea): ac6814cfb60239aacba900a57e641b591f8f514417efabd762a4944ccbf3d2ff
        # DEBUG in sign() g: 115792089237316195423570985008687907852837564279074904382605163141518161494336
        # DEBUG in sign() ggacc: 115792089237316195423570985008687907852837564279074904382605163141518161494336
        # DEBUG in sign() bytes(ggacc): fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
        # DEBUG in sign() d: 58019938553999360805220214828316695280393786059961551882538033992475795114704
        # DEBUG in sign() bytes(ea * d): 0000000000000000000000000000000000000000000000000000000000000000566343cf4d8453361393854c35bc792320ecfa31a34543a0feccbd505ffef613b7c5169f2689006c0a4fd5a983385947708566503b8716ed899ac461ca63a530
        # DEBUG in sign() bytes(ea * d % n): a765e455964108a3b9ac7cf52083027d2ed536c546d4a4bef69386b8212f0eee
        # DEBUG in sign() bytes(e * a * d % n): a765e455964108a3b9ac7cf52083027d2ed536c546d4a4bef69386b8212f0eee
        # DEBUG in sign() bytes(ea * d + k_1): 0000000000000000000000000000000000000000000000000000000000000000566343cf4d8453361393854c35bc792320ecfa31a34543a0feccbd505ffef61408509845387a0112bd06883fd99161e01fcdf21f69a66cbcac80941a0e85a391
        # DEBUG in sign() bytes(b * k_2): 00000000000000000000000000000000000000000000000000000000000000003de96d8c3021d700c85d816994e5005de3ff399a05a66c5e95619807c8c808c27817b626319bd64a32a1775d8314fab2e7bc067b6a41ecbd9bae06ba40df9670
        # DEBUG in sign() bytes(e * a * d + k_1 + b * k_2): 0000000000000000000000000000000000000000000000000000000000000000944cb15b7da62a36dbf106b5caa1798104ec33cba8ebafff942e555828c6fed680684e6b6a15d75cefa7ff9d5ca65c930789f89ad3e8597a482e9ad44f653a01
        # DEBUG in sign() bytes((k_1 + b * k_2 + e * a * d) % n): 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ae386064b26105404798f75de2eb9af5eda5387b064b83d049cb7c5e08879531
        # DEBUG in sign() psig: ae386064b26105404798f75de2eb9af5eda5387b064b83d049cb7c5e08879531
        # DEBUG in sign() pubnonce: 0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480


        secnonce = bytes.fromhex(
            "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")

        secnonce = secnonce + (144 - len(secnonce)) * bytes.fromhex("00")  # pad to reach 144 bytes

        b = bytes.fromhex("3f5badf8ab2c557b406c286005f141fabc51dd01aad15ff86137add044be8110")
        ea = bytes.fromhex("ac6814cfb60239aacba900a57e641b591f8f514417efabd762a4944ccbf3d2ff")
        r_has_even_y = True
        ggacc_is_1 = False

        psig = SatochipTest.cc.card_musig2_sign_hash(keynbr=1, secnonce=secnonce, b=b, ea=ea, r_has_even_y=r_has_even_y, ggacc_is_1=ggacc_is_1)
        print(f"psig: {psig.hex()}")

        expected_psig = bytes.fromhex("ae386064b26105404798f75de2eb9af5eda5387b064b83d049cb7c5e08879531")
        self.assertEqual(psig, expected_psig)

    def test_bip327_sign_vector5(self):
        # For satochip, secnonce should be encrypted. However test vectors are in plaintexts
        # WARNING: for testing, secnonce decryption should be disabled in firmware!

        # intermediate variables
        # DEBUG in sign() secnonce: 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9
        # DEBUG in sign() sk: 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671
        # DEBUG in sign() SessionContext: <class '__main__.SessionContext'>
        # DEBUG in sign() Q: (107179521481969063589684955794666486814340065679032862067712787212485410932785, 108444218236247070249999960376680851616622600416447756742194847077659881744058)
        # DEBUG in sign() gacc: 1
        # DEBUG in sign() b: 77851308704095185506420183774810073021544989291714946594500604845257713343671
        # DEBUG in sign() bytes(b): ac1e477ad7cb9a132f917bfc96ad3e21250b061dca23e8d13ded58f4eaa55cb7
        # DEBUG in sign() R: (110964656728463108156683471624494137157680369857870744237447134283435547768000, 50862397490275563023414026231392611706176511025865871456219522725277946490456)
        # DEBUG in sign() has_even_y(R): True
        # DEBUG in sign() e: 106438001368693724278940201216257113552492287462989314414475865790778004812643
        # DEBUG in sign() k_1: 36431514431184840875737805332730640390057201654055800592349420020811014733409
        # DEBUG in sign() k_2: 113148867309972698379112179734019177163102671022090608997887899023468232507895
        # DEBUG in sign() bytes(k_1): 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61
        # DEBUG in sign() bytes(k_2): fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f7
        # DEBUG in sign() P: (66658882606648252401616320978147272968829919412912148913784336526768956662185, 6960230844399131691910613049996756785334915340173527185181592482524406464039)
        # DEBUG in sign() pk: b'\x03\x93_\x97-\xa0\x13\xf8\n\xe0\x11\x89\x0f\xa8\x9bg\xa2{{\xe6\xcc\xb2M2t\xd1\x8b-@g\xf2a\xa9'
        # DEBUG in sign() a: 56733896202123218411833936789565720375090351854548528202946800303968875094148
        # DEBUG in sign() bytes(a): 7d6e3f4f742a6339631446aa2243f656fd1fe3fbe2693c745ec12dfe9aeaa084
        # DEBUG in sign() ea: 77331640959707941422835596168825726083305705755028150903618863404411398202796
        # DEBUG in sign() bytes(ea): aaf8285ee7ae183977a9f2d279294e236e6a5831ff0adf7a1325b03daaad25ac
        # DEBUG in sign() g: 1
        # DEBUG in sign() ggacc: 1
        # DEBUG in sign() bytes(ggacc): 0000000000000000000000000000000000000000000000000000000000000001
        # DEBUG in sign() d: 57772150683316834618350770180371212572443778219113352500067129149042366379633
        # DEBUG in sign() bytes(ea * d): 0000000000000000000000000000000000000000000000000000000000000000554d3f8f5a68edf357cd44129060bfd9cd1651fc30e16362031f30331bb26b297199e90d47cc4854ed7965de22aa83ef506d397f717e397206cfa43d91cae8ec
        # DEBUG in sign() bytes(ea * d % n): d795d466868a91ffd39feaf44263049f96ae437f5f1cd371e5e37e1c11851992
        # DEBUG in sign() bytes(e * a * d % n): d795d466868a91ffd39feaf44263049f96ae437f5f1cd371e5e37e1c11851992
        # DEBUG in sign() bytes(ea * d + k_1): 0000000000000000000000000000000000000000000000000000000000000000554d3f8f5a68edf357cd44129060bfd9cd1651fc30e16362031f30331bb26b29c2256ab359bd48fba030187479038c87ffb5c54e9f9d8f4129b573f5d5ece74d
        # DEBUG in sign() bytes(b * k_2): 0000000000000000000000000000000000000000000000000000000000000000a83074b6534aa2be4334cd22df71eb666b06cd6aa1ccc072856579793ec9b9650cdde76552b1c9217a602a93627001946a2d4bd521da7c2d0c141a3729882b91
        # DEBUG in sign() bytes(e * a * d + k_1 + b * k_2): 0000000000000000000000000000000000000000000000000000000000000000fd7db445adb390b19b0211356fd2ab40381d1f66d2ae23d48884a9ac5a7c248ecf035218ac6f121d1a904307db738e1c69e31123c1780b6e35c98e2cff7512de
        # DEBUG in sign() bytes((k_1 + b * k_2 + e * a * d) % n): 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d7d63ffd644ccda4e62bc2bc0b1d02dd32a1dc3030e155195810231d1037d82d
        # DEBUG in sign() psig: d7d63ffd644ccda4e62bc2bc0b1d02dd32a1dc3030e155195810231d1037d82d
        # DEBUG in sign() pubnonce: 0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480

        secnonce = bytes.fromhex(
            "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")

        secnonce = secnonce + (144 - len(secnonce)) * bytes.fromhex("00")  # pad to reach 144 bytes

        b = bytes.fromhex("ac1e477ad7cb9a132f917bfc96ad3e21250b061dca23e8d13ded58f4eaa55cb7")
        ea = bytes.fromhex("aaf8285ee7ae183977a9f2d279294e236e6a5831ff0adf7a1325b03daaad25ac")
        r_has_even_y = True
        ggacc_is_1 = True

        psig = SatochipTest.cc.card_musig2_sign_hash(keynbr=1, secnonce=secnonce, b=b, ea=ea, r_has_even_y=r_has_even_y, ggacc_is_1=ggacc_is_1)
        print(f"psig: {psig.hex()}")

        expected_psig = bytes.fromhex("d7d63ffd644ccda4e62bc2bc0b1d02dd32a1dc3030e155195810231d1037d82d")
        self.assertEqual(psig, expected_psig)

    def test_bip327_sign_vector6(self):
        # For satochip, secnonce should be encrypted. However test vectors are in plaintexts
        # WARNING: for testing, secnonce decryption should be disabled in firmware!

        # intermediate variables
        # DEBUG in sign() secnonce: 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9
        # DEBUG in sign() sk: 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671
        # DEBUG in sign() SessionContext: <class '__main__.SessionContext'>
        # DEBUG in sign() Q: (107179521481969063589684955794666486814340065679032862067712787212485410932785, 108444218236247070249999960376680851616622600416447756742194847077659881744058)
        # DEBUG in sign() gacc: 1
        # DEBUG in sign() b: 115243723262080438592937971099287861611840826998853531836161227117049657720847
        # DEBUG in sign() bytes(b): fec9a2c784ade2134f1d4f711d2f7daca8e7ee0ba36e3825077a70379eac800f
        # DEBUG in sign() R: (62595135587327895583222527892376200781785029571852328589476283850408837772880, 39839544303607077008938741277634789150966003029908757774608410741337680090102)
        # DEBUG in sign() has_even_y(R): True
        # DEBUG in sign() e: 12451472014299825401564525291250119202116227667780711408565512725634140795739
        # DEBUG in sign() k_1: 36431514431184840875737805332730640390057201654055800592349420020811014733409
        # DEBUG in sign() k_2: 113148867309972698379112179734019177163102671022090608997887899023468232507895
        # DEBUG in sign() bytes(k_1): 508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61
        # DEBUG in sign() bytes(k_2): fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f7
        # DEBUG in sign() P: (66658882606648252401616320978147272968829919412912148913784336526768956662185, 6960230844399131691910613049996756785334915340173527185181592482524406464039)
        # DEBUG in sign() pk: b'\x03\x93_\x97-\xa0\x13\xf8\n\xe0\x11\x89\x0f\xa8\x9bg\xa2{{\xe6\xcc\xb2M2t\xd1\x8b-@g\xf2a\xa9'
        # DEBUG in sign() a: 56733896202123218411833936789565720375090351854548528202946800303968875094148
        # DEBUG in sign() bytes(a): 7d6e3f4f742a6339631446aa2243f656fd1fe3fbe2693c745ec12dfe9aeaa084
        # DEBUG in sign() ea: 87083350396924705603925081158061322040292302009835051701432640316584414798307
        # DEBUG in sign() bytes(ea): c0876dfd25bcac2e812d22765066a7dac30b62e45e055d356c00b9cf9db5e1e3
        # DEBUG in sign() g: 1
        # DEBUG in sign() ggacc: 1
        # DEBUG in sign() bytes(ggacc): 0000000000000000000000000000000000000000000000000000000000000001
        # DEBUG in sign() d: 57772150683316834618350770180371212572443778219113352500067129149042366379633
        # DEBUG in sign() bytes(ea * d): 0000000000000000000000000000000000000000000000000000000000000000600efa92f19d31870aedfff7f6aafe99c60153bfbf0c56f5a6d959de2dcca87b394d9849c5574b62b8ef1ccc61897fcf550152b379ea65407e006256c6675733
        # DEBUG in sign() bytes(ea * d % n): 989e9b3a6608aff559c59b67a34bd3e6ebba7c048cff508aded3e62212e27211
        # DEBUG in sign() bytes(e * a * d % n): 989e9b3a6608aff559c59b67a34bd3e6ebba7c048cff508aded3e62212e27211
        # DEBUG in sign() bytes(ea * d + k_1): 0000000000000000000000000000000000000000000000000000000000000000600efa92f19d31870aedfff7f6aafe99c60153bfbf0c56f5a6d959de2dcca87b89d919efd7484c096ba5cf62b7e288680449de82a809bb0fa0e6320f0a895594
        # DEBUG in sign() bytes(b * k_2): 0000000000000000000000000000000000000000000000000000000000000000f8f8b5c54253061e6f5bbb9df5812f2fedd58c9a614790ab63a68329717437683bc7300447e310f1ba57b821dba100a36afbb8464738b0b068a3c82b65269d79
        # DEBUG in sign() bytes(e * a * d + k_1 + b * k_2): 00000000000000000000000000000000000000000000000000000000000000015907b05833f037a57a49bb95ec2c2dc9b3d6e05a2053e7a10a7fdd079f40dfe3c5a049f41f2b5cfb25fd87849383890b6f4596c8ef426bc00989fa3a6faff30d
        # DEBUG in sign() bytes((k_1 + b * k_2 + e * a * d) % n): 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e184351828da5094a97c79cabdaaa0bfb87608c32e8829a4df5340a6f243b78c
        # DEBUG in sign() psig: e184351828da5094a97c79cabdaaa0bfb87608c32e8829a4df5340a6f243b78c
        # DEBUG in sign() pubnonce: 0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480

        secnonce = bytes.fromhex(
            "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")

        secnonce = secnonce + (144 - len(secnonce)) * bytes.fromhex("00")  # pad to reach 144 bytes

        b = bytes.fromhex("fec9a2c784ade2134f1d4f711d2f7daca8e7ee0ba36e3825077a70379eac800f")
        ea = bytes.fromhex("c0876dfd25bcac2e812d22765066a7dac30b62e45e055d356c00b9cf9db5e1e3")
        r_has_even_y = True
        ggacc_is_1 = True

        psig = SatochipTest.cc.card_musig2_sign_hash(keynbr=1, secnonce=secnonce, b=b, ea=ea, r_has_even_y=r_has_even_y, ggacc_is_1=ggacc_is_1)
        print(f"psig: {psig.hex()}")

        expected_psig = bytes.fromhex("e184351828da5094a97c79cabdaaa0bfb87608c32e8829a4df5340a6f243b78c")
        self.assertEqual(psig, expected_psig)


if __name__ == '__main__':
    unittest.main()