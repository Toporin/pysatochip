#!/usr/bin/env python3
#
# Copyright (c) 2020-2021 Toporin - https://github.com/Toporin
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

# Run with: python3 -m unittest -v test_satochip.py
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
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION
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
logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )

class SatochipTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        
        # constants
        cls.INS_VERIFY_PIN= 0x42
        #initialize list of secrets
        cls.pin= list(bytes("123456", "utf-8"))
        cls.wrong_pin= list(bytes("0000", "utf-8"))

        logger.info("Initialize new CardConnector...")
        cls.cc = CardConnector(None, logger.getEffectiveLevel())
        time.sleep(1) # give some time to initialize reader...
        logger.info("ATR: "+str(cls.cc.card_get_ATR()))
        
        # check setup
        while(cls.cc.card_present):
            (response, sw1, sw2, d)=cls.cc.card_get_status()
            
            # check version
            if  (cls.cc.setup_done):
                v_supported= SATOCHIP_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"SeedKeeper version={v_applet} Electrum supported version= {v_supported}") #debugSatochip
                if (cls.cc.needs_secure_channel):
                    cls.cc.card_initiate_secure_channel()
                break 
                
            # setup device (done only once)
            else:
                # setup pin
                pin_0= cls.pin # bytes("123456", "utf-8")
                pin_tries_0= 0x05;
                ublk_tries_0= 0x01;
                # PUK code can be used when PIN is unknown and the card is locked
                # We use a random value as the PUK is not used currently and is not user friendly
                ublk_0= list(urandom(16)); 
                pin_tries_1= 0x01
                ublk_tries_1= 0x01
                pin_1= list(urandom(16)); #the second pin is not used currently
                ublk_1= list(urandom(16));
                secmemsize= 32 # RFU
                memsize= 0x0000 # RFU
                create_object_ACL= 0x01 # RFU
                create_key_ACL= 0x01 # RFU
                create_pin_ACL= 0x01 # RFU
                
                #setup
                (response, sw1, sw2)=cls.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1!=0x90 or sw2!=0x00:       
                    logger.warning(f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")
                    return
                    #raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
                    
                break
                
        # verify pin:
        try: 
            #cls.cc.card_verify_PIN()
            cls.cc.card_verify_PIN_deprecated(0, cls.pin)
        except RuntimeError as ex:
            logger.error(repr(ex))            
            return
        
        # get authentikey
        try:
            cls.authentikey=cls.cc.card_bip32_get_authentikey()
        except UninitializedSeedError as ex:
            cls.authentikey= None
            logger.error(repr(ex))            
            return
    
    # setup
    def setUp(self):
        (response, sw1, sw2)= SatochipTest.cc.card_verify_PIN_deprecated(0, SatochipTest.pin)
        self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
        
        # todo: check card type!
        self.assertEqual(SatochipTest.cc.card_type, "Satochip")
        
    # BIP32 
    
    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector1(self):  
        # Bip32 test vectors 1 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors)
        print("\n\n[test_CardConnector] test_card_bip32_get_extendedkey_seed_vector1:") #debugSatochip
        
        seed_hex= "000102030405060708090a0b0c0d0e0f"
        seed= list(bytes.fromhex(seed_hex)) 
        authentikey= SatochipTest.cc.card_bip32_import_seed(seed) 
        paths=[ "m",
                "m/0'",
                "m/0'/1",
                "m/0'/1/2'",
                "m/0'/1/2'/2",
                "m/0'/1/2'/2/1000000000"]
        xpubs=[ "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"]        
        #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                xpub= SatochipTest.cc.card_bip32_get_xpub(paths[i], 'standard', is_mainnet=True)
                self.assertEqual(xpub, xpubs[i])
    
        # reset seed
        (response, sw1, sw2)= SatochipTest.cc.card_reset_seed(SatochipTest.pin)
        self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
        
    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector2(self):
        print("\n\n[test_CardConnector] test_card_bip32_get_extendedkey_seed_vector2:") #debugSatochip
        
        seed= list(bytes.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
        authentikey= SatochipTest.cc.card_bip32_import_seed(seed) 
        paths=[ "m",
                "m/0",
                "m/0/2147483647'",
                "m/0/2147483647'/1",
                "m/0/2147483647'/1/2147483646'",
                "m/0/2147483647'/1/2147483646'/2"]
        xpubs=[ "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"]    
       #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                xpub= SatochipTest.cc.card_bip32_get_xpub(paths[i], 'standard', is_mainnet=True)
                self.assertEqual(xpub, xpubs[i])
    
        # reset seed
        (response, sw1, sw2)= SatochipTest.cc.card_reset_seed(SatochipTest.pin)
        self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )

    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector3(self):
        print("\n\n[test_CardConnector] test_card_bip32_get_extendedkey_seed_vector3:") #debugSatochip
        
        seed= list(bytes.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))
        authentikey= SatochipTest.cc.card_bip32_import_seed(seed) 
        paths=[ "m",
                "m/0'"]
        xpubs=[ "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"]
       #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                xpub= SatochipTest.cc.card_bip32_get_xpub(paths[i], 'standard', is_mainnet=True)
                self.assertEqual(xpub, xpubs[i])
    
        # reset seed
        (response, sw1, sw2)= SatochipTest.cc.card_reset_seed(SatochipTest.pin)
        self.assertEqual(sw1, 0x90)
        self.assertEqual(sw2, 0x00)
    
    # SIGN MSG
        
    #@unittest.skip("debug")
    def test_card_sign_message(self):
        print("\n\n test_card_sign_message:") #debugSatochip
        msgs=[  "",
                    " ",
                    "Hello World",
                    "The quick brown fox jumps over the lazy dog",
                    8*"The quick brown fox jumps over the lazy dog"]
        path= "m/0'"

        # import seed
        seed= list(bytes.fromhex("000102030405060708090a0b0c0d0e0f")) 
        authentikey= SatochipTest.cc.card_bip32_import_seed(seed) 
        # get extended key
        (childkey, childchaincode)=SatochipTest.cc.card_bip32_get_extendedkey(path)
        keynbr= 0xFF 
        #subtests
        for i in range(0, len(msgs)):
            with self.subTest(i=i):
                print("Signing message "+str(i)+" : "+msgs[i] + "...")
                msg=msgs[i]
                (response, sw1, sw2, compsig) = SatochipTest.cc.card_sign_message(keynbr, childkey, msg, hmac=b'', altcoin=None)
                self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
                
                # test LTC msg signing
                (response, sw1, sw2, compsig) = SatochipTest.cc.card_sign_message(keynbr, childkey, msg, hmac=b'', altcoin="Litecoin")
                self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
                
        # reset seed
        (response, sw1, sw2)= SatochipTest.cc.card_reset_seed(SatochipTest.pin)
        self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
    
    # 2FA
    
    #@unittest.skip("debug")
    def test_card_2FA(self):
        print("\n\n test_card_2FA:") #debugSatochip

        # set 2FA
        secret_2FA= bytes(20) #urandom(20)
        amount_limit= 0 # i.e. always use 
        (response, sw1, sw2)=SatochipTest.cc.card_set_2FA_key(secret_2FA, amount_limit)
        #self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
        # set seed
        seed= list(bytes.fromhex("000102030405060708090a0b0c0d0e0f")) 
        if SatochipTest.authentikey is None:
            authentikey= SatochipTest.cc.card_bip32_import_seed(seed) 
        else:
            authentikey= SatochipTest.authentikey
        print("AUTHENTIKEY: " + str(authentikey))
        
        # get extended key
        path= "m/0'/1"
        (childkey, childchaincode)=SatochipTest.cc.card_bip32_get_extendedkey(path)
        keynbr= 0xFF 
        # sign dummy tx
        
        # sign msg
        msgs=[  "",
                    " ",
                    "Hello World",
                    "The quick brown fox jumps over the lazy dog",
                    8*"The quick brown fox jumps over the lazy dog"]
        for i in range(0, len(msgs)):
            with self.subTest(i=i):
                print("Signing message "+str(i)+" : "+msgs[i] + "...")
                msg=msgs[i]
                #todo: compute hmac
                paddedmsghash = sha256( msg_magic(msg.encode('utf-8')) ).hexdigest()
                challenge= paddedmsghash + 32*"BB"
                mac = hmac.new(secret_2FA, bytes.fromhex(challenge), sha1).digest()
                
                (response, sw1, sw2, compsig) = SatochipTest.cc.card_sign_message(keynbr, childkey, msg, hmac=mac, altcoin=None)
                self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
                
                # with wrong hmac it should not work
                (response, sw1, sw2, compsig) = SatochipTest.cc.card_sign_message(keynbr, childkey, msg, hmac=bytes(20), altcoin=None)
                self.assertEqual(compsig, b'')
                self.assertEqual( hex(256*sw1+sw2), hex(0x9C0B) )
        
        # reset seed
        authentikey_bytes= authentikey.get_public_key_bytes(True)
        authentikey_coordx= authentikey_bytes[1:33].hex()
        challenge= authentikey_coordx+ 32*'FF'
        mac = hmac.new(secret_2FA, bytes.fromhex(challenge), sha1).digest()
        (response, sw1, sw2)= SatochipTest.cc.card_reset_seed(SatochipTest.pin, hmac=list(bytes(20))) #wrong mac
        self.assertEqual( hex(256*sw1+sw2), hex(0x9C0B) )
        (response, sw1, sw2)= SatochipTest.cc.card_reset_seed(SatochipTest.pin, hmac=list(mac))
        self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
        # verify PIN: after a seed reset, user is logged out
        (response, sw1, sw2)= SatochipTest.cc.card_verify_PIN_deprecated(0, SatochipTest.pin)
        self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
        
        # reset 2FA
        id_2FA_20b= hmac.new(secret_2FA, "id_2FA".encode('utf-8'), sha1).hexdigest()
        challenge= id_2FA_20b + 44*'AA'
        mac = hmac.new(secret_2FA, bytes.fromhex(challenge), sha1).digest()
        (response, sw1, sw2)= SatochipTest.cc.card_reset_2FA_key(list(bytes(20))) #wrong mac
        self.assertEqual( hex(256*sw1+sw2), hex(0x9C0B) )
        (response, sw1, sw2)= SatochipTest.cc.card_reset_2FA_key(list(mac))
        self.assertEqual( hex(256*sw1+sw2), hex(0x9000) )
    
    
    #TODO: 
    # test bip32path2bytes
    # test ETH msg signing
    
    
if __name__ == '__main__':
    unittest.main()