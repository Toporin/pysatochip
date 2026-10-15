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

# Run with: python3 -m unittest -v test_seedkeeper.py
#
# For running these tests, you need a SeedKeeper inserted in a card reader, ideally non-initialized.
# If the card is initialized, the PIN should be set to 123456 otherwise it will fail 

import time
import logging
import unittest
import string
import hashlib
import hmac
import random
from random import randrange
from os import urandom

from mnemonic import Mnemonic

from pysatochip.CardConnector import CardConnector, UninitializedSeedError, SeedKeeperError
from pysatochip.JCconstants import JCconstants
from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.version import SEEDKEEPER_PROTOCOL_VERSION

from satochip_cli import mnemonic_to_masterseed, mnemonic_to_entropy, entropy_to_mnemonic

logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )


class SeedKeeperTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        
        # constants
        cls.LOG_SIZE=4
        cls.INS_GENERATE_MASTERSEED= 0xA0
        cls.INS_GENERATE_2FA_SECRET= 0xAE
        cls.INS_IMPORT_SECRET= 0xA1
        cls.INS_EXPORT_SECRET= 0xA2
        cls.INS_VERIFY_PIN= 0x42
        #initialize list of secrets
        cls.sid=[]
        cls.pin= list(bytes("123456", "utf-8"))
        cls.wrong_pin= list(bytes("0000", "utf-8"))

        logger.info("Initialize new CardConnector...")
        cls.cc = CardConnector(None, logger.getEffectiveLevel())
        time.sleep(1) # give some time to initialize reader...
        logger.info("ATR: "+str(cls.cc.card_get_ATR()))
        
        # check setup
        while(cls.cc.card_present):
            (response, sw1, sw2, d)=cls.cc.card_get_status()
            
            # todo: check card type!
            
            # check version
            v_supported= SEEDKEEPER_PROTOCOL_VERSION 
            cls.v_applet= d["protocol_version"] 
            logger.info(f"SeedKeeper version={cls.v_applet} Electrum supported version= {v_supported}") #debugSatochip

            if  (cls.cc.setup_done):
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
            logger.error(repr(ex))            
            return
        
##############
    
    #@unittest.skip("debug")
    def test_generate_masterseed(self):
        """Generate a masterseed (legacy), then erase it"""
        sid=0
        seed_size= range(16, 65, 16) #64
        for size in seed_size:
            export_rights= 0x01
            label= "Test: Mymasterseed  "+ str(size) + "bytes export-allowed"
            (response, sw1, sw2, sid, fingerprint)= SeedKeeperTest.cc.seedkeeper_generate_masterseed(size, export_rights, label)
            self.assertEqual(sw1, 0x90)
            self.assertEqual(sw2, 0x00)
            
            # check logs
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_GENERATE_MASTERSEED)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9000)
            
            # check fingerprint and export secret
            #sdict= SeedKeeperTest.cc.seedkeeper_export_plain_secret(sid)
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], 0x10)
            self.assertEqual(sdict['origin'], 0x03)
            self.assertEqual(sdict['export_rights'], export_rights)
            self.assertEqual(sdict['fingerprint'], fingerprint) 
            self.assertEqual(sdict['rfu1'], 0x00) 
            self.assertEqual(sdict['rfu2'], 0x00) 
            self.assertEqual(sdict['label'], label) 
            SeedKeeperTest.sid+=[sid]
                
            # test logs
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_SECRET)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9000)
            
            if SeedKeeperTest.v_applet>=2:
                # test delete
                response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
                self.assertEqual(dic["is_reset"], True)
            else:
                print(f"SeedKeeper v0.1: delete secret not supported!")

    #@unittest.skip("debug")
    def test_generate_2FA_secret(self):
        export_rights= 0x01
        label= "Test: 2FA  20 bytes export-allowed"
        (response, sw1, sw2, sid, fingerprint)= SeedKeeperTest.cc.seedkeeper_generate_2FA_secret(export_rights, label)
        self.assertEqual(sw1, 0x90)
        self.assertEqual(sw2, 0x00)
        
        # check logs
        (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
        self.assertEqual(len(logs), 1)
        last_log= logs[0]
        (ins, id1, id2, res)= last_log
        self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
        self.assertEqual(ins, SeedKeeperTest.INS_GENERATE_2FA_SECRET)
        self.assertEqual(id1, sid)
        self.assertEqual(id2, 0xFFFF)
        self.assertEqual(res, 0x9000)
        
        # check fingerprint and export secret
        #sdict= SeedKeeperTest.cc.seedkeeper_export_plain_secret(sid)
        sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
        self.assertEqual(sdict['id'], sid)
        self.assertEqual(sdict['type'], 0xB0)
        self.assertEqual(sdict['origin'], 0x03)
        self.assertEqual(sdict['export_rights'], export_rights)
        self.assertEqual(sdict['fingerprint'], fingerprint) 
        self.assertEqual(sdict['rfu1'], 0x00) 
        self.assertEqual(sdict['rfu2'], 0x00) 
        self.assertEqual(sdict['label'], label) 
        SeedKeeperTest.sid+=[sid]
            
        # test logs
        (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
        self.assertEqual(len(logs), 1)
        last_log= logs[0]
        (ins, id1, id2, res)= last_log
        self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
        self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_SECRET)
        self.assertEqual(id1, sid)
        self.assertEqual(id2, 0xFFFF)
        self.assertEqual(res, 0x9000)

        if SeedKeeperTest.v_applet>=2:
            # test delete
            response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
            self.assertEqual(dic["is_reset"], True)
        else:
            print(f"SeedKeeper v0.1: delete secret not supported!")
    
    #@unittest.skip("debug")
    def test_import_export_secret_plain(self):
        # bip39_12= "praise seed filter man vintage live circle flag zoo orphan feature right"
        # bip39_18= "current later item champion riot seat second seven card evidence pause twice spread reason purity easily surprise split"
        # bip39_24= "chunk hat mirror there suit burst salute patch trumpet drastic spare pilot laptop smile hurry bleak friend rude divide melody iron fame dynamic parrot"
        # bip39s=[bip39_12, bip39_18, bip39_24]
        MNEMONIC = Mnemonic(language="english")
        bip39_12= MNEMONIC.generate(strength=128)
        bip39_18= MNEMONIC.generate(strength=192)
        bip39_24= MNEMONIC.generate(strength=256)
        bip39s=[bip39_12, bip39_18, bip39_24]
        
        for bip39 in bip39s:
            bip39_list= list(bip39.encode("utf-8"))
            secret_list= [len(bip39_list)]+bip39_list
            secret_type= 0x30
            export_rights= 0x01
            label= "Test: BIP39 seed with " + str(len(bip39.split(' '))) + " words export-allowed"
            #(sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_plain_secret(secret_type, export_rights, label, secret)
            header= SeedKeeperTest.cc.make_header(secret_type, export_rights, label)
            secret_dic={'header':header, 'secret_list':secret_list}
            (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
            
            #sdict= SeedKeeperTest.cc.seedkeeper_export_plain_secret(sid)
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], secret_type)
            self.assertEqual(sdict['origin'], 0x01)
            self.assertEqual(sdict['export_rights'], export_rights)
            self.assertEqual(sdict['fingerprint'], fingerprint) 
            self.assertEqual(sdict['rfu1'], 0x00) 
            self.assertEqual(sdict['rfu2'], 0x00) 
            self.assertEqual(sdict['label'], label) 
            self.assertEqual(sdict['secret_list'], secret_list) 
            SeedKeeperTest.sid+=[sid]
                        
            # test SeedKeeper logging
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(True)
            self.assertTrue(len(logs)>=2)
            exp_log= logs[0]
            (ins, id1, id2, res)= exp_log
            self.assertEqual(len(exp_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_SECRET)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9000)
            imp_log= logs[1]
            (ins, id1, id2, res)= imp_log
            self.assertEqual(len(imp_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_IMPORT_SECRET)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9000)

            if SeedKeeperTest.v_applet>=2:
                # test delete
                response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
                self.assertEqual(dic["is_reset"], True)
            else:
                print(f"SeedKeeper v0.1: delete secret not supported!")

    #@unittest.skip("debug")
    def test_import_export_secret_encrypted(self):

        # get authentikey then import it in plaintext
        authentikey=SeedKeeperTest.cc.card_export_authentikey()
        authentikey_list= list( authentikey.get_public_key_bytes(compressed=False) )
        secret_list= [len(authentikey_list)] + authentikey_list
        secret_type= 0x70
        export_rights= 0x01
        label= "SeedKeeper own authentikey"
        header= SeedKeeperTest.cc.make_header(secret_type, export_rights, label)
        secret_dic={'header':header, 'secret_list':secret_list}
        (sid_authentikey, fingerprint_authentikey)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
        # export the authentikey
        sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid_authentikey, sid_pubkey= None)
        self.assertEqual(sdict['id'], sid_authentikey)
        self.assertEqual(sdict['type'], secret_type)
        self.assertEqual(sdict['origin'], 0x01)
        self.assertEqual(sdict['export_rights'], export_rights)
        self.assertEqual(sdict['fingerprint'], fingerprint_authentikey) 
        self.assertEqual(sdict['rfu1'], 0x00) 
        self.assertEqual(sdict['rfu2'], 0x00) 
        self.assertEqual(sdict['label'], label) 
        self.assertEqual(sdict['secret_list'], secret_list) 
        SeedKeeperTest.sid+=[sid_authentikey]   
        
        sid=0
        seed_size= range(16, 65, 16) #64
        for size in seed_size:
            # generate masterseed on card
            export_rights= 0x02
            label= "Test: Mymasterseed  "+ str(size) + "bytes export-encrypted"
            (response, sw1, sw2, sid, fingerprint)= SeedKeeperTest.cc.seedkeeper_generate_masterseed(size, export_rights, label)
            self.assertEqual(sw1, 0x90)
            self.assertEqual(sw2, 0x00)
            
            # check logs
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_GENERATE_MASTERSEED)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9000)
            
            # export secret in plaintext => should fail given the export rights
            with self.assertRaises(SeedKeeperError):
                sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
                
            # test logs for fail
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_SECRET)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9c31) # SW_EXPORT_NOT_ALLOWED
        
            # export it encrypted
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= sid_authentikey)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], 0x10)
            self.assertEqual(sdict['origin'], 0x03)
            self.assertEqual(sdict['export_rights'], export_rights)
            self.assertEqual(sdict['fingerprint'], fingerprint) 
            self.assertEqual(sdict['rfu1'], 0x00) 
            self.assertEqual(sdict['rfu2'], 0x00) 
            self.assertEqual(sdict['label'], label) 
            SeedKeeperTest.sid+=[sid]
            
            # check logs
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_SECRET)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, sid_authentikey)
            self.assertEqual(res, 0x9000) 
            
            # reimport it encrypted then check if it matches
            (sid2, fingerprint2)=  SeedKeeperTest.cc.seedkeeper_import_secret(sdict, sid_pubkey=sid_authentikey)
            self.assertEqual(fingerprint, fingerprint2) 
            
            # check logs
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
            self.assertEqual(len(logs), 1)
            last_log= logs[0]
            (ins, id1, id2, res)= last_log
            self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_IMPORT_SECRET)
            self.assertEqual(id1, sid2)
            self.assertEqual(id2, sid_authentikey)
            self.assertEqual(res, 0x9000) 
            
            if SeedKeeperTest.v_applet>=2:
                # test delete 
                response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
                self.assertEqual(dic["is_reset"], True) 
                # test delete reimported key
                response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid2)
                self.assertEqual(dic["is_reset"], True)
            else:
                print(f"SeedKeeper v0.1: delete secret not supported!")

        if SeedKeeperTest.v_applet>=2:
            # test delete imported authentikey
            response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid_authentikey)
            self.assertEqual(dic["is_reset"], True)
        else:
            print(f"SeedKeeper v0.1: delete secret not supported!")

    #@unittest.skip("debug")
    def test_BIP39_mnemonic_v2(self):
        
        # introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: Masterseed with BIP39 not supported!")
            return

        wordlist = "english"
        MNEMONIC = Mnemonic(language=wordlist)
        bip39_12= MNEMONIC.generate(strength=128)
        bip39_18= MNEMONIC.generate(strength=192)
        bip39_24= MNEMONIC.generate(strength=256)
        bip39s=[bip39_12, bip39_18, bip39_24]
        
        bip39_passphrases= ["", "", "HelloDarknessMyOldFriend"]

        for index, bip39 in enumerate(bip39s):

            # make header
            export_rights = 'Plaintext export allowed'
            stype = 'Masterseed' #'BIP39 mnemonic v2'
            label = f"Test BIP39v2 {len(bip39.split())} words"
            header = SeedKeeperTest.cc.make_header(stype, export_rights, label, subtype=0x01)
            #print(f"Label: {label}")

            # format secret
            wordlist_byte = 0x00 # english
        
            try:
                bip39_entropy_bytes = mnemonic_to_entropy(bip39, wordlist)
                bip39_entropy_list = list(bip39_entropy_bytes)
            except Exception as ex:
                print(f"Error: failed to convert mnemonic {bip39} to entropy!")
                continue
            
            bip39_passphrase = bip39_passphrases[index]
            bip39_passphrase_list = list(bytes(bip39_passphrase, 'utf-8'))
            try:
                masterseed_bytes= mnemonic_to_masterseed(bip39, bip39_passphrase, 'BIP39 mnemonic')
                masterseed_list = list(masterseed_bytes)
            except Exception as ex:
                print(f"Error: failed to convert mnemonic {bip39} to masterseed!")
                continue

            # this format is backward compatible with Masterseed, this facilitates encrypted export to satochip
            secret_list = ([len(masterseed_list)] + 
                            masterseed_list + 
                            [wordlist_byte] + 
                            [len(bip39_entropy_list)] + 
                            bip39_entropy_list + 
                            [len(bip39_passphrase_list)] + 
                            bip39_passphrase_list
                            )

            secret_dic={'header':header, 'secret_list':secret_list}
            # import in plaintext
            (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
            
            # export in plaintext
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], 0x10) # 'Masterseed'
            self.assertEqual(sdict['origin'], 0x01)
            self.assertEqual(sdict['export_rights'], 0x01) # 'Plaintext export allowed'
            self.assertEqual(sdict['fingerprint'], fingerprint) 
            self.assertEqual(sdict['rfu1'], 0x01) 
            self.assertEqual(sdict['rfu2'], 0x00) 
            self.assertEqual(sdict['label'], label) 
            self.assertEqual(sdict['secret_list'], secret_list) 
            SeedKeeperTest.sid+=[sid]
                        
            # test SeedKeeper logging
            (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(True)
            self.assertTrue(len(logs)>=2)
            exp_log= logs[0]
            (ins, id1, id2, res)= exp_log
            self.assertEqual(len(exp_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_EXPORT_SECRET)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9000)
            imp_log= logs[1]
            (ins, id1, id2, res)= imp_log
            self.assertEqual(len(imp_log), SeedKeeperTest.LOG_SIZE)
            self.assertEqual(ins, SeedKeeperTest.INS_IMPORT_SECRET)
            self.assertEqual(id1, sid)
            self.assertEqual(id2, 0xFFFF)
            self.assertEqual(res, 0x9000)

            if SeedKeeperTest.v_applet>=2:
                # test delete
                response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
                self.assertEqual(dic["is_reset"], True) 

                # test SeedKeeper logging
                (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
                self.assertEqual(len(logs), 1)
                last_log= logs[0]
                (ins, id1, id2, res)= last_log
                self.assertEqual(len(last_log), SeedKeeperTest.LOG_SIZE)
                self.assertEqual(ins, 0xA5) # INS_RESET_SECRET
                self.assertEqual(id1, sid)
                self.assertEqual(id2, 0xFFFF)
                self.assertEqual(res, 0x9000)
            else:
                print(f"SeedKeeper v0.1: delete secret not supported!")

    #@unittest.skip("debug")
    def test_generate_random_secret(self):

        # introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: generate random_secret with external entropy not supported!")
            return

        pw_sizes = [16, 32, 48, 64]
        for index, size in enumerate(pw_sizes):

            stype = 0x91 # Master Password
            export_rights = 0x01 # Plaintext export allowed
            subtype = 0x00 # default
            label = f"Test MasterPassword Size:{size}"

            # random entropy as ascii text
            entropy = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(size))
            #print(f"Entropy: {entropy}")

            save_entropy = True

            # generate on card, 
            (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_generate_random_secret(stype, subtype, size, export_rights, label, save_entropy, entropy)
            self.assertEqual(sw1, 0x90)
            self.assertEqual(sw2, 0x00)
            sid = dic['id']
            fingerprint = dic['fingerprint']
            sid_entropy = dic['id_entropy']
            fingerprint_entropy = dic['fingerprint_entropy']
            
            # export master password in plaintext
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], 0x91) # SECRET_TYPE_MASTER_PASSWORD
            self.assertEqual(sdict['origin'], 0x03)
            self.assertEqual(sdict['export_rights'], export_rights)
            self.assertEqual(sdict['fingerprint'], fingerprint) 
            self.assertEqual(sdict['rfu1'], subtype) # subtype is an additional metadata 
            self.assertEqual(sdict['rfu2'], 0x00) 
            self.assertEqual(sdict['label'], f"Test MasterPassword Size:{size}") 

            # test master password fingerprint
            sha256 = hashlib.sha256()
            secret_hex= sdict["secret"]
            fingerprint_sw = hashlib.sha256(bytes.fromhex(secret_hex)).hexdigest()[0:8]
            self.assertEqual(fingerprint_sw, sdict['fingerprint'])

            # export entropy in plaintext
            sdict_entropy= SeedKeeperTest.cc.seedkeeper_export_secret(sid_entropy, sid_pubkey= None)
            self.assertEqual(sdict_entropy['id'], sid_entropy)
            self.assertEqual(sdict_entropy['type'], 0x80) # SECRET_TYPE_KEY
            self.assertEqual(sdict_entropy['origin'], 0x03)
            self.assertEqual(sdict_entropy['export_rights'], export_rights)
            self.assertEqual(sdict_entropy['fingerprint'], fingerprint_entropy) 
            self.assertEqual(sdict_entropy['rfu1'], 0x10) # subtype 0x10 for entropy
            self.assertEqual(sdict_entropy['rfu2'], 0x00) 
            self.assertEqual(sdict_entropy['label'], "entropy") 

            # test entropy derivation: Secret is the 'size' first bytes of sha512(entropy) 
            entropy_hex = sdict_entropy["secret"]
            secret_hex_sw = hashlib.sha512(bytes.fromhex(entropy_hex[2:])).hexdigest()[0:2*size] # size in bytes => 2*size in hex
            #print(f"secret_hex_sw: {secret_hex_sw}")
            #print(f"secret_hex: {secret_hex}")
            self.assertEqual(secret_hex_sw, secret_hex[2:])

            # derive secrets from master password: Derived_data is the 64bytes HmacSha512 of Salt (used as key) and Master_Password (used as message)
            # random salt
            salt_str = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(size))
            salt_bytes = salt_str.encode('utf-8')
            secret_bytes = bytes.fromhex(secret_hex_sw)
            (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_derive_master_password(salt_str, sid, sid_pubkey=None)
            derived = dic['derived_data']
            derived_sw = hmac.new(salt_bytes, secret_bytes, hashlib.sha512).hexdigest()
            #print(f"derived: {derived}")
            #print(f"derived_sw: {derived_sw}")
            self.assertEqual(derived_sw, derived)

            # test delete master password
            response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
            self.assertEqual(dic["is_reset"], True) 

            # test delete entropy
            response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid_entropy)
            self.assertEqual(dic["is_reset"], True) 


    # from test_satochip.py
    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector1(self):  
        # Bip32 test vectors 1 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors)
        
        # introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: BIP32 derivation not supported!")
            return

        seed_hex= "000102030405060708090a0b0c0d0e0f"
        seed_list= list(bytes.fromhex(seed_hex)) 
        secret_list= [len(seed_list)]+seed_list

        # make header
        export_rights = 0x01 # 'Plaintext export allowed'
        stype = 'Masterseed'
        label = f"Test Masterseed BIP32 vector1"
        header = SeedKeeperTest.cc.make_header(stype, export_rights, label)
        print(f"header: {header}")
        #print(f"Label: {label}")

        secret_dic={'header':header, 'secret_list':secret_list}
        # import in plaintext
        (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
        print(f"sid: {sid}")
        print(f"fingerprint: {fingerprint}")

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

        xprvs=[  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        ]

        #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                print(f"Derivation {i}")
                xpub= SeedKeeperTest.cc.card_bip32_get_xpub(paths[i], 'standard', is_mainnet=True, sid=sid)
                self.assertEqual(xpub, xpubs[i])

        # test xprv
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                print(f"Xprv Derivation {i}")
                xprv= SeedKeeperTest.cc.card_bip32_get_xprv(paths[i], 'standard', is_mainnet=True, sid=sid)
                print(f"xprv   : {xprv}")
                print(f"xprv_sw: {xprvs[i]}")
                self.assertEqual(xprv, xprvs[i])
        
        # test delete seed
        response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
        self.assertEqual(dic["is_reset"], True) 

    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector2(self):
        
        # introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: BIP32 not supported!")
            return

        seed_hex= "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        seed_list= list(bytes.fromhex(seed_hex)) 
        secret_list= [len(seed_list)]+seed_list

        # make header
        export_rights = 0x01 # 'Plaintext export allowed'
        stype = 'Masterseed'
        label = f"Test Masterseed BIP32 vector2"
        header = SeedKeeperTest.cc.make_header(stype, export_rights, label)
        print(f"header: {header}")
        #print(f"Label: {label}")

        secret_dic={'header':header, 'secret_list':secret_list}
        # import in plaintext
        (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
        print(f"sid: {sid}")
        print(f"fingerprint: {fingerprint}")
        
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

        xprvs=[ "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        ]

        #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                print(f"Derivation {i}")
                xpub= SeedKeeperTest.cc.card_bip32_get_xpub(paths[i], 'standard', is_mainnet=True, sid=sid)
                self.assertEqual(xpub, xpubs[i])
        
        # test xprv
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                print(f"Xprv Derivation {i}")
                xprv= SeedKeeperTest.cc.card_bip32_get_xprv(paths[i], 'standard', is_mainnet=True, sid=sid)
                self.assertEqual(xprv, xprvs[i])

        # test delete seed
        response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
        self.assertEqual(dic["is_reset"], True) 

    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_seed_vector3(self):
        
        # introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: BIP32 derivation not supported!")
            return

        seed_hex= "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        seed_list= list(bytes.fromhex(seed_hex)) 
        secret_list= [len(seed_list)]+seed_list

        # make header
        export_rights = 0x01 # 'Plaintext export allowed'
        stype = 'Masterseed'
        label = f"Test Masterseed BIP32 vector2"
        header = SeedKeeperTest.cc.make_header(stype, export_rights, label)
        print(f"header: {header}")
        #print(f"Label: {label}")

        secret_dic={'header':header, 'secret_list':secret_list}
        # import in plaintext
        (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
        print(f"sid: {sid}")
        print(f"fingerprint: {fingerprint}")

        paths=[ "m",
                "m/0'"]
        xpubs=[ "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"]
        xprvs=[ "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"]
   
        #subtests
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                print(f"Derivation {i}")
                xpub= SeedKeeperTest.cc.card_bip32_get_xpub(paths[i], 'standard', is_mainnet=True, sid=sid)
                self.assertEqual(xpub, xpubs[i])

        # test xprv
        for i in range(0, len(paths)):
            with self.subTest(i=i):
                print(f"Xprv Derivation {i}")
                xprv= SeedKeeperTest.cc.card_bip32_get_xprv(paths[i], 'standard', is_mainnet=True, sid=sid)
                self.assertEqual(xprv, xprvs[i])

        # test delete seed
        response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
        self.assertEqual(dic["is_reset"], True) 

    #@unittest.skip("debug")
    def test_card_bip32_get_extendedkey_bip85(self):

        # introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: BIP32 derivation not supported!")
            return

        # vectors generated using https://iancoleman.io/bip39/#english
        wordlist = "english"
        MNEMONIC = Mnemonic(language=wordlist)
        #bip39= MNEMONIC.generate(strength=128)
        bip39 = "panel rally element develop cloud diamond brother rack scale path burger arctic"
        masterseed = "d42b84073d7b0a6ceae2b37eeeffa5f763678f1cbf17f22ed2f8a38401528c769744fb5020ce05bc4e1f33dfb0d1d716c528d18dcfa2ab08c7efcee8655148f2"
        xprv = "xprv9s21ZrQH143K4MUxTrPj2uJL5rvsAWYEhR5RxsC6tKAVoCyWhrdhD6JEgPmEoJCCKKyNLTFiCwvbBsKjmiobg3WQQT64EFnJ6SEvMkRWydx"
        bip85_childkey = "devote sheriff detail immense current online clown letter loop spread weasel filter"
        # path m/83696968'/39'/{language}'/{words}'/{index}'
        path= "m/83696968'/39'/0'/12'/0'"

        # make header
        export_rights = 0x01 #'Plaintext export allowed'
        stype = 'Masterseed' #'BIP39 mnemonic v2'
        label = f"Test BIP85 with BIP39v2 {len(bip39.split())} words"
        header = SeedKeeperTest.cc.make_header(stype, export_rights, label, subtype=0x01)
        #print(f"Label: {label}")

        # format secret
        wordlist_byte = 0x00 # english
    
        try:
            bip39_entropy_bytes = mnemonic_to_entropy(bip39, wordlist)
            bip39_entropy_list = list(bip39_entropy_bytes)
        except Exception as ex:
            print(f"Error: failed to convert mnemonic {bip39} to entropy!")

        bip39_passphrase = ""
        bip39_passphrase_list = list(bytes(bip39_passphrase, 'utf-8'))
        try:
            masterseed_bytes= mnemonic_to_masterseed(bip39, bip39_passphrase, 'BIP39 mnemonic')
            masterseed_list = list(masterseed_bytes)
        except Exception as ex:
            print(f"Error: failed to convert mnemonic {bip39} to masterseed!")

        # this format is backward compatible with Masterseed, this facilitates encrypted export to satochip
        secret_list = ([len(masterseed_list)] + 
                        masterseed_list + 
                        [wordlist_byte] + 
                        [len(bip39_entropy_list)] + 
                        bip39_entropy_list + 
                        [len(bip39_passphrase_list)] + 
                        bip39_passphrase_list
                        )

        secret_dic={'header':header, 'secret_list':secret_list}
        # import in plaintext
        (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
        
        # export masterseed in plaintext
        sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
        self.assertEqual(sdict['id'], sid)
        self.assertEqual(sdict['type'], 0x10) # 'Masterseed'
        self.assertEqual(sdict['origin'], 0x01)
        self.assertEqual(sdict['export_rights'], export_rights)
        self.assertEqual(sdict['label'], label) 
        self.assertEqual(sdict['secret_list'], secret_list) 
        masterseed2= bytes(masterseed_list).hex()
        print(f"masterseed2: {masterseed2}")
        self.assertEqual(masterseed, masterseed2) 

        # test BIP85 derivation on card
        entropy_bytes=  SeedKeeperTest.cc.card_bip32_get_extendedkey(path, sid=sid, option_flags=0x04)
        #print(entropy_bytes.hex())

        # get Bip39 from entropy
        bip39_from_entropy = entropy_to_mnemonic(entropy_bytes[0:16], wordlist) # 16 bytes of entropy for 12 words
        #print(f"bip39_from_entropy: {bip39_from_entropy}")
        self.assertEqual(bip39_from_entropy, bip85_childkey)

        # test delete BIP39v2 seed
        response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
        self.assertEqual(dic["is_reset"], True) 


    #@unittest.skip("debug")
    def test_verify_PIN(self):
        (response, sw1, sw2)= SeedKeeperTest.cc.card_verify_PIN_deprecated(0, SeedKeeperTest.wrong_pin)
        self.assertEqual(sw1, 0x63)
        (response, sw1, sw2)= SeedKeeperTest.cc.card_verify_PIN_deprecated(0, SeedKeeperTest.pin)
        self.assertEqual(sw1, 0x90)
        self.assertEqual(sw2, 0x00)
        # check logs
        (logs, nbtotal_logs, nbavail_logs)= SeedKeeperTest.cc.seedkeeper_print_logs(False)
        self.assertTrue(len(logs)==1)
        (ins, id1, id2, res)= logs[0]
        self.assertEqual(ins, SeedKeeperTest.INS_VERIFY_PIN)
        self.assertEqual(id1, 0xFFFF)
        self.assertEqual(id2, 0xFFFF)
        self.assertEqual(res & 0xFF00, 0x6300)
    
    #@unittest.skip("debug")
    def test_memory(self):

        # this test will fill all the card available memory
        # Secret deletion introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: delete secret not supported!")
            return

        sids = []
        secrets = []
        fingerprints = []

        secret_size= 1
        while (True):
            print(f"secret_size: {secret_size}")
            secret_list = [(secret_size>>8)%256, (secret_size%256)] + list(urandom(secret_size)); 

            # make header
            export_rights = 0x01 #'Plaintext export allowed'
            stype = 'Data'
            label = f"Test Data with {secret_size}+2 bytes"
            header = SeedKeeperTest.cc.make_header(stype, export_rights, label)
            #print(f"Label: {label}")

            secret_dic={'header':header, 'secret_list':secret_list}
            # import in plaintext
            try:    
                (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
                sids+=[sid]
                secrets+= [secret_list]
                fingerprints+= [fingerprint]

                (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_get_status()
                print(f"nb_secrets: {dic['nb_secrets']}")
                print(f"total_memory: {dic['total_memory']}")
                print(f"free_memory: {dic['free_memory']}")
                print(f"nb_logs_total: {dic['nb_logs_total']}")
                print(f"nb_logs_avail: {dic['nb_logs_avail']}")
                print(f"last_log: {dic['last_log']}")

            except Exception as ex:
                print(f"Exception during secret import: {ex}")
                break

            secret_size+=1

        for index, sid in enumerate(sids):

            # export secret
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], 0xc0)
            self.assertEqual(sdict['origin'], 0x01)
            self.assertEqual(sdict['export_rights'], 0x01)
            self.assertEqual(sdict['secret_list'], secrets[index]) 
            self.assertEqual(sdict['fingerprint'], fingerprints[index]) 
            
            # destroy object
            response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
            self.assertEqual(dic["is_reset"], True) 

            (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_get_status()
            print(f"nb_secrets: {dic['nb_secrets']}")
            print(f"total_memory: {dic['total_memory']}")
            print(f"free_memory: {dic['free_memory']}")
            print(f"nb_logs_total: {dic['nb_logs_total']}")
            print(f"nb_logs_avail: {dic['nb_logs_avail']}")
            print(f"last_log: {dic['last_log']}")

    #@unittest.skip("debug")
    def test_memory_big_secrets(self):

        # this test will fill all the card available memory
        # Secret deletion introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: delete secret not supported!")
            return

        sids = []
        secrets = []
        fingerprints = []

        secret_size= 192
        while (True):
            print(f"secret_size: {secret_size}")
            secret_list = [(secret_size>>8)%256, (secret_size%256)] + list(urandom(secret_size)); 

            # make header
            export_rights = 0x01 #'Plaintext export allowed'
            stype = 'Data'
            label = f"Test Data with {secret_size}+2 bytes"
            header = SeedKeeperTest.cc.make_header(stype, export_rights, label)
            #print(f"Label: {label}")

            secret_dic={'header':header, 'secret_list':secret_list}
            # import in plaintext
            try:    
                (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
                sids+=[sid]
                secrets+= [secret_list]
                fingerprints+= [fingerprint]

                (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_get_status()
                print(f"nb_secrets: {dic['nb_secrets']}")
                print(f"total_memory: {dic['total_memory']}")
                print(f"free_memory: {dic['free_memory']}")
                print(f"nb_logs_total: {dic['nb_logs_total']}")
                print(f"nb_logs_avail: {dic['nb_logs_avail']}")
                print(f"last_log: {dic['last_log']}")

            except Exception as ex:
                print(f"Exception during secret import: {ex}")
                break

            secret_size+=64

        for index, sid in enumerate(sids):

            # export secret
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], 0xc0) 
            self.assertEqual(sdict['origin'], 0x01)
            self.assertEqual(sdict['export_rights'], 0x01)
            self.assertEqual(sdict['secret_list'], secrets[index]) 
            self.assertEqual(sdict['fingerprint'], fingerprints[index]) 
            
            # destroy object
            response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
            self.assertEqual(dic["is_reset"], True) 

            (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_get_status()
            print(f"nb_secrets: {dic['nb_secrets']}")
            print(f"total_memory: {dic['total_memory']}")
            print(f"free_memory: {dic['free_memory']}")
            print(f"nb_logs_total: {dic['nb_logs_total']}")
            print(f"nb_logs_avail: {dic['nb_logs_avail']}")
            print(f"last_log: {dic['last_log']}")

    #@unittest.skip("debug")
    def test_memory_passwords(self):

        # this test will fill all the card available memory
        # Secret deletion introduced in SeedKeeper v0.2
        if SeedKeeperTest.v_applet==1:
            print(f"SeedKeeper v0.1: delete secret not supported!")
            return

        sids = []
        secrets = []
        urls = []
        logins = []
        fingerprints = []

        
        while (True):
            # variable size
            secret_size= randrange(10,16)
            # random ascii login
            login_str = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(secret_size))
            login_bytes = login_str.encode('utf-8')
            url_str = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(secret_size))
            url_bytes = url_str.encode('utf-8')
            secret_list = [(secret_size%256)] + list(urandom(secret_size)) + [len(login_bytes)] + list(login_bytes) + [len(url_bytes)] + list(url_bytes)

            # make header
            export_rights = 0x01 #'Plaintext export allowed'
            stype = 'Password'
            label = f"Test password with {secret_size} bytes"
            header = SeedKeeperTest.cc.make_header(stype, export_rights, label, subtype=0x01)
            #print(f"Label: {label}")

            secret_dic={'header':header, 'secret_list':secret_list}
            # import in plaintext
            try:    
                (sid, fingerprint)=  SeedKeeperTest.cc.seedkeeper_import_secret(secret_dic, sid_pubkey=None)
                sids+=[sid]
                secrets+= [secret_list]
                urls += [url_str]
                logins += [login_str]
                fingerprints+= [fingerprint]

                (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_get_status()
                print(f"nb_secrets: {dic['nb_secrets']}")
                print(f"total_memory: {dic['total_memory']}")
                print(f"free_memory: {dic['free_memory']}")
                print(f"nb_logs_total: {dic['nb_logs_total']}")
                print(f"nb_logs_avail: {dic['nb_logs_avail']}")
                print(f"last_log: {dic['last_log']}")

            except Exception as ex:
                print(f"Exception during secret import: {ex}")
                break

        for index, sid in enumerate(sids):

            # export secret
            sdict= SeedKeeperTest.cc.seedkeeper_export_secret(sid, sid_pubkey= None)
            self.assertEqual(sdict['id'], sid)
            self.assertEqual(sdict['type'], 0x90)
            self.assertEqual(sdict['origin'], 0x01)
            self.assertEqual(sdict['export_rights'], 0x01)
            self.assertEqual(sdict['secret_list'], secrets[index]) 
            self.assertEqual(sdict['fingerprint'], fingerprints[index]) 
            
            # destroy object
            response, sw1, sw2, dic = SeedKeeperTest.cc.seedkeeper_reset_secret(sid)
            self.assertEqual(dic["is_reset"], True) 

            (response, sw1, sw2, dic) = SeedKeeperTest.cc.seedkeeper_get_status()
            print(f"nb_secrets: {dic['nb_secrets']}")
            print(f"total_memory: {dic['total_memory']}")
            print(f"free_memory: {dic['free_memory']}")
            print(f"nb_logs_total: {dic['nb_logs_total']}")
            print(f"nb_logs_avail: {dic['nb_logs_avail']}")
            print(f"last_log: {dic['last_log']}")


    #TODO

    # try  to export non existent id
    # test factory reset
    # test Block/Unblock pin
    # test v0.1 vs v0.2


    
    
def __main__():
    unittest.main()

if __name__ == "__main__":
    __main__()

