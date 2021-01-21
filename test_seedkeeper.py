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
import random
import unittest
from os import urandom

from mnemonic import Mnemonic

from pysatochip.CardConnector import CardConnector, UninitializedSeedError, SeedKeeperError
from pysatochip.JCconstants import JCconstants
from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION

# try: 
    # from Client import Client
    # from handler import HandlerTxt, HandlerSimpleGUI
# except Exception as e:
    # print('ImportError: '+repr(e))
    # from seedkeeper.Client import Client
    # from seedkeeper.handler import HandlerTxt, HandlerSimpleGUI


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
        
        #setup seedkeeper
        # handler= HandlerTxt() #HandlerSimpleGUI(logger.getEffectiveLevel())
        # client= Client(None, handler, logger.getEffectiveLevel())

        logger.info("Initialize new CardConnector...")
        cls.cc = CardConnector(None, logger.getEffectiveLevel())
        time.sleep(1) # give some time to initialize reader...
        logger.info("ATR: "+str(cls.cc.card_get_ATR()))
        
        # check setup
        while(cls.cc.card_present):
            (response, sw1, sw2, d)=cls.cc.card_get_status()
            
            # todo: check card type!
            
            # check version
            if  (cls.cc.setup_done):
                #v_supported= CardConnector.SATOCHIP_PROTOCOL_VERSION 
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
            logger.error(repr(ex))            
            return
        
##############

    def test_generate_masterseed(self):
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
        
    #TODO

    # test Block/Unblock pin
    # try  to export non existent id
    
    
def __main__():
    unittest.main()

if __name__ == "__main__":
    __main__()

