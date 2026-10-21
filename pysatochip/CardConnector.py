from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.util import toHexString, toBytes
from smartcard.sw.SWExceptions import SWException

from .JCconstants import *
from .CardDataParser import CardDataParser
from .ecc import ECPubkey, ECPrivkey
# SecureChannelError / UninitializedSecureChannelError are defined in SecureChannel.py
# and re-exported here on purpose: AGENTS.md documents the protocol exceptions as
# living in CardConnector, and downstream code imports them from here.
from .SecureChannel import SecureChannel, SecureChannelError, UninitializedSecureChannelError
from . import set_log_level
from .util import msg_magic, sha256d, hash_160, EncodeBase58Check, dict_swap_keys_values
from .certificate_validator import CertificateValidator

import hashlib
import hmac
import warnings
import base64
import logging
import threading
from collections import namedtuple
from os import urandom
from typing import Union, List, Optional

#debug
# import sys
# import traceback

logger = logging.getLogger(__name__)
# NB: no logger.setLevel() here on purpose. Module loggers must stay at NOTSET
# so that a level set on the `pysatochip` package logger cascades to all of
# them -- see pysatochip.set_log_level().

MSG_WARNING= ("Before you request coins to be sent to addresses in this "
                    "wallet, ensure you can pair with your device, or that you have "
                    "its seed (and passphrase, if any).  Otherwise all coins you "
                    "receive will be unspendable.")
                    
MSG_USE_2FA= ("Do you want to use 2-Factor-Authentication (2FA)?\n\n"
                "With 2FA, any transaction must be confirmed on a second device such as \n"
               "your smartphone. First you have to install the Satochip-2FA android app on \n"
               "google play. Then you have to pair your 2FA device with your Satochip \n"
               "by scanning the qr-code on the next screen. \n"
               "Warning: be sure to backup a copy of the qr-code in a safe place, \n"
               "in case you have to reinstall the app!")

SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
XPUB_HEADERS_MAINNET = {
        'standard':    '0488b21e',  # xpub
        'p2wpkh-p2sh': '049d7cb2',  # ypub
        'p2wsh-p2sh':  '0295b43f',  # Ypub
        'p2wpkh':      '04b24746',  # zpub
        'p2wsh':       '02aa7ed3',  # Zpub
    }
XPUB_HEADERS_TESTNET = {
        'standard':    '043587cf',  # tpub
        'p2wpkh-p2sh': '044a5262',  # upub
        'p2wsh-p2sh':  '024289ef',  # Upub
        'p2wpkh':      '045f1cf6',  # vpub
        'p2wsh':       '02575483',  # Vpub
    }
# based on https://github.com/spesmilo/electrum/blob/master/electrum/constants.py
XPRV_HEADERS_MAINNET = {
        'standard':    '0488ade4',  # xprv
        'p2wpkh-p2sh': '049d7878',  # yprv
        'p2wsh-p2sh':  '0295b005',  # Yprv
        'p2wpkh':      '04b2430c',  # zprv
        'p2wsh':       '02aa7a99',  # Zprv
    }
XPRV_HEADERS_TESTNET = {
        'standard':    '04358394',  # tprv
        'p2wpkh-p2sh': '044a4e28',  # uprv
        'p2wsh-p2sh':  '024285b5',  # Uprv
        'p2wpkh':      '045f18bc',  # vprv
        'p2wsh':       '02575048',  # Vprv
    }

# a key derived (or tweaked) through the CardConnector, as returned by the card,
# replayed if the card loses it (see CardConnector._restore_derived_keys)
Bip32Derivation = namedtuple('Bip32Derivation', 'path sid option_flags pubkey chaincode')
TaprootTweak = namedtuple('TaprootTweak', 'keynbr tweak bypass_flag derivation tweaked_pubkey')

# Instructions whose APDU body carries no secret material, in either direction,
# and may therefore be rendered in full in debug logs.
#
# This is an allow-list on purpose, and it governs both directions: anything not
# named here has its body masked, so a newly added secret-bearing instruction
# stays masked until someone deliberately clears it.
_LOGGABLE_INS = frozenset({
    0xA4,                                       # ISO SELECT: AID only
    0xFF,                                       # reader pseudo-APDU
    JCconstants.INS_GET_STATUS,
    JCconstants.INS_INIT_SECURE_CHANNEL,        # ephemeral pubkey + signatures
    JCconstants.INS_PROCESS_SECURE_CHANNEL,     # outer wrapper; body is ciphertext
    JCconstants.INS_GET_CHALLENGE,
    JCconstants.INS_CHALLENGE_RESPONSE_PKI,
    JCconstants.INS_EXPORT_PKI_CERTIFICATE,
    JCconstants.INS_EXPORT_PKI_PUBKEY,
    JCconstants.INS_BIP32_GET_AUTHENTIKEY,
    JCconstants.INS_LOGOUT_ALL,
    JCconstants.INS_LIST_KEYS,
    JCconstants.INS_LIST_PINS,
})


def _redact_apdu(apdu):
    """Hex of a command APDU for logging, with the data field masked unless the
    instruction is on _LOGGABLE_INS."""
    apdu = list(apdu)
    if len(apdu) < 5:
        return toHexString(apdu)
    if apdu[1] in _LOGGABLE_INS:
        return toHexString(apdu)
    return f"{toHexString(apdu[0:5])}{(len(apdu) - 5) * ' *'}"


def _redact_response(response, ins=None):
    """Hex of a response APDU for logging, masked unless the instruction that
    produced it is on _LOGGABLE_INS. `ins=None` means "unknown", which masks."""
    response = list(response)
    if ins in _LOGGABLE_INS:
        return toHexString(response)
    return f"({len(response)} bytes)" + len(response) * ' *'


# simple observer that will print on the console the card connection events.
class LogCardConnectionObserver(CardConnectionObserver):
    def update( self, cardconnection, ccevent ):
        if 'connect'==ccevent.type:
            logger.info( 'connecting to' + repr(cardconnection.getReader()) )
        elif 'disconnect'==ccevent.type:
            logger.info( 'disconnecting from' + repr(cardconnection.getReader()) )
        elif 'command'==ccevent.type:
            self._last_ins = ccevent.args[0][1] if len(ccevent.args[0]) > 1 else None
            logger.debug(f"> {_redact_apdu(ccevent.args[0])}")
        elif 'response'==ccevent.type:
            if []==ccevent.args[0]:
                logger.debug( f'< [] {toHexString(ccevent.args[-2:])}')
            else:
                logger.debug( f'< {_redact_response(ccevent.args[0], getattr(self, "_last_ins", None))} {toHexString(ccevent.args[-2:])}')

# a card observer that detects inserted/removed cards and initiate connection
class RemovalObserver(CardObserver):
    """A simple card observer that is notified
    when cards are inserted/removed from the system and
    prints the list of cards
    """
    def __init__(self, cc):
        self.cc=cc
        self.observer = LogCardConnectionObserver() #ConsoleCardConnectionObserver()
            
    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            if card.atr == [59, 141, 1, 128, 251, 160, 0, 0, 3, 151, 66, 84, 70, 89, 4, 1, 207]: continue # Ignore Windows Hello for Business virtual device (3B 8D 01 80 FB A0 00 00 03 97 42 54 46 59 04 01 CF)
            #TODO check ATR and check if more than 1 card?
            logger.info(f"+Inserted: {toHexString(card.atr)}")
            self.cc.card_present= True
            self.cc.cardservice= card
            self.cc.cardservice.connection = card.createConnection()
            self.cc.cardservice.connection.connect()
            self.cc.cardservice.connection.addObserver(self.observer)
            
            # get CPLC
            try:
                (response_CPLC, sw1, sw2) = self.cc.card_get_CPLC()
                logger.debug(f"DEBUG CPLC: {bytes(response_CPLC).hex()}")
                (response_IIN, sw1, sw2) = self.cc.card_get_IIN()
                logger.debug(f"DEBUG IIN: {bytes(response_IIN).hex()}")
                (response_CIN, sw1, sw2) = self.cc.card_get_CIN()
                logger.debug(f"DEBUG CIN: {bytes(response_CIN).hex()}")
                self.cc.UID= response_CPLC+response_IIN+response_CIN
                logger.debug(f"DEBUG UID: {bytes(self.cc.UID).hex()}")
                self.cc.UID_SHA1= hashlib.sha1(bytes(self.cc.UID)).hexdigest()
                logger.debug(f"DEBUG UID_SHA1: {self.cc.UID_SHA1}")
            except Exception as exc:
                logger.warning(f"Error during CPLC/IIN/CIN: {repr(exc)}")
                
            #select applet
            try:
                (response, sw1, sw2) = self.cc.card_select()
                if sw1!=0x90 or sw2!=0x00:
                    self.cc.card_disconnect()
                    break

                # During factory reset, we should not send other commands than reset...
                if self.cc.mode_factory_reset == False:
                    (response, sw1, sw2, status)= self.cc.card_get_status() #todo save card_status for reuse
                    if (sw1!=0x90 or sw2!=0x00) and (sw1!=0x9C or sw2!=0x04):
                        self.cc.card_disconnect()
                        break
                    # the secure channel is NOT initiated here: it is established
                    # lazily, in the thread that first sends a command needing it
                    # (see card_encrypt_secure_channel). Doing it here made this
                    # monitor thread race with the client thread.

                # todo: skip or not for reset_factory?
                if self.cc.client is not None:
                    self.cc.client.request('update_status',True)   
                
            except Exception as exc:
                logger.warning(f"Error during connection: {repr(exc)}")
                if self.cc.client is not None:
                    msg=(f"Exception while selecting card! \nOnly {self.cc.card_filter} cards are supported")
                    self.cc.client.request('show_error',msg)   
                
        for card in removedcards:
            logger.info(f"-Removed: {toHexString(card.atr)}")
            self.cc.card_disconnect()
             

class CardConnector:

    # CardConnector supports Satochip, Seedkeeper, Satodime
    SELECT = [0x00, 0xA4, 0x04, 0x00]
    SATOCHIP_AID= [0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70] #SatoChip
    SEEDKEEPER_AID= [0x53,0x65,0x65,0x64,0x4b,0x65,0x65,0x70,0x65,0x72]  #SeedKeeper
    SATODIME_AID= [0x53, 0x61, 0x74, 0x6f, 0x44, 0x69, 0x6d, 0x65] #SatoDime
    SATOCASH_AID= [0x53, 0x61, 0x74, 0x6f, 0x63, 0x61, 0x73, 0x68] # Satocash
    
    def __init__(self, client=None, loglevel= None, card_filter=None):
        # `loglevel` is a convenience for pysatochip.set_log_level(): it sets the
        # level of the whole package, not of this instance. Leave it as None to
        # let the application own its logging configuration.
        if loglevel is not None:
            set_log_level(loglevel)
        logger.debug("In __init__")
        self.logger= logger
        self.parser=CardDataParser()
        self.client=client
        if self.client is not None:
            self.client.cc=self
        self.cardtype = AnyCardType() #TODO: specify ATR to ignore connection to wrong card types?
        self.needs_2FA = None
        self.is_seeded= None
        self.needsPIN = None # Satocash
        self.setup_done= None
        self.needs_secure_channel= None
        self.mode_factory_reset = False # set to True when performing factory reset
        # Secure channel. self.sc is either None or a fully initialized channel:
        # it is built lazily by whichever thread needs it first (see
        # card_ensure_secure_channel) and published only once complete, so that
        # no caller can observe a half-initialized channel. _sc_lock serializes
        # the initiation itself, so the card monitor thread and a client thread
        # cannot run two 0x81 exchanges against each other.
        self.sc = None
        self._sc_lock = threading.RLock()
        self._sc_initializing = False
        # cache PIN
        self.pin_nbr=None
        self.pin=None
        # cache unlock_secret (Satodime)
        self.is_owner= False # the owner is the user (device) that knows the unlock_secret
        self.unlock_secret= SIZE_UNLOCK_SECRET*[0x00]
        self.unlock_counter= SIZE_UNLOCK_COUNTER*[0x00]
        # Satodime, SeedKeeper or Satochip?
        self.card_filter= card_filter # limit card_select to a subset of [satochip, seedkeeper, satodime]
        self.card_type= "card"
        self.cert_pem=None # PEM certificate of device, if any
        # cache protocol version (version x.y => 256*x+y)
        self.protocol_version = 0
        self.nfc_policy = None
        self.feature_schnorr_policy = None
        self.feature_nostr_policy = None
        self.feature_liquid_policy = None
        # last BIP32 derivation and taproot tweak, replayed if the card loses the derived keys
        # (see _restore_derived_keys)
        self._last_bip32_derivation = None # Bip32Derivation
        self._last_taproot_tweak = None # TaprootTweak


        # cardservice
        self.cardservice= None #will be instantiated when a card is inserted
        try:
            self.cardrequest = CardRequest(timeout=0, cardType=self.cardtype)
            self.cardservice = self.cardrequest.waitforcard()
            #TODO check ATR and check if more than 1 card?
            self.card_present= True
        except CardRequestTimeoutException:
            self.card_present= False
        # monitor if a card is inserted or removed
        self.cardmonitor = CardMonitor()
        self.cardobserver = RemovalObserver(self)
        self.cardmonitor.addObserver(self.cardobserver)

    def set_mode_factory_reset(self, mode_factory_reset):
        """ WARNING: setting mode_factory_reset to True allows to reset the card to factory and erase all data!"""
        self.mode_factory_reset = mode_factory_reset


    ###########################################
    #             Applet management           #
    ###########################################

    def card_transmit(self, plain_apdu):
        logger.debug("In card_transmit")

        sc_retries= 0
        while(self.card_present):

            #encrypt apdu
            ins= plain_apdu[1]
            if (self.needs_secure_channel) and (ins not in [0xA4, 0x81, 0x82, 0xFF, JCconstants.INS_GET_STATUS]):
                apdu = self.card_encrypt_secure_channel(plain_apdu)
            else:
                apdu= plain_apdu

            # transmit apdu
            (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)

            # PIN authentication is required
            if (sw1==0x9C) and (sw2==0x06):
                (response, sw1, sw2)= self.card_verify_PIN_simple()
            # secure channel session lost on the card side
            # 0x9C20: secure channel required (we sent plaintext)
            # 0x9C21: secure channel not initialized
            # 0x9C22: wrong IV (counter desync)
            # 0x9C23: wrong MAC (key desync)
            # The card wiped its session state (applet deselected, card reset or
            # reader power-off during an idle period). Old applets keep the
            # "initialized" flag persistent while the session keys live in
            # transient memory, so a reset can surface as 0x9C22/0x9C23 rather
            # than 0x9C21. Re-establish the channel and retry the APDU once with
            # fresh keys. The retry is bounded on purpose: a persistent
            # 0x9C22/0x9C23 can also indicate tampering on the PC/SC path.
            # (ins 0x81 is the channel initiation itself: never re-initiate it.)
            elif (sw1==0x9C) and (sw2>=0x20) and (sw2<=0x23) and (ins != 0x81):
                if sc_retries > 0:
                    return (response, sw1, sw2)
                sc_retries+= 1
                logger.warning(f"In card_transmit: secure channel error (error code {hex(256*sw1+sw2)}), re-initiating secure channel and retrying once")
                if sw2==0x20:
                    # the card just told us it requires a secure channel
                    self.needs_secure_channel= True
                self.card_initiate_secure_channel()
            #decrypt response
            elif (sw1==0x90) and (sw2==0x00):
                if (self.needs_secure_channel) and (ins not in [0xA4, 0x81, 0x82, 0xFF, JCconstants.INS_GET_STATUS]):
                    response= self.card_decrypt_secure_channel(response, ins)
                return (response, sw1, sw2)
            else:
                return (response, sw1, sw2)

        # no card present
        raise CardNotPresentError('No card found! Please insert card!')

    def card_get_ATR(self):
        logger.debug('In card_get_ATR()')
        return self.cardservice.connection.getATR()
    
    def card_get_CPLC(self):
        logger.debug("In card_get_CPLC")
        cla= 0x80 #CLA_GP
        ins= 0xCA # GPSession.INS_GET_DATA 
        p1= 0x9F
        p2= 0x7F
        apdu=[cla, ins, p1, p2]
        #(response, sw1, sw2)= self.card_transmit(apdu)
        (response, sw1, sw2) = self.cardservice.connection.transmit(apdu) # bypass card_transmit checks...
        return (response, sw1, sw2)
        
    def card_get_IIN(self):
        logger.debug("In card_get_IIN")
        cla= 0x80 #CLA_GP
        ins= 0xCA # GPSession.INS_GET_DATA 
        p1= 0x00
        p2= 0x42
        apdu=[cla, ins, p1, p2]
        #(response, sw1, sw2)= self.card_transmit(apdu)
        (response, sw1, sw2) = self.cardservice.connection.transmit(apdu) # bypass card_transmit checks...
        return (response, sw1, sw2)
        
    def card_get_CIN(self):
        logger.debug("In card_get_CIN")
        cla= 0x80 #CLA_GP
        ins= 0xCA # GPSession.INS_GET_DATA 
        p1= 0x00
        p2= 0x45
        apdu=[cla, ins, p1, p2]
        #(response, sw1, sw2)= self.card_transmit(apdu)
        (response, sw1, sw2) = self.cardservice.connection.transmit(apdu) # bypass card_transmit checks...
        return (response, sw1, sw2)
        
    def card_disconnect(self):
        logger.debug('In card_disconnect()')
        self.pin= None #reset PIN
        self.pin_nbr= None
        self.is_seeded= None
        self.needs_2FA = None
        self.setup_done= None
        self.needs_secure_channel= None
        self.sc= None # a new card needs a new secure channel
        self.card_present= False
        self.card_type= "card"
        if self.cardservice:
            self.cardservice.connection.disconnect()
            self.cardservice= None
        if self.client is not None:
            self.client.request('update_status',False)
        # reset authentikey
        self.parser.authentikey=None
        self.parser.authentikey_coordx= None
        self.parser.authentikey_from_storage=None

    def get_sw12(self, sw1, sw2):
        # sw1 is the high byte: (0x9C, 0x01) is 0x9C01, which is how the
        # JCconstants SW_* values are written.
        return 256*sw1+sw2

    def card_select(self):
        logger.debug("In card_select")

        # selecting an applet resets the secure channel on the card side
        self.sc = None

        # if no filter, try all supported applet in this order
        if (self.card_filter==None):
            self.card_filter= ["satochip", "seedkeeper", "satodime", "satocash"]
        elif isinstance(self.card_filter, str):
            self.card_filter= [self.card_filter]
        
        # try to connect to each allowed applet sequentially
        for card_applet in self.card_filter:
            try:    
                if (card_applet=="satochip"):
                    return self.card_select_satochip()
                elif (card_applet=="seedkeeper"):
                    return self.card_select_seedkeeper()
                elif (card_applet=="satodime"):
                    return self.card_select_satodime()
                elif (card_applet=="satocash"):
                    return self.card_select_satocash()
            except CardSelectError as ex:
                pass
        
        # no suitable card found
        raise CardSelectError("No suitable card found", ins=0xA4)
          
    def card_select_satochip(self):
        apdu = CardConnector.SELECT + [len(CardConnector.SATOCHIP_AID)] + CardConnector.SATOCHIP_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise CardSelectError("CardSelect error", ins=0xA4)
        self.card_type="Satochip"
        logger.debug("Found a Satochip!")
        return (response, sw1, sw2)
                
    def card_select_seedkeeper(self):
        apdu = CardConnector.SELECT + [len(CardConnector.SEEDKEEPER_AID)] + CardConnector.SEEDKEEPER_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise CardSelectError("CardSelect error", ins=0xA4)
        self.card_type="SeedKeeper"
        logger.debug("Found a SeedKeeper!")
        return (response, sw1, sw2)
        
    def card_select_satodime(self):
        apdu = CardConnector.SELECT + [len(CardConnector.SATODIME_AID)] + CardConnector.SATODIME_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise CardSelectError("CardSelect error", ins=0xA4)
        self.card_type="Satodime"
        logger.debug("Found a Satodime!")
        return (response, sw1, sw2)

    def card_select_satocash(self):
        apdu = CardConnector.SELECT + [len(CardConnector.SATOCASH_AID)] + CardConnector.SATOCASH_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise CardSelectError("CardSelect error", ins=0xA4)
        self.card_type="Satocash"
        logger.debug("Found a Satocash!")
        return (response, sw1, sw2)

    def card_get_status(self):
        logger.debug("In card_get_status")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_GET_STATUS
        p1= 0x00
        p2= 0x00
        apdu=[cla, ins, p1, p2]
        (response, sw1, sw2)= self.card_transmit(apdu) # todo: try/except if setup not done
        d={}
        if (sw1==0x90) and (sw2==0x00):
            # card applet version
            d["protocol_major_version"]= response[0]
            d["protocol_minor_version"]= response[1]
            d["applet_major_version"]= response[2]
            d["applet_minor_version"]= response[3]
            d["protocol_version"]= (d["protocol_major_version"]<<8)+d["protocol_minor_version"] 
            self.protocol_version= d["protocol_version"] #cache version
            # PIN/PUK status
            if len(response) >=8:
                d["PIN0_remaining_tries"]= response[4]
                d["PUK0_remaining_tries"]= response[5]
                d["PIN1_remaining_tries"]= response[6]
                d["PUK1_remaining_tries"]= response[7]
                self.needs_2FA= d["needs2FA"]= False #default value
            # 2FA status
            if len(response) >=9:
                self.needs_2FA= d["needs2FA"]= False if response[8]==0X00 else True
            # seed status (satochip)
            if len(response) >=10:
                self.is_seeded= d["is_seeded"]= False if response[9]==0X00 else True
            # setup status
            if len(response) >=11:
                self.setup_done= d["setup_done"]= False if response[10]==0X00 else True
            else:
                self.setup_done= d["setup_done"]= True    
            # secure channel status
            if len(response) >=12:
                self.needs_secure_channel= d["needs_secure_channel"]= False if response[11]==0X00 else True    
            else:
                self.needs_secure_channel= d["needs_secure_channel"]= False
            # NFC policy
            if len(response) >=13:
                self.nfc_policy= d["nfc_policy"]= response[12] # 0:NFC_ENABLED, 1:NFC_DISABLED, 2:NFC_BLOCKED
            else:
                self.nfc_policy= d["nfc_policy"]= 0x00 # NFC_ENABLED by default
            # optional features policy
            # currently only for satochip v0.14-0.5+
            if len(response) >=16:
                # 0:FEATURE_ENABLED, 1:FEATURE_DISABLED, 2:FEATURE_BLOCKED
                self.feature_schnorr_policy= d["feature_schnorr_policy"]= response[13]
                self.feature_nostr_policy = d["feature_nostr_policy"] = response[14]
                self.feature_liquid_policy = d["feature_liquid_policy"] = response[15]
            else:
                # unsupported by default
                self.feature_schnorr_policy = d["feature_schnorr_policy"] = None
                self.feature_nostr_policy = d["feature_nostr_policy"] = None
                self.feature_liquid_policy = d["feature_liquid_policy"] = None

        elif (sw1==0x9c) and (sw2==0x04):
            self.setup_done= d["setup_done"]= False  
            self.is_seeded= d["is_seeded"]= False
            self.needs_secure_channel= d["needs_secure_channel"]= False
            
        else:
            logger.warning(f"Unknown error in get_status() (error code {hex(256*sw1+sw2)})")
            #raise RuntimeError(f"Unknown error in get_status() (error code {hex(256*sw1+sw2)})")
            
        return (response, sw1, sw2, d)
    
    ###########################################
    #         Generic applet methods          #
    ###########################################
    
    def card_get_label(self):
    
        logger.debug("In card_get_label")
        cla= JCconstants.CardEdge_CLA
        ins= 0x3D
        p1= 0x00
        p2= 0x01 #get
        apdu=[cla, ins, p1, p2]
        (response, sw1, sw2)= self.card_transmit(apdu)
        
        if (sw1==0x90 and sw2==0x00):
            label_size= response[0]
            try:
                label= bytes(response[1:]).decode('utf8')
            except UnicodeDecodeError as e:
                logger.warning("UnicodeDecodeError while decoding card label !")
                label=  str(bytes(response[1:]))
        elif (sw1==0x6d and sw2==0x00):  # unsupported by the card  
            label= '(none)'
        else:
            logger.warning(f"Error while recovering card label: {hex(256*sw1+sw2)}")
            label= '(unknown)'
        
        return (response, sw1, sw2, label)
        
    def card_set_label(self, label):
        logger.debug("In card_set_label")
        cla= JCconstants.CardEdge_CLA
        ins= 0x3D
        p1= 0x00
        p2= 0x00 #set
        
        label_list= list(label.encode('utf8'))
        data= [len(label_list)]+label_list
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        (response, sw1, sw2)= self.card_transmit(apdu)
        
        return (response, sw1, sw2)

    def card_get_ndef(self):

        logger.debug("In card_get_ndef")
        cla = JCconstants.CardEdge_CLA
        ins = 0x3F
        p1 = 0x00
        p2 = 0x01  # get
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.card_transmit(apdu)

        if (sw1 == 0x90 and sw2 == 0x00):
            ndef_size = response[0]
            ndef_bytes = bytes(response[1:])
        elif (sw1 == 0x6d and sw2 == 0x00):  # unsupported by the card
            ndef_bytes = []
        else:
            logger.warning(f"Error while recovering card ndef: {hex(256 * sw1 + sw2)}")
            ndef_bytes = []

        return (response, sw1, sw2, ndef_bytes)

    def card_set_ndef(self, ndef_bytes):
        logger.debug("In card_set_ndef")
        cla = JCconstants.CardEdge_CLA
        ins = 0x3F
        p1 = 0x00
        p2 = 0x00  # set

        ndef_list = list(ndef_bytes)
        data = [len(ndef_list)] + ndef_list
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        (response, sw1, sw2) = self.card_transmit(apdu)

        return (response, sw1, sw2)

    def card_get_ndef_v2(self):
        '''
        Get NDEF data if enabled.
        Compatibility: Version v2 is for Satodime v0.2-0.1 and higher
        '''
        logger.debug("In card_get_ndef_v2")
        cla = JCconstants.CardEdge_CLA
        ins = 0x3F
        p1 = 0x00
        p2 = 0x01  # get
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.card_transmit(apdu)

        if sw1 == 0x90 and sw2 == 0x00:
            ndef_policy = response[0]
            ndef_size = 256 * response[1] + response[2]
            if ndef_policy == 0x01:
                ndef_bytes = bytes(response[3:])
            else:
                ndef_bytes = b''
        elif sw1 == 0x6d and sw2 == 0x00:  # unsupported by the card
            raise UnsupportedFeatureError()
        else:
            logger.warning(f"Error while recovering card ndef: {hex(256 * sw1 + sw2)}")
            raise UnexpectedSW12Error(f"Error while recovering card ndef: {hex(256 * sw1 + sw2)}", sw1, sw2)

        return response, sw1, sw2, ndef_policy, ndef_bytes

    def card_set_ndef_v2(self, ndef_bytes, ndef_policy=0x01):
        '''
        Set NDEF data if enabled.
        Compatibility: Version v2 is for Satodime v0.2-0.1 and higher
        '''
        logger.debug("In card_set_ndef_v2")
        cla = JCconstants.CardEdge_CLA
        ins = 0x3F
        p1 = ndef_policy
        p2 = 0x00  # set

        ndef_list = list(ndef_bytes)
        datasize = 1 + len(ndef_list) + SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE
        apduheader = [cla, ins, p1, p2, datasize]

        data = [len(ndef_list)] + ndef_list + self.unlock_counter

        # compute unlock_code
        unlock_code = list(
            hmac.new(bytes(self.unlock_secret), bytes(apduheader + data), hashlib.sha1).digest())

        data = data + unlock_code
        if len(data) != datasize:
            raise Exception(f"Error in card_set_ndef_v2: wrong data length {len(data)} instead of {datasize}")
        apdu = apduheader + data
        (response, sw1, sw2) = self.card_transmit(apdu)

        return response, sw1, sw2

    def card_set_nfc_policy(self, policy_byte):
        logger.debug("In card_set_nfc_policy")
        cla= JCconstants.CardEdge_CLA
        ins= 0x3E
        p1= policy_byte
        p2= 0x00 #set
        
        data= []
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        (response, sw1, sw2)= self.card_transmit(apdu)
        
        return (response, sw1, sw2)

    def card_set_feature_policy(self, feature_id_byte, feature_policy_byte):
        logger.debug("In card_set_feature_policy")
        cla = JCconstants.CardEdge_CLA
        ins = 0x3A
        p1 = feature_id_byte
        p2 = feature_policy_byte

        data = []
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        (response, sw1, sw2) = self.card_transmit(apdu)

        return (response, sw1, sw2)

    def card_setup(self,
                    pin_tries0, ublk_tries0, pin0, ublk0,
                    pin_tries1, ublk_tries1, pin1, ublk1,
                    memsize, memsize2,
                    create_object_ACL, create_key_ACL, create_pin_ACL,
                    option_flags=0, hmacsha160_key=None, amount_limit=0):
        
        logger.debug("In card_setup")

        # check pin format
        if type(pin0) == str:
            pin0 = list(pin0.encode("utf-8"))
        elif type(pin0) == bytes:
            pin0 = list(pin0)

        if type(ublk0) == str:
            ublk0 = list(ublk0.encode("utf-8"))
        elif type(ublk0) == bytes:
            ublk0 = list(ublk0)

        if type(pin1) == str:
            pin1 = list(pin1.encode("utf-8"))
        elif type(pin1) == bytes:
            pin1 = list(pin1)

        if type(ublk1) == str:
            ublk1 = list(ublk1.encode("utf-8"))
        elif type(ublk1) == bytes:
            ublk1 = list(ublk1)

        # to do: check pin sizes <= 16
        pin=[0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30] # default pin
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SETUP
        p1=0
        p2=0
        apdu=[cla, ins, p1, p2]

        # data=[pin_length(1) | pin |
        #       pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 |
        #       pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 |
        #       memsize(2) | memsize2(2) | ACL(3) |
        #       option_flags(2) | hmacsha160_key(20) | amount_limit(8)]
        if option_flags==0:
            optionsize= 0
        elif option_flags&0x8000==0x8000:
            optionsize= 30
        else:
            optionsize= 2
        lc= 16+len(pin)+len(pin0)+len(pin1)+len(ublk0)+len(ublk1)+optionsize

        apdu+=[lc]
        apdu+=[len(pin)]+pin
        apdu+=[pin_tries0,  ublk_tries0, len(pin0)] + pin0 + [len(ublk0)] + ublk0
        apdu+=[pin_tries1,  ublk_tries1, len(pin1)] + pin1 + [len(ublk1)] + ublk1
        apdu+=[memsize>>8, memsize&0x00ff, memsize2>>8, memsize2&0x00ff]
        apdu+=[create_object_ACL, create_key_ACL, create_pin_ACL]
        if option_flags!=0:
            apdu+=[option_flags>>8, option_flags&0x00ff]
            apdu+= hmacsha160_key
            for i in reversed(range(8)):
                apdu+=[(amount_limit>>(8*i))&0xff]

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2== 0x00):
            self.set_pin(0, pin0) #cache PIN value
            self.setup_done = True
            
            if self.card_type=='Satodime': # cache values 
               self.satodime_set_unlock_counter(response[0:SIZE_UNLOCK_COUNTER])
               self.satodime_set_unlock_secret(response[SIZE_UNLOCK_COUNTER:(SIZE_UNLOCK_COUNTER+SIZE_UNLOCK_SECRET)])
               self.is_owner= True
                    
        return (response, sw1, sw2)

    def card_reset_factory_signal(self):
        # transmit apdu
        apdu = [0xB0, 0xFF, 0x00, 0x00, 0x00]
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            logger.info("APDU reset transmitted successfully")
        else:
            logger.info(f"APDU reset transmitted with result code {hex(256*sw1+sw2)}")
        return response, sw1, sw2

    def card_reset_factory_v3(self):
        """Initiate the Factory Reset Process (version 3)
        Based on sending one specific APDU once to the card.
        Supported by Satochip with version >=0.16-0.0.
        """
        logger.debug("In card_reset_factory_v3")
        apdu = [0xB0, 0xFD, 0xAA, 0x55, 0x00]  # Factory Reset v3 APDU
        (response, sw1, sw2) = self.card_transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            logger.debug("CARD HAS BEEN RESET TO FACTORY!")
        elif sw1 == 0x9c and sw2 == 0x04:
            raise CardSetupNotDoneError()
        elif sw1 == 0x6D and sw2 == 0x00:
            raise UnsupportedFeatureError()
        else:
            raise UnexpectedSW12Error(f"Unexpected error (error code {hex(256*sw1+sw2)})", sw1, sw2)

        return response, sw1, sw2

    ###########################################
    #      Satochip private key commands      #
    ###########################################

    def satochip_import_privkey(self, keyslot_nbr, privkey: bytes):
        """This function imports a private ECkey into the card.

        Currently, only secp256k1 key are supported.
        If 2FA is enabled, a hmac code must be provided (Not implemented yet!)

        Return void if successful, otherwise throw an error
        """
        logger.debug("In satochip_import_privkey")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_IMPORT_KEY
        p1 = keyslot_nbr
        p2 = 0x00

        # data: [key_encoding(1) | key_type(1) | key_size(2) | RFU(6) | key_blob | (option)HMAC - 2FA(20b)]
        key_encoding = JCconstants.BLOB_ENC_PLAIN
        key_type = 	12 # KeyBuilder.TYPE_EC_FP_PRIVATE
        key_size = [0x01, 0x00] # 256bits
        rfu = 6 * [0x00]
        key_blob = list(privkey)
        if len(key_blob) == 32:
            key_blob = [0x00, 0x20] + key_blob
        else:
            raise ValueError(f"Wrong private key size during import private_key size: {len(key_blob)} instead of 32")
        hmac= [] # todo, currently 2FA is not supported for this operation
        data = [key_encoding, key_type] + key_size + rfu + key_blob + hmac

        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)

        if sw1 != 0x90 or sw2 != 0x00:
            logger.error(f"Error during privkey import: (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Error during privkey import: (error code {hex(256*sw1+sw2)})", sw1, sw2)

        return

    def satochip_reset_privkey(self, keyslot_nbr):
        """This function reset a private ECkey  previously imported into the card.

        If 2FA is enabled, a hmac code must be provided (Not implemented yet!)

        Return void if successful, otherwise throw an error
        """
        logger.debug("In satochip_reset_privkey")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_RESET_KEY
        p1 = keyslot_nbr
        p2 = 0x00

        # data: [(option)HMAC-2FA(20b)]
        hmac = []  # todo, currently 2FA is not supported for this operation
        data = hmac

        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.error(f"Error during privkey import: (error code {hex(256 * sw1 + sw2)})")
            raise UnexpectedSW12Error(f"Error during privkey import: (error code {hex(256 * sw1 + sw2)})", sw1, sw2)

        return

    def satochip_get_pubkey_from_keyslot(self, keyslot_nbr):
        """return the public key associated with a particular private key stored
        at a given keyslot in the applet.
        The exact key blob contents depend on the key algorithm and type.

        return(SECP256K1):
         the public key object for the given slot
         raise an error if the slot is not initialized
        """
        logger.debug("In satochip_get_pubkey_from_keyslot")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_GET_PUBLIC_FROM_PRIVATE
        p1 = keyslot_nbr
        p2 = 0x00
        apdu = [cla, ins, p1, p2]

        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.error(f"Error during privkey import: (error code {hex(256 * sw1 + sw2)})")
            raise UnexpectedSW12Error(f"Error during privkey import: (error code {hex(256 * sw1 + sw2)})", sw1, sw2)

        # response [coordx_size(2b) | pubkey_coordx | sig_size(2b) | sig]
        pubkey = self.parser.parse_get_pubkey_from_keyslot(response)
        return pubkey

    ###########################################
    #              BIP32 commands             #
    ###########################################

    def card_bip32_import_seed(self, seed):
        ''' Import a seed into the device
        
        Parameters: 
        seed (str | bytes | list): the seed as a hex_string or bytes or list of int

        Returns: 
        authentikey: ECPubkey object that identifies the  device
        '''
        if type(seed) is str:
            seed= list(bytes.fromhex(seed))
        elif type(seed) is bytes:
            seed= list(seed)
        
        logger.debug("In card_bip32_import_seed")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_IMPORT_SEED
        p1= len(seed)
        p2= 0x00
        lc= len(seed)
        apdu=[cla, ins, p1, p2, lc]+seed
        
        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # compute authentikey pubkey and send to chip for future use
        authentikey= None
        if (sw1==0x90) and (sw2==0x00):
            authentikey= self.card_bip32_set_authentikey_pubkey(response)
            authentikey_hex= authentikey.get_public_key_bytes(True).hex()
            logger.debug('[card_bip32_import_seed] authentikey_card= ' + authentikey_hex)
            self.is_seeded= True
            # compute authentikey locally from seed (legacy before Satochip v0.12)
            # TODO: remove check if authentikey is not derived from seed
            #pub_hex= self.get_authentikey_from_masterseed(seed)
            # if (pub_hex != authentikey_hex):
                # raise RuntimeError('Authentikey mismatch: local value differs from card value!')
                
        elif (sw1==0x9C and sw2==0x17):
            logger.error(f"Error during secret import: card is already seeded (0x9C17)")
            raise CardError('Secure import failed: card is already seeded (0x9C17)!')
        elif (sw1==0x9C and sw2==0x0F):
            logger.error(f"Error during secret import: invalid parameter (0x9C0F)")
            raise CardError(f"Error during secret import: invalid parameter (0x9C0F)")
        else:
            # do not return a None authentikey silently: the failure would only
            # surface later, on the first command that needs the seed
            logger.error(f"Unexpected error during seed import (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f'Unexpected error during seed import (error code {hex(256*sw1+sw2)})', sw1, sw2)
        
        return authentikey
    
    def card_import_encrypted_secret(self, secret_dic):
        '''Import an encrypted secret (BIP32 masterseed or 2FA secret) exported from a SeedKeeper.
        
        The secret is encrypted using a shared key generated using ECDH with the 2 devices authentikeys.
        Before import can be done, the two device should be paired by importing the 
        Satochip-authentikey in the SeedKeeper with seedkeeper_import_secret(), 
        and the SeedKeeper-authentikey in the Satochip with card_import_trusted_pubkey().
         
        Parameters: 
        secret_dic: a dictionnary that defines the secret, as returned by seedkeeper_export_secret()

        Returns: 
        authentikey: ECPubkey object that identifies the  device
        '''
        logger.debug("In card_import_encrypted_secret")
        
        cla= JCconstants.CardEdge_CLA
        ins= 0xAC
        p1= 0x00
        p2= 0x00        
        header= list(bytes.fromhex(secret_dic['header']))[2:(2+12)]  #header= list(bytes.fromhex(secret_dic['header'][4:])) # first 2 bytes are sid
        iv= list(bytes.fromhex(secret_dic['iv']))
        secret_list= list(bytes.fromhex(secret_dic['secret_encrypted']))
        hmac= list(bytes.fromhex(secret_dic['hmac']))
        data= header + iv + [(len(secret_list)>>8), (len(secret_list)%256)] + secret_list + [len(hmac)] + hmac
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90 and sw2==0x00):
            pass 
        elif (sw1==0x6d and sw2==0x00):
            logger.error(f"Error during secret import: operation not supported by the card (0x6D00)")
            raise CardError(f"Error during secret import: operation not supported by the card (0x6D00)")
        elif (sw1==0x9C and sw2==0x17):
            logger.error(f"Error during secret import: card is already seeded (0x9C17)")
            raise CardError('Secure import failed: card is already seeded (0x9C17)!')
        elif (sw1==0x9C and sw2==0x18):
            logger.error(f"Error during secret import: card already requires 2FA (0x9C18)")
            raise CardError('Secure import failed: card already requires 2FA (0x9C18)!')
        elif (sw1==0x9C and sw2==0x0F):
            logger.error(f"Error during secret import: invalid parameter (0x9C0F)")
            raise CardError(f"Error during secret import: invalid parameter (0x9C0F)")
        elif (sw1==0x9C and sw2==0x33):
            logger.error(f"Error during secret import: wrong MAC (0x9C33)")
            raise CardError('Secure import failed: wrong MAC (0x9C33)!')
        elif (sw1==0x9C and sw2==0x34):
            logger.error(f"Error during secret import: wrong fingerprint (0x9C34)")
            raise CardError('Secure import failed: wrong fingerprint (0x9C34)!')
        elif (sw1==0x9C and sw2==0x35):
            logger.error(f"Error during secret import: no TrustedPubkey (0x9C35)")
            raise CardError('Secure import failed: TrustedPubkey (0x9C35)!')
        else:
            logger.error(f"Error during secret import (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error during secure secret import (error code {hex(256*sw1+sw2)})", sw1, sw2)
        
        secret_type= header[0]
        if  secret_type==0x10:
            authentikey= self.parser.parse_bip32_get_authentikey(response)
            authentikey_hex= authentikey.get_public_key_bytes(True).hex()
            logger.debug('authentikey_card= ' + authentikey_hex)
            return authentikey
        elif  secret_type==0xB0:
            return None
            
    def card_import_trusted_pubkey(self, pubkey_list):
        ''' Import a trusted ec pubkey into the device. This pubkey will be used for the secure import of a secret
        
        Parameters: 
        pubkey_list: the pubkey in uncompressed form (65 bytes) as a hex_string or bytes or list of int

        Returns: 
        pubkey_hex: the pubkey as a hex string (65*2 hex chars)
        '''
        logger.debug("In card_import_trusted_pubkey")
        if type(pubkey_list) is str:
            pubkey_list= list(bytes.fromhex(pubkey_list))
        elif type(pubkey_list) is bytes:
            pubkey_list= list(pubkey_list)
        
        cla= JCconstants.CardEdge_CLA
        ins= 0xAA
        p1= 0x00
        p2= 0x00    
        pubkey_size= len(pubkey_list)
        if (pubkey_size !=65):
            raise RuntimeError(f'Error during trusted pubkey import: wrong pubkey size, expected 65 but received {pubkey_size}')
        data= [pubkey_size>>8, pubkey_size%256] + pubkey_list
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x6D and sw2==0x00): 
            logger.error(f"Error during secret import: operation not supported by the card (0x6D00)")
            raise CardError(f"Error during secret import: operation not supported by the card (0x6D00)")
        elif (sw1==0x9C and sw2==0x17):
            logger.error(f"Error during secret import: card is already seeded (0x9C17)")
            raise CardError('Secure import failed: card is already seeded (0x9C17)!')
        elif (sw1==0x9C and sw2==0x0F):
            logger.error(f"Error during secret import: invalid parameter (0x9C0F)")
            raise CardError(f"Error during secret import: invalid parameter (0x9C0F)")
        elif (sw1!=0x90 or sw2!=0x00):
            # never hand an error payload to the parser
            logger.error(f"Error during trusted pubkey import: {hex(256*sw1+sw2)}")
            raise UnexpectedSW12Error(
                f"Unexpected error during trusted pubkey import (error code {hex(256*sw1+sw2)})", sw1, sw2)

        if self.parser.authentikey is None:
            self.parser.authentikey = self.card_export_authentikey()

        pubkey_hex=self.parser.get_trusted_pubkey(response)
        return pubkey_hex
        
    def card_export_trusted_pubkey(self):
        ''' Export the trusted ec pubkey from the device. This pubkey is used for the secure import of a secret
        
        Returns: 
        pubkey_hex: the pubkey as a hex string (65*2 hex chars)
        '''
        logger.debug("In card_export_trusted_pubkey")
        cla= JCconstants.CardEdge_CLA
        ins= 0xAB
        p1= 0x00
        p2= 0x00    
        apdu=[cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x9C and sw2==0x35):
            return 65*'00'
        if (sw1==0x6D and sw2==0x00): # instruction not supported
            return 65*'FF'
        if (sw1!=0x90 or sw2!=0x00):
            # never hand an error payload to the parser
            logger.error(f"Error during trusted pubkey export: {hex(256*sw1+sw2)}")
            raise UnexpectedSW12Error(
                f"Unexpected error during trusted pubkey export (error code {hex(256*sw1+sw2)})", sw1, sw2)

        if self.parser.authentikey is None:
            self.parser.authentikey = self.card_export_authentikey()

        pubkey_hex=self.parser.get_trusted_pubkey(response)
        return pubkey_hex
    
    def card_export_authentikey(self):        
        ''' Export the device authentikey.
        
        The authentikey identifies uniquely the device and is also used for setting a
        secure channel when doing a secure import with card_import_encrypted_secret().
        
        Returns: 
        authentikey: ECPubkey object that identifies the  device
        '''
        logger.debug("In card_export_authentikey")
        cla= JCconstants.CardEdge_CLA
        ins= 0xAD
        p1= 0x00
        p2= 0x00
        apdu=[cla, ins, p1, p2]

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            # compute corresponding pubkey and send to chip for future use
            authentikey = self.parser.parse_bip32_get_authentikey(response)
            return authentikey
        elif (sw1==0x9c and sw2==0x04):
            logger.info("card_bip32_get_authentikey(): Satochip is not initialized => Raising error!")
            raise UninitializedSeedError('Satochip is not initialized! You should create a new wallet!\n\n'+MSG_WARNING)
        else:
            logger.warning(f"Unexpected error during authentikey export (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error during authentikey export (error code {hex(256*sw1+sw2)})", sw1, sw2)

    
    def card_reset_seed(self, pin, hmac=[]):
        ''' Reset the seed
        
        Parameters: 
        pin  (hex-string | bytes | list): the pin required to unlock the device
        hmac (hex-string | bytes | list): the 20-byte code required if 2FA is enabled
        
        Returns: 
        (response, sw1, sw2): (list, int, int)
        '''
        logger.debug("In card_reset_seed")
        if type(pin) is str:
            pin= list(pin.encode('utf-8'))
        elif type(pin) is bytes:
            pin= list(pin)
        
        if type(hmac) is str:
            hmac= list(bytes.fromhex(hmac))
        elif type(hmac) is bytes:
            hmac= list(hmac)
        
        cla= JCconstants.CardEdge_CLA
        ins= 0x77
        p1= len(pin)
        p2= 0x00
        lc= len(pin)+len(hmac)
        apdu=[cla, ins, p1, p2, lc]+pin+hmac

        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            self.is_seeded= False
        return (response, sw1, sw2)

    def card_bip32_get_authentikey(self):
        ''' Return the authentikey      
        
        Compared to card_export_authentikey(), this method raise UninitializedSeedError if no seed is configured in the device
        
        Returns: 
        authentikey: an ECPubkey
        '''
        logger.debug("In card_bip32_get_authentikey")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_GET_AUTHENTIKEY
        p1= 0x00
        p2= 0x00
        apdu=[cla, ins, p1, p2]

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x9c and sw2==0x14:
            logger.info("card_bip32_get_authentikey(): Seed is not initialized => Raising error!")
            raise UninitializedSeedError("Satochip seed is not initialized!\n\n "+MSG_WARNING)
        if sw1==0x9c and sw2==0x04:
            logger.info("card_bip32_get_authentikey(): Satochip is not initialized => Raising error!")
            raise UninitializedSeedError('Satochip is not initialized! You should create a new wallet!\n\n'+MSG_WARNING)
        # compute corresponding pubkey and send to chip for future use
        authentikey= None
        if (sw1==0x90) and (sw2==0x00):
            authentikey = self.card_bip32_set_authentikey_pubkey(response)
            self.is_seeded=True
        return authentikey
        
    def card_bip32_set_authentikey_pubkey(self, response):
        ''' Allows to compute coordy of authentikey externally to optimize computation time-out
        coordy value is verified by the chip before being accepted '''
        logger.debug("In card_bip32_set_authentikey_pubkey")
        cla= JCconstants.CardEdge_CLA
        ins= 0x75
        p1= 0x00
        p2= 0x00

        authentikey= self.parser.parse_bip32_get_authentikey(response)
        if authentikey:
            coordy= authentikey.get_public_key_bytes(compressed=False)
            coordy= list(coordy[33:])
            data= response + [(len(coordy)>>8)&0xFF, len(coordy)&0xFF] + coordy
            lc= len(data)
            apdu=[cla, ins, p1, p2, lc]+data
            (response, sw1, sw2) = self.card_transmit(apdu)
            if (sw1!=0x90 or sw2!=0x00):
                # This command is only an optimization for older applet (version <= v0.10-0.3):
                # it caches coordy on the chip so it does not have to recompute it later.
                # The authentikey returned below was parsed (signature checked) from the caller's
                # response, not from this command, so a rejection costs
                # performance rather than correctness -- and new applets may
                # not implement ins 0x75 at all.
                logger.debug(
                    f"Could not cache the authentikey coordy on the card "
                    f"(error code {hex(256*sw1+sw2)}); continuing without it")
        return authentikey
    
    def card_bip32_get_extendedkey(self, path, sid=None, option_flags=0x40):
        ''' Get the BIP32 extended key for given path
        
        Parameters: 
        path (str | bytes): the path; if given as a string, it will be converted to bytes (4 bytes for each path index)
        sid (int): for SeedKeeper, this is the secret_id of the masterseed that we want to use for derivation

        Returns: 
        pubkey: ECPubkey object
        chaincode: bytearray
        '''
        if (type(path)==str):
            (depth, path)= self.parser.bip32path2bytes(path)
    
        logger.debug("In card_bip32_get_extendedkey")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_GET_EXTENDED_KEY
        p1= len(path)//4
        p2= option_flags #option flags: 0x80:erase cache memory - 0x40: optimization for non-hardened child derivation
        lc= len(path)

        data = list(path)
        if sid is not None:
            data = data + [(sid>>8)%256, sid%256]
        lc= len(data)

        apdu=[cla, ins, p1, p2, lc] + data

        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        # send apdu
        # single exchange: every branch below returns or raises, so there is
        # nothing to loop over here
        (response, sw1, sw2) = self.card_transmit(apdu)

        # if there is no more memory available, erase cache...
        #if self.get_sw12(sw1,sw2)==JCconstants.SW_NO_MEMORY_LEFT:
        if (sw1==0x9C) and (sw2==0x01):
            logger.info("[card_bip32_get_extendedkey] Reset memory...")#debugSatochip
            # Set the erase flag rather than toggling it, and restore p2
            # afterwards: the caller may legitimately have set bit 7 itself, and
            # that choice must survive this retry.
            saved_p2= apdu[3]
            apdu[3]= saved_p2 | 0x80
            response, sw1, sw2 = self.card_transmit(apdu)
            apdu[3]= saved_p2
        # other (unexpected) error
        if (sw1!=0x90) or (sw2!=0x00):
            raise UnexpectedSW12Error(f'Unexpected error  (error code {hex(256*sw1+sw2)})', sw1, sw2)
        if (sw1==0x90) and (sw2==0x00):
            if (option_flags & 0x04) == 0x04: # BIP85
                entropy_bytes= self.parser.parse_bip32_get_extendedkey_bip85(response)
                return entropy_bytes
            elif (option_flags & 0x02) == 0x00: # BIP32 pubkey
                if ( (response[32]&0x80)== 0x80):
                    logger.info("[card_bip32_get_extendedkey] Child Derivation optimization...")#debugSatochip
                    (pubkey, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                    coordy= pubkey.get_public_key_bytes(compressed=False)
                    coordy= list(coordy[33:])
                    authcoordy= self.parser.authentikey.get_public_key_bytes(compressed=False)
                    authcoordy= list(authcoordy[33:])
                    data= response+[(len(coordy)>>8)&0xFF, len(coordy)&0xFF]+coordy
                    apdu_opt= [cla, 0x74, 0x00, 0x00, len(data)]+data
                    # This command is only an optimization for older applet (version <= v0.10-0.3):
                    # it caches coordy on the chip so it does not have to recompute it later.
                    # New applets do not implement ins 0x74 at all.
                    response_opt, sw1_opt, sw2_opt = self.card_transmit(apdu_opt)

                (pubkey, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                if sid is None:
                    # the card now holds this key for signing with keynbr 0xFF
                    self._last_bip32_derivation= Bip32Derivation(bytes(path), sid, option_flags,
                        pubkey.get_public_key_bytes(compressed=True), bytes(chaincode))
                return (pubkey, chaincode)
            else: # BIP32 privkey
                (privkey, chaincode)= self.parser.parse_bip32_get_extended_privkey(response)
                return (privkey, chaincode)

    def card_bip32_get_xpub(self, path, xtype, is_mainnet, sid=None):
        ''' Get the BIP32 xpub for given path.
        
        Parameters: 
        path (str | bytes): the path; if given as a string, it will be converted to bytes (4 bytes for each path index)
        xtype (str): the type of transaction such as  'standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh'
        is_mainnet (bool): is mainnet or testnet 
        sid (int): for SeedKeeper, this is the secret_id of the masterseed that we want to use for derivation
        
        Returns: 
        xpub (str): the corresponding xpub value
        '''
        assert xtype in SUPPORTED_XTYPES
        
        # path is of the form 44'/0'/1'
        logger.debug(f"card_bip32_get_xpub(): path={str(path)}")#debugSatochip
        if (type(path)==str):
            (depth, bytepath)= self.parser.bip32path2bytes(path)
        else:
            # bip32path2bytes() packs 4 bytes per level, so for an already
            # serialized path the depth is simply its length over 4. bytes()
            # also accepts a bytearray or a list of ints.
            bytepath= bytes(path)
            depth= len(bytepath)//4

        (childkey, childchaincode)= self.card_bip32_get_extendedkey(bytepath, sid)
        if depth == 0: #masterkey
            fingerprint= bytes([0,0,0,0])
            child_number= bytes([0,0,0,0])
        else: #get parent info
            (parentkey, parentchaincode)= self.card_bip32_get_extendedkey(bytepath[0:-4], sid)
            fingerprint= hash_160(parentkey.get_public_key_bytes(compressed=True))[0:4]
            child_number= bytepath[-4:]
        
        xpub_header= XPUB_HEADERS_MAINNET[xtype] if is_mainnet else XPUB_HEADERS_TESTNET[xtype]
        xpub = bytes.fromhex(xpub_header) + bytes([depth]) + fingerprint + child_number + childchaincode + childkey.get_public_key_bytes(compressed=True)
        assert(len(xpub)==78)
        xpub= EncodeBase58Check(xpub)
        logger.debug(f"card_bip32_get_xpub(): xpub={str(xpub)}")#debugSatochip
        return xpub

    def card_bip32_get_xprv(self, path, xtype, is_mainnet, sid=None):
        ''' Get the BIP32 xpriv for given path. 
        Only suitable for SeedKeeper, Satochip does NOT allow export of private keys by design.
        
        Parameters: 
        path (str | bytes): the path; if given as a string, it will be converted to bytes (4 bytes for each path index)
        xtype (str): the type of transaction such as  'standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh'
        is_mainnet (bool): is mainnet or testnet 
        sid (int): for SeedKeeper, this is the secret_id of the masterseed that we want to use for derivation
        
        Returns: 
        xpriv (str): the corresponding xpriv value
        '''
        logger.debug(f"card_bip32_get_xpriv(): path={str(path)}")#debugSatochip
        if (type(path)==str):
            (depth, bytepath)= self.parser.bip32path2bytes(path)
        else:
            # bip32path2bytes() packs 4 bytes per level, so for an already
            # serialized path the depth is simply its length over 4. bytes()
            # also accepts a bytearray or a list of ints.
            bytepath= bytes(path)
            depth= len(bytepath)//4

        option_flags= 0x02 # request privkey
        (childkey, childchaincode)= self.card_bip32_get_extendedkey(bytepath, sid, option_flags)
        if depth == 0: #masterkey
            fingerprint= bytes([0,0,0,0])
            child_number= bytes([0,0,0,0])
        else: #get parent info
            (parentkey, parentchaincode)= self.card_bip32_get_extendedkey(bytepath[0:-4], sid, option_flags)
            fingerprint= hash_160(parentkey.get_public_key_bytes(compressed=True))[0:4]
            child_number= bytepath[-4:]
        
        xprv_header= XPRV_HEADERS_MAINNET[xtype] if is_mainnet else XPRV_HEADERS_TESTNET[xtype]
        xprv = bytes.fromhex(xprv_header) + bytes([depth]) + fingerprint + child_number + childchaincode + bytes([0x00]) + childkey.get_private_key_bytes()
        assert(len(xprv)==78)
        xprv= EncodeBase58Check(xprv)
        return xprv

    def card_bip32_get_liquid_master_blinding_key(self):
        logger.debug("card_bip32_get_liquid_master_blinding_key");

        cla = JCconstants.CardEdge_CLA
        ins = 0x7D
        p1 = 0x00
        p2 = 0x00
        lc = 0x00
        apdu = [cla, ins, p1, p2, lc]
        (response, sw1, sw2) = self.card_transmit(apdu)

        if (sw1 != 0x90 or sw2 != 0x00):
            raise UnexpectedSW12Error(f'Unexpected error  (error code {hex(256 * sw1 + sw2)})', sw1, sw2)

        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        offset=0
        keySize= 256 * (response[offset] & 0xff) + response[offset+1]
        offset+=2
        blindingKey= response[2:2+keySize]
        offset += keySize

        # The applet signs everything written before the signature field, i.e.
        # [keySize(2b) | blindingKey], with the authentikey -- see
        # getBIP32LiquidMasterBlindingKey() -> appendAuthentikeySignature() in
        # SatochipApplet. Without this check a hostile or swapped card chooses
        # the master blinding key for every confidential Liquid address the
        # wallet derives from it.
        signed_data= response[0:offset]
        sigSize= 256 * response[offset] + response[offset+1]
        offset+=2
        sig= response[offset:(offset+sigSize)]
        offset += sigSize
        if sigSize==0:
            raise ValueError("Signature missing")
        self.parser.verify_signature(signed_data, sig, self.parser.authentikey)

        return blindingKey

    ###########################################
    #            Signing commands             #
    ###########################################
    
    def card_sign_message(self, keynbr, pubkey, message, hmac=b'', altcoin=None):
        ''' Sign the message with the device
        
        Message is prepended with a specific header as described here:
        https://bitcoin.stackexchange.com/questions/77324/how-are-bitcoin-signed-messages-generated
        
        The dedicated SignMessage command (ins 0x6E) is deprecated since applet
        v0.16-0.0 (it returns 0x9C26): the message hash is now computed
        client-side and signed with the SignTransactionHash command (ins 0x7A),
        which is supported by all applets since v0.10.
        
        Parameters: 
        keynbr (int): the key to use (0xFF for bip32 key)
        pubkey (ECPubkey): the pubkey used for signing; this is used for key recovery
        message (str | bytes): the message to sign
        hmac: the 20-byte hmac code required if 2FA is enabled.
            Note: with SignTransactionHash, the 2FA challenge is the hmac-sha1 of
            [sha256d(msg_magic(message, altcoin)) | 32-byte 0xCC-padding]
            (the deprecated SignMessage command used a single sha256 hash and a
            0xBB-padding instead).
        altcoin (str | bytes): for altcoin signing
        
        Returns: 
        (response, sw1, sw2, compsig): (list, int, int, bytes)
        compsig is the signature in  compact 65-byte format 
        (https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long)
        '''
        logger.debug("In card_sign_message")
        if (type(message)==str):
            message = message.encode('utf8')
        if (type(altcoin)==str):
            altcoin = altcoin.encode('utf8')
            
        # compute the message hash client-side, as done inside the card previously
        hash = sha256d(msg_magic(message, altcoin))
        # sign the hash with the SignTransactionHash command (ins 0x7A)
        chalresponse= list(hmac) if hmac else None
        (response, sw1, sw2) = self.card_sign_transaction_hash(keynbr, list(hash), chalresponse)
        
        # parse signature from response
        if (sw1!=0x90 or sw2!=0x00):
            logger.warning(f"Unexpected error in card_sign_message() (error code {hex(256*sw1+sw2)})") #debugSatochip
            compsig=b''
        else:
            compsig=self.parser.parse_message_signature(response, hash, pubkey)
                
        return (response, sw1, sw2, compsig)

    def card_parse_transaction(self, transaction: bytes, is_segwit=False):
        ''' DEPRECATED. Compute the double-sha256 of the bytes given as input.

        .. deprecated:: 0.18.5
            This function does **not** parse the transaction. It only returns
            sha256(sha256(transaction)), and is kept solely for backward
            compatibility. Use sha256d() from pysatochip.util, or pass the hash
            straight to card_sign_transaction_hash().

        The dedicated ParseTransaction command (ins 0x71) was removed in applet
        v0.16-0.0 (it returns 0x9C26), so no APDU is exchanged with the card.
        Parsing was dropped as well: the parser only ever accumulated the bytes
        it walked over, so its result was always the plain double-sha256 of its
        input, for both the legacy and the segwit code path. `is_segwit` is
        therefore ignored; it is kept only so existing call sites still work.

        The caller is solely responsible for building the correct preimage, and
        for checking it: nothing here validates that the input is a well-formed
        transaction. For legacy transactions the preimage is the prepared
        transaction (the scriptCode of the input to sign in place of its
        scriptSig, plus the locktime and the 4-byte sighash type); for segwit it
        is the BIP143 preimage. Since the card no longer parses the transaction,
        it cannot attest the hash with its authentikey either.

        Parameters:
        transaction (bytes): the bytes to hash (a prepared transaction or a
            BIP143 preimage; not validated)
        is_segwit (bool): ignored, kept for backward compatibility

        Returns:
        (response, sw1, sw2, tx_hash, needs_2fa)
        response (list): empty, no APDU is sent anymore
        sw1, sw2 (int): always (0x90, 0x00), no APDU is sent anymore
        tx_hash (list): sha256(sha256(transaction))
        needs_2FA (bool): whether 2FA is enabled (and thus required for signing)
        '''
        logger.debug("In card_parse_transaction (deprecated)")
        warnings.warn(
            "card_parse_transaction() is deprecated and does not parse the "
            "transaction: it only returns the double-sha256 of its input. Use "
            "pysatochip.util.sha256d() instead.",
            DeprecationWarning, stacklevel=2)

        tx_hash= list(sha256d(transaction))
        needs_2fa= bool(self.needs_2FA)

        return ([], 0x90, 0x00, tx_hash, needs_2fa)

    def card_sign_transaction(self, keynbr, txhash, chalresponse):
        ''' Sign the transaction hash in the device
        
        Parameters: 
        keynbr (int): the key to use (0xFF for bip32 key)
        txhash (list): the transaction hash, as computed by card_parse_transaction()
        chalresponse (list): the hmac code if 2FA is enabled
        
        Returns: 
        (response, sw1, sw2)
        response (list): the signature in DER format
        '''
        logger.debug("In card_sign_transaction")
        # The dedicated SignTransaction command (ins 0x6F) is deprecated since
        # applet v0.16-0.0 (it returns 0x9C26); SignTransactionHash (ins 0x7A)
        # signs the same hash directly, without comparing it to a card-cached
        # hash. Note that the 2FA challenge must follow the SignTransactionHash
        # rule: hmac-sha1 of [txhash | 32-byte 0xCC-padding] (the deprecated
        # SignTransaction command used a 0x00-padding instead).
        return self.card_sign_transaction_hash(keynbr, txhash, chalresponse)
    
    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse):
        ''' Sign the transaction hash in the device
        
        Parameters: 
        keynbr (int): the key to use (0xFF for bip32 key)
        txhash (list): the transaction hash 
        chalresponse (list): the hmac code if 2FA is enabled
        
        Returns: 
        (response, sw1, sw2)
        response (list): the signature in DER format
        '''
        logger.debug("In card_sign_transaction_hash")
        #if (type(chalresponse)==str):
        #    chalresponse = list(bytes.fromhex(chalresponse))
        cla= JCconstants.CardEdge_CLA
        ins= 0x7A
        p1= keynbr
        p2= 0x00

        if len(txhash)!=32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")
        elif chalresponse is None:
            data= txhash
        else:
            if len(chalresponse)!=20:
                raise ValueError("Wrong Challenge response length:"+ str(len(chalresponse)) + "(should be 20)")
            data= txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        # the card may have lost the BIP32 key: derive it again, then resend
        if keynbr == 0xFF and (256*sw1+sw2) == JCconstants.SW_INCORRECT_INITIALIZATION:
            if self._restore_derived_keys():
                response, sw1, sw2 = self.card_transmit(apdu)
        return response, sw1, sw2

    def card_sign_schnorr_hash(self, keynbr, txhash, chalresponse):
        ''' Sign the transaction hash in the device using schnorr signature

        Parameters:
        keynbr (int): the key to use (0xFF for bip32 key)
        txhash (list): the transaction hash
        chalresponse (list): the hmac code if 2FA is enabled

        Returns:
        (response, sw1, sw2)
        response (list): the signature as 64bytes (see bip341)
        '''

        logger.debug("In card_sign_schnorr_hash")

        cla = JCconstants.CardEdge_CLA
        ins = 0x7B
        p1 = keynbr
        p2 = 0x00

        if len(txhash) != 32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")
        elif chalresponse is None:
            data = txhash
        else:
            if len(chalresponse) != 20:
                raise ValueError("Wrong Challenge response length:" + str(len(chalresponse)) + "(should be 20)")
            data = txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag

        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        # the card may have lost the tweaked key: tweak it again, then resend
        if (256*sw1+sw2) == JCconstants.SW_INCORRECT_INITIALIZATION:
            if self._restore_derived_keys(with_tweak=True):
                response, sw1, sw2 = self.card_transmit(apdu)
        return response, sw1, sw2

    def card_taproot_tweak_privkey(self, keynbr, tweak=None, bypass_flag: bool = False):
        '''This function tweaks the currently available private stored in the Satochip.
        Tweaking is based on the 'taproot_tweak_seckey(seckey0, h)' algorithm specification defined here:
        https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs

        Parameters:
        keynbr (int): the key to use (0xFF for bip32 key)
        tweak (list | bytes | None): the taproot merkle root h, as 32 bytes.
            Use None (or an empty value) when the output commits to no script
            tree, i.e. key-path-only spending as in BIP86: the tagged hash is
            then computed over x(P) alone.
            Note that h = None and h = 32 zero bytes are two DIFFERENT tweaks,
            since BIP341 hashes the concatenation x(P) || h. Only the former
            gives the standard BIP86 output key.
        bypass_flag (bool): if set to True, key tweaking is bypassed (Nostr)

        returns:
        (response, sw1, sw2)
        response (list): tweaked Pubkey in uncompressed form (65 bytes)
        '''
        logger.debug("in card_taproot_tweak_privkey")

        cla = JCconstants.CardEdge_CLA
        ins = 0x7C
        p1 = keynbr
        p2 = 0x00 if not bypass_flag else 0x01

        if tweak is None:
            tweak = [] # no script tree: only x(P) is hashed (BIP86)
        tweak = list(tweak)

        if len(tweak) not in (0, 32):
            raise ValueError(f"Wrong tweak length: {len(tweak)} (should be 32, or 0 for no script tree)")

        data = [len(tweak)] + tweak
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        # the card may have lost the BIP32 key: derive it again, then resend
        if keynbr == 0xFF and (256*sw1+sw2) == JCconstants.SW_INCORRECT_INITIALIZATION:
            if self._restore_derived_keys():
                response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            # response: [pubkey_size(2b) | pubkey(65b) | sig_size(2b) | authentikey_sig]
            derivation = self._last_bip32_derivation if keynbr == 0xFF else None
            self._last_taproot_tweak = TaprootTweak(keynbr, tweak, bypass_flag, derivation, bytes(response[0:67]))
        return response, sw1, sw2

    def _restore_derived_keys(self, with_tweak=False):
        ''' Derives again the BIP32 key, and tweaks again the taproot key if with_tweak is set,
        after the card has lost them.

        Since applet v0.16-0.0, the BIP32 extended key (keynbr 0xFF) and the taproot tweaked
        key are transient: they are cleared when the applet is deselected or the card is reset,
        e.g. when another application uses the reader. card_transmit() then silently opens a
        new secure channel and verifies the cached PIN, but a command using these keys fails
        with SW_INCORRECT_INITIALIZATION (0x9C13). Older applets kept the keys in flash, so the
        command used to succeed with the key derived in the previous session.

        The last derivation (and tweak) made through this CardConnector is replayed. It is only
        accepted if the card returns the same public key as the first time, so that a key is
        never restored on another card or from another seed. Both keys are cleared together,
        so both are restored: the BIP32 key derived last stays the one used with keynbr 0xFF.

        Returns True if the card holds the same keys as before: the caller can then resend its
        command. Otherwise, the key must be derived again (card_bip32_get_extendedkey), and
        tweaked again for schnorr signatures, in the same card session.
        '''
        last_derivation = self._last_bip32_derivation
        last_tweak = self._last_taproot_tweak

        if (last_tweak if with_tweak else last_derivation) is None:
            restored = False # nothing was derived (or tweaked) through this CardConnector
        else:
            try:
                card_derivation = None # the BIP32 key held by the card
                restored = True
                if with_tweak:
                    restored = self._replay_taproot_tweak(last_tweak)
                    card_derivation = last_tweak.derivation # derived again for keynbr 0xFF
                if restored and last_derivation is not None and last_derivation != card_derivation:
                    restored = self._replay_bip32_derivation(last_derivation)
            finally:
                # the replay records its own derivation and tweak: keep those of the client
                self._last_bip32_derivation = last_derivation
                self._last_taproot_tweak = last_tweak

        if restored:
            logger.info("The card had lost the derived keys (0x9C13): restored")
        else:
            logger.warning("The card has no derived key (0x9C13): derive the key "
                           + ("and tweak it " if with_tweak else "")
                           + "in the same card session before signing")
        return restored

    def _replay_bip32_derivation(self, derivation):
        ''' Derives again a recorded Bip32Derivation, and checks that the card returns the same
        pubkey and chaincode. Returns True on success.
        '''
        try:
            (pubkey, chaincode) = self.card_bip32_get_extendedkey(
                derivation.path, derivation.sid, derivation.option_flags)
        except UnexpectedSW12Error as e:
            logger.warning(f"The BIP32 key could not be derived again: {e}")
            return False
        if pubkey.get_public_key_bytes(compressed=True) != derivation.pubkey or bytes(chaincode) != derivation.chaincode:
            logger.warning("The BIP32 key could not be derived again: the card returned another pubkey")
            return False
        return True

    def _replay_taproot_tweak(self, tweak):
        ''' Tweaks again a recorded TaprootTweak (deriving its BIP32 key again first, for
        keynbr 0xFF), and checks that the card returns the same tweaked pubkey.
        Returns True on success.
        '''
        if tweak.keynbr == 0xFF:
            if tweak.derivation is None: # the key was not derived through this CardConnector
                return False
            if not self._replay_bip32_derivation(tweak.derivation):
                return False
        (response, sw1, sw2) = self.card_taproot_tweak_privkey(tweak.keynbr, tweak.tweak, tweak.bypass_flag)
        if (sw1!=0x90) or (sw2!=0x00) or bytes(response[0:67]) != tweak.tweaked_pubkey:
            logger.warning("The taproot tweak could not be done again")
            return False
        return True

    def card_musig2_generate_nonce(self, keynbr: int, aggpk: Optional[bytes], msg: Optional[bytes], extra: Optional[bytes]):
        '''This function generate a MuSig2 nonce for the currently available private key stored in the Satochip.
        Generation is based on the BIP-0327 specification: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki.

        Parameters:
        keynbr (int): the key to use (0xFF for bip32 key)
        aggpk (list): the x-only aggregate public key
        msg (list): the message (should be 127-bytes or less)
        extra_bytes (list): auxiliary input (should be 127-bytes or less)

        returns: pubnonce, encrypted_sec_nonce
        '''
        logger.debug("in card_musig2_generate_nonce")

        cla = JCconstants.CardEdge_CLA
        ins = 0x7E
        p1 = keynbr

        # OP_INIT: recover pubnonce
        p2 = JCconstants.OP_INIT

        # data: [aggpk_size(1b) | aggpk | msg_size (1b) | msg | extra_size(1b) | extra_bytes]
        data = []
        if aggpk is None:
            data += [0x00]
        else:
            data += [len(aggpk)] + list(aggpk)
        if msg is None:
            data += [0xff]
        else:
            data += [len(msg)] + list(msg)
        if extra is None:
            data += [0x00]
        else:
            data += [len(extra)] + list(extra)
        #data = [len(aggpk)] + list(aggpk) + [len(msg)] + list(msg) + [len(extra)] + list(extra)
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        pubnonce = bytes(response)
        logger.debug(f"card_musig2_generate_nonce() OP_INIT: sw12={hex(256 * sw1 + sw2)}")

        # OP_FINALIZE: recover encrypted_secnonce
        p2 = JCconstants.OP_FINALIZE
        data = []
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        encrypted_secnonce = bytes(response)
        logger.debug(f"card_musig2_generate_nonce() OP_FINALIZE: sw12={hex(256 * sw1 + sw2)}")

        return pubnonce, encrypted_secnonce

    def card_musig2_sign_hash(self, keynbr: int, secnonce: bytes, b: bytes, ea: bytes, r_has_even_y: bool, ggacc_is_1: bool):
        '''This function generate a MuSig2 signature for the currently available private key stored in the Satochip.
        The signature is computed based on secnonce and intermediate values b, ea, R_evenness and ggac.
        Signature is based on the BIP-0327 specification: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki.

        Parameters:
        keynbr (int): the key to use (0xFF for bip32 key)
        secnonce (bytes):
        ea (bytes):
        b (bytes):

        returns:
        (response, sw1, sw2)
        '''
        logger.debug("in card_musig2_sign_hash")

        cla = JCconstants.CardEdge_CLA
        ins = 0x7F
        p1 = keynbr

        # OP_INIT: send encrypted_secnonce
        p2 = JCconstants.OP_INIT

        # data: [secnonce(144)]
        assert len(secnonce) == 144
        data = list(secnonce)
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        logger.debug(f"card_musig2_sign_hash() OP_INIT: sw12={hex(256*sw1+sw2)}")

        # OP_FINALIZE: send data for signing
        p2 = JCconstants.OP_FINALIZE

        # data: [ b(32b)| ea(32b) | R_evenness(1b) | ggacc(1b) ]
        assert len(b) == 32
        assert len(ea) == 32
        data = list(b)
        data += list(ea)
        if r_has_even_y:
            data += [0x00]
        else:
            data += [0x01]
        if ggacc_is_1:
            data += [0x01]
        else:
            data += [0x00]

        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        psig = bytes(response)
        logger.debug(f"card_musig2_sign_hash() OP_FINALIZE: sw12={hex(256 * sw1 + sw2)}")

        return psig


    ###########################################
    #              2FA commands               #
    ###########################################
     
    def card_set_2FA_key(self, hmacsha160_key, amount_limit=0):
        ''' Enable and import 2FA in the device
        
        Parameters: 
        hmacsha160_key (bytes | list): the 20-bytes secret
        amount_limit (int): the amount 
        
        Returns: 
        (response, sw1, sw2)
        '''
        if type(hmacsha160_key) is str:
            hmacsha160_key= list(bytes.fromhex(hmacsha160_key))
        elif type(hmacsha160_key) is bytes:
            hmacsha160_key= list(hmacsha160_key)
            
        logger.debug("In card_set_2FA_key")
        cla= JCconstants.CardEdge_CLA
        ins= 0x79
        p1= 0x00
        p2= 0x00
        lc= 28 # data=[ hmacsha160_key(20) | amount_limit(8) ]
        apdu=[cla, ins, p1, p2, lc]

        apdu+= hmacsha160_key
        for i in reversed(range(8)):
            apdu+=[(amount_limit>>(8*i))&0xff]

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            self.needs_2FA= True
        elif (sw1==0x9C and sw2==0x18):
            logger.error(f"Error during 2fa import: card already requires 2FA (0x9C18)")
            raise CardError('Import failed: card already requires 2FA (0x9C18)!')
        elif (sw1==0x6D and sw2==0x00):
            logger.error(f"Error during 2fa import: command unsupported(0x6D00")
            raise CardError(f"Error during 2fa import: command unsupported (0x6D00)")
        else:
            logger.error(f'Unexpected error code: {hex(256*sw1+sw2)}')
            raise UnexpectedSW12Error(f'Unexpected error code: {hex(256*sw1+sw2)}', sw1, sw2)
        return (response, sw1, sw2)

    def card_reset_2FA_key(self, chalresponse):
        ''' Disable 2FA.
        
        Parameters: 
        chalresponse (list | bytes | hex_str): the 20-bytes code to confirm
        
        Returns: 
        (response, sw1, sw2)
        '''
        logger.debug("In card_reset_2FA_key")
        if type(chalresponse) is str:
            chalresponse= list(bytes.fromhex(chalresponse))
        elif type(chalresponse) is bytes:
            chalresponse= list(chalresponse)
        
        cla= JCconstants.CardEdge_CLA
        ins= 0x78
        p1= 0x00
        p2= 0x00
        lc= 20 # data=[ hmacsha160_key(20) ]
        apdu=[cla, ins, p1, p2, lc]
        apdu+= chalresponse

        # send apdu 
        (response, sw1, sw2) = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            self.needs_2FA= False
        return (response, sw1, sw2)

    def card_crypt_transaction_2FA(self, msg, is_encrypt=True):
        logger.debug("In card_crypt_transaction_2FA")
        if (type(msg)==str):
            msg = msg.encode('utf8')
        msg=list(msg)
        msg_out=[]

        # CIPHER_INIT - no data processed
        cla= JCconstants.CardEdge_CLA
        ins= 0x76
        p2= JCconstants.OP_INIT
        blocksize=16
        if is_encrypt:
            p1= 0x02
            lc= 0x00
            apdu=[cla, ins, p1, p2, lc]
            # for encryption, the data is padded with PKCS#7
            size=len(msg)
            padsize= blocksize - (size%blocksize)
            msg= msg+ [padsize]*padsize
            # send apdu
            (response, sw1, sw2) = self.card_transmit(apdu)
            if sw1==0x90 and sw2==0x00:
                # extract IV & id_2FA
                IV= response[0:16]
                id_2FA= response[16:36]
                msg_out=IV
                # id_2FA is 20 bytes, should be 32 => use sha256
                from hashlib import sha256
                id_2FA= sha256(bytes(id_2FA)).hexdigest()
            elif sw1==0x9c and sw2==0x19:
                raise RuntimeError(f"Error: 2FA is not enabled (error code: {hex(256*sw1+sw2)}")
            else:
                raise UnexpectedSW12Error(f'Unexpected error code: {hex(256*sw1+sw2)}', sw1, sw2)
        else:
            p1= 0x01
            lc= 0x10
            apdu=[cla, ins, p1, p2, lc]
            # for decryption, the IV must be provided as part of the msg
            IV= msg[0:16]
            msg=msg[16:]
            apdu= apdu+IV
            if len(msg)%blocksize!=0:
                logger.info('Padding error!')
            # send apdu
            (response, sw1, sw2) = self.card_transmit(apdu)
            if sw1==0x90 and sw2==0x00:
                pass
            elif sw1==0x9c and sw2==0x19:
                raise RuntimeError(f"Error: 2FA is not enabled (error code: {hex(256*sw1+sw2)}")
            else:
                raise UnexpectedSW12Error(f'Unexpected error code: {hex(256*sw1+sw2)}', sw1, sw2)
            
        # msg is cut in chunks and each chunk is sent to the card for encryption/decryption
        # given the protocol overhead, size of each chunk is limited in size:
        # without secure channel, an APDU command is max 255 byte, so chunk<=255-(5+2)
        # with secure channel, data is encrypted and HMACed, the max size is then 152 bytes
        # (overhead: 20b mac, padding, iv, byte_size)
        chunk= 128 #152 
        buffer_offset=0
        buffer_left=len(msg)
        # CIPHER PROCESS/UPDATE (optionnal)
        while buffer_left>chunk:
            p2= JCconstants.OP_PROCESS
            lc= 2+chunk
            apdu=[cla, ins, p1, p2, lc]
            apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
            apdu+= msg[buffer_offset:(buffer_offset+chunk)]
            buffer_offset+=chunk
            buffer_left-=chunk
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)
            # extract msg
            out_size= (response[0]<<8) + response[1]
            msg_out+= response[2:2+out_size]

        # CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left #following while condition, buffer_left<=chunk
        p2= JCconstants.OP_FINALIZE
        lc= 2+chunk
        apdu=[cla, ins, p1, p2, lc]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= msg[buffer_offset:(buffer_offset+chunk)]
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        # extract msg
        out_size= (response[0]<<8) + response[1]
        msg_out+= response[2:2+out_size]

        if is_encrypt:
            #convert from list to string
            msg_out= base64.b64encode(bytes(msg_out)).decode('ascii')
            return (id_2FA, msg_out)
        else:
            #remove padding
            pad= msg_out[-1]
            msg_out=msg_out[0:-pad]
            msg_out= bytes(msg_out).decode('latin-1')#''.join(chr(i) for i in msg_out) #bytes(msg_out).decode('latin-1')
            return (msg_out)

    ###########################################
    #                PIN commands             #
    ###########################################
    
    def card_create_PIN(self, pin_nbr, pin_tries, pin, ublk):
        logger.debug("In card_create_PIN")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CREATE_PIN
        p1= pin_nbr
        p2= pin_tries
        lc= 1 + len(pin) + 1 + len(ublk)
        apdu=[cla, ins, p1, p2, lc] + [len(pin)] + pin + [len(ublk)] + ublk

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)

    #deprecated but used for testcase
    def card_verify_PIN_deprecated(self, pin_nbr, pin):
        logger.debug("In card_verify_PIN_deprecated")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_VERIFY_PIN
        p1= pin_nbr
        p2= 0x00
        lc= len(pin)
        apdu=[cla, ins, p1, p2, lc] + pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)

    def card_verify_PIN_simple(self, pin = None):
        ''' Verify card PIN. Use PIN code provided by user first, or cached PIN value if available.
            Throws exceptions for different cases:
            * CardNotPresentError if card is not inserted in reader
            * PinRequiredError if no PIN code is available
            * WrongPinError if PIN is wrong
            * PinBlockedError if PIN is blocked after too many attempts
            * UnexpectedSW12Error for other issues
        '''
        logger.debug("In card_verify_PIN_simple")
        
        if not self.card_present:
            raise CardNotPresentError('No card found! Please insert card!');

        if pin is not None:
            logger.debug("DEBUG In card_verify_PIN_simple got pin from args!")
            if type(pin)==str:
                pin_0= list(pin.encode("utf-8"))
            elif type(pin)==bytes:
                pin_0= list(pin)
            else:
                raise PinRequiredError(f'PIN should be a String or Bytes, not {type(pin)}')
        else: 
            if self.pin is not None:
                logger.debug("DEBUG In card_verify_PIN_simple got pin from cache!")
                # recover cached value
                pin_0= self.pin
            else:
                raise PinRequiredError('Device cannot be unlocked without PIN code!')

        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_VERIFY_PIN
        apdu=[cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
        
        if (self.needs_secure_channel):
            apdu = self.card_encrypt_secure_channel(apdu)
        response, sw1, sw2 = self.cardservice.connection.transmit(apdu)

        # secure channel session lost on the card side (same recovery as card_transmit)
        if sw1 == 0x9c and 0x20 <= sw2 <= 0x23:
            logger.warning(f"In card_verify_PIN_simple: secure channel error (error code {hex(256*sw1+sw2)}), re-initiating secure channel and retrying once")
            if sw2 == 0x20:
                # the card just told us it requires a secure channel
                self.needs_secure_channel= True
            self.card_initiate_secure_channel()
            #raise UninitializedSecureChannelError('Secure channel is not initialized')
            # resend verify PIN command
            apdu = [cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
            apdu = self.card_encrypt_secure_channel(apdu)
            response, sw1, sw2 = self.cardservice.connection.transmit(apdu)

        # correct PIN: cache PIN value
        if sw1==0x90 and sw2==0x00: 
            self.set_pin(0, pin_0) 
            return response, sw1, sw2
        # wrong PIN, get remaining tries available (since v0.11)
        elif sw1==0x63 and (sw2 & 0xc0)==0xc0:
            logger.error("In card_verify_PIN_simple wrong PIN!")
            self.set_pin(0, None) #reset cached PIN value
            pin_left= (sw2 & ~0xc0)
            raise WrongPinError(f"Wrong PIN! {pin_left} tries remaining!", pin_left)
        # wrong PIN (legacy before v0.11)    
        elif sw1==0x9c and sw2==0x02:
            logger.error("In card_verify_PIN_simple wrong PIN!")
            self.set_pin(0, None) #reset cached PIN value
            (response2, sw1b, sw2b, d)=self.card_get_status() # get number of pin tries remaining
            pin_left= d.get("PIN0_remaining_tries",-1)
            raise WrongPinError(f"Wrong PIN! {pin_left} tries remaining!", pin_left)
        # blocked PIN
        elif sw1==0x9c and sw2==0x0c:
            logger.error("In card_verify_PIN_simple Blocked PIN!")
            self.set_pin(0, None) #reset cached PIN value
            msg = (f"Too many failed attempts! Your device has been blocked! \n\nYou need your PUK code to unblock it (error code {hex(256*sw1+sw2)})")
            raise PinBlockedError(msg)
        # card not setup
        elif sw1==0x9c and sw2==0x04:
            logger.error(f"In card_verify_PIN_simple setup not done (code 0x9C04)")
            raise CardSetupNotDoneError(f"Failed to verify PIN: setup not done (code 0x9C04)")
        # any other edge case
        else:
            self.set_pin(0, None) #reset cached PIN value
            msg = (f"Please check your card! Unexpected error (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(msg, sw1, sw2)  


    def card_verify_PIN(self, pin = None):
        ''' This method is deprecated, use card_verify_PIN_simple() preferrably
            Difference between card_verify_PIN() & card_verify_PIN_simple():
            * card_verify_PIN() send callback to client in case of problem (e.g no/wrong/blocked pin)
            * card_verify_PIN_simple() throws a specific error, to be catch by caller
        '''
        logger.debug("In card_verify_PIN")
        
        while (self.card_present):
            if pin is None:
                if self.pin is None:
                    is_PIN= False
                    if self.client is not None:
                        msg = f'Enter the PIN for your {self.card_type}:'
                        (is_PIN, pin_0)= self.client.PIN_dialog(msg) #todo: use request?
                    if is_PIN is False:
                        raise RuntimeError(('Device cannot be unlocked without correct PIN code!'))
                    pin_0=list(pin_0)
                else:
                    pin_0= self.pin
            else:
                pin_0= list(bytes(pin, "utf-8"))

            cla= JCconstants.CardEdge_CLA
            ins= JCconstants.INS_VERIFY_PIN
            apdu=[cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
            
            if (self.needs_secure_channel):
                apdu = self.card_encrypt_secure_channel(apdu)
            response, sw1, sw2 = self.cardservice.connection.transmit(apdu)
            
            # correct PIN: cache PIN value
            if sw1==0x90 and sw2==0x00: 
                self.set_pin(0, pin_0) # cache value for future use
                return (response, sw1, sw2)     
            # wrong PIN, get remaining tries available (since v0.11)
            elif sw1==0x63 and (sw2 & 0xc0)==0xc0:
                pin = None # reset provided pin
                self.set_pin(0, None) #reset cached PIN value
                pin_left= (sw2 & ~0xc0)
                msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise WrongPinError(msg, pin_left)
            # wrong PIN (legacy before v0.11)    
            elif sw1==0x9c and sw2==0x02:
                pin = None # reset provided pin
                self.set_pin(0, None) #reset cached PIN value
                (response2, sw1b, sw2b, d)=self.card_get_status() # get number of pin tries remaining
                pin_left= d.get("PIN0_remaining_tries",-1)
                msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise WrongPinError(msg, pin_left)
            # blocked PIN
            elif sw1==0x9c and sw2==0x0c:
                msg = (f"Too many failed attempts! Your device has been blocked! \n\nYou need your PUK code to unblock it (error code {hex(256*sw1+sw2)})")
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise IdentityBlockedError(msg)
            elif sw1==0x9c and sw2==0x04:
                msg = "Failed to verify PIN: setup not done (code 0x9C04)"
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise CardSetupNotDoneError(msg)
            # any other edge case
            else:
                self.set_pin(0, None) #reset cached PIN value
                msg = (f"Please check your card! Unexpected error (error code {hex(256*sw1+sw2)})")
                if self.client is not None:
                    self.client.request('show_error', msg)
                return (response, sw1, sw2)     
                
        #if not self.card_present:
        if self.client is not None:
            self.client.request('show_error', 'No card found! Please insert card!')
        else:
            raise RuntimeError('No card found! Please insert card!')
        return
            
    def set_pin(self, pin_nbr, pin):
        self.pin_nbr=pin_nbr
        self.pin=pin
        return

    def is_pin_set(self):
        if self.pin is None:
            return False
        else:
            return True

    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        logger.debug("In card_change_PIN")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CHANGE_PIN
        p1= pin_nbr
        p2= 0x00
        lc= 1 + len(old_pin) + 1 + len(new_pin)
        apdu=[cla, ins, p1, p2, lc] + [len(old_pin)] + old_pin + [len(new_pin)] + new_pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # correct PIN: cache new PIN value
        if sw1==0x90 and sw2==0x00: 
            self.set_pin(pin_nbr, new_pin) 
        # wrong PIN, get remaining tries available (since v0.11)
        elif sw1==0x63 and (sw2 & 0xc0)==0xc0:
            self.set_pin(pin_nbr, None) #reset cached PIN value
            pin_left= (sw2 & ~0xc0)
            msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
            raise WrongPinError(msg, pin_left)
        # wrong PIN (legacy before v0.11)    
        elif sw1==0x9c and sw2==0x02: 
            self.set_pin(pin_nbr, None) #reset cached PIN value
            (response2, sw1b, sw2b, d)=self.card_get_status() # get number of pin tries remaining
            pin_left= d.get("PIN0_remaining_tries",-1)
            msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
            raise WrongPinError(msg, pin_left)
        # blocked PIN
        elif sw1==0x9c and sw2==0x0c:
            msg = (f"Too many failed attempts! Your device has been blocked! \n\nYou need your PUK code to unblock it (error code {hex(256*sw1+sw2)})")
            raise PinBlockedError(msg)
        else:
            # Any other status means the PIN was not changed. Raise rather than
            # return: self.pin still holds the old value, and a caller that does
            # not re-check sw1/sw2 would take this for success.
            logger.error(f"Error during PIN change: {hex(256*sw1+sw2)}")
            raise UnexpectedSW12Error(
                f"Unexpected error during PIN change (error code {hex(256*sw1+sw2)})", sw1, sw2)

        return (response, sw1, sw2)      

    def card_unblock_PIN(self, pin_nbr, ublk, new_pin=None):
        """Unblock a blocked PIN using the corresponding unblock code (PUK).

        Parameters:
            pin_nbr (int): the PIN number to unblock (0x00-0x07)
            ublk (list of int): the PUK bytes
            new_pin (list of int | None): optional new PIN value. Only supported by
                Satochip applet v0.16-0.0 and above: if provided, the PIN is set to
                this value when unblocking; otherwise it keeps its previous value.

        returns: (response, sw1, sw2)
        """
        logger.debug("In card_unblock_PIN")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_UNBLOCK_PIN
        p1= pin_nbr
        p2= 0x00
        # Satochip applet v0.16-0.0 introduced a backward-incompatible UnblockPIN format:
        # the PUK is prefixed with its size and a new PIN can optionally be provided:
        #     data= [PUK_size(1b) | PUK | (optional) PIN_size(1b) | (optional) PIN]
        # Older Satochip versions and the other applets (SeedKeeper, Satodime, Satocash)
        # use the legacy format: data= [PUK].
        use_new_format= False
        if (self.card_type=="Satochip"):
            if not self.protocol_version:
                # protocol_version is cached by card_get_status(); if it is not cached
                # yet, fetch it from the card (GET STATUS is always accepted, even
                # before setup). If the fetch fails, fall back to the legacy format.
                self.card_get_status()
            use_new_format= ((self.protocol_version or 0) >= (0<<8)+16) # v0.16-0.0 & above
        if use_new_format:
            data= [len(ublk)] + ublk
            if new_pin is not None:
                data+= [len(new_pin)] + new_pin
        else:
            if new_pin is not None:
                raise ValueError("Setting a new PIN while unblocking is only supported for Satochip v0.16-0.0 and above")
            data= ublk
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc] + data
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # wrong PUK, get remaining tries available (since v0.11)
        if sw1==0x63 and (sw2 & 0xc0)==0xc0:
            self.set_pin(pin_nbr, None) #reset cached PIN value
            pin_left= (sw2 & ~0xc0)
            msg = ("Wrong PUK! {} tries remaining!").format(pin_left)
            raise WrongPinError(msg, pin_left)
        # wrong PUK (legacy before v0.11)    
        elif sw1==0x9c and sw2==0x02: 
            self.set_pin(pin_nbr, None) #reset cached PIN value
            (response2, sw1b, sw2b, d)=self.card_get_status() # get number of pin tries remaining
            pin_left= d.get("PUK0_remaining_tries",-1)
            msg = ("Wrong PUK! {} tries remaining!").format(pin_left)
            raise WrongPinError(msg, pin_left)
        # blocked PUK
        elif sw1==0x9c and sw2==0x0c:
            self.set_pin(pin_nbr, None) #reset cached PIN value
            msg = (f"Too many failed attempts. Your device has been blocked! (error code {hex(256*sw1+sw2)})")
            raise PinBlockedError(msg)
        # reset to factory (SeedKeeper v0.2)
        elif sw1==0xFF and sw2==0x00: 
            self.set_pin(pin_nbr, None) #reset cached PIN value
            self.setup_done = False
            msg = ("CARD RESET TO FACTORY!")
            raise CardResetToFactoryError(msg)

        return (response, sw1, sw2)

    def card_logout_all(self):
        logger.debug("In card_logout_all")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_LOGOUT_ALL
        p1= 0x00
        p2= 0x00
        lc=0
        apdu=[cla, ins, p1, p2, lc]
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        self.set_pin(0, None)
        return (response, sw1, sw2)
        
    ###########################################
    #            Secure Channel               #
    ###########################################
    
    def card_initiate_secure_channel(self):
        """Establish a *new* secure channel with the card.

        The channel is built into a local object and published to self.sc only
        once it is fully usable, so another thread never sees a half-initialized
        channel. Prefer card_ensure_secure_channel() unless a fresh channel is
        specifically required (e.g. after the card returns 0x9C21).
        """
        logger.debug("In card_initiate_secure_channel()")
        cla= JCconstants.CardEdge_CLA
        ins= 0x81
        p1= 0x00 
        p2= 0x00
        
        with self._sc_lock:
            # get sc
            sc= SecureChannel()
            pubkey= list(sc.sc_pubkey_serialized)
            lc= len(pubkey) #65
            apdu=[cla, ins, p1, p2, lc] + pubkey
            
            # send apdu (ins 0x81 is never encrypted, see card_transmit)
            self._sc_initializing= True
            try:
                response, sw1, sw2 = self.card_transmit(apdu)
            finally:
                self._sc_initializing= False

            # On an error status the body is an error payload or empty: never
            # derive a session key from it.
            if (sw1!=0x90 or sw2!=0x00):
                logger.error(f"Error during secure channel initialization (error code {hex(256*sw1+sw2)})")
                raise UnexpectedSW12Error(
                    f"Unexpected error during secure channel initialization (error code {hex(256*sw1+sw2)})",
                    sw1, sw2)

            # parse response and extract pubkey...
            peer_pubkey = self.parser.parse_initiate_secure_channel(response)
            peer_pubkey_bytes= peer_pubkey.get_public_key_bytes(compressed=False)
            sc.initiate_secure_channel(peer_pubkey_bytes)
            
            # publish the channel only once it is complete
            self.sc= sc
        
        return peer_pubkey             
    
    def card_ensure_secure_channel(self):
        """Initiate the secure channel unless a usable one is already available.

        Idempotent and thread-safe: this is the single entry point through which
        the channel gets created, so callers never have to set it up themselves.
        """
        with self._sc_lock:
            if (self.sc is not None) and self.sc.initialized_secure_channel:
                return
            if self._sc_initializing:
                # reached only if a command needing encryption is sent from
                # within the 0x81 exchange itself: initiating again would recurse
                raise SecureChannelError('Secure channel is being initialized')
            logger.debug("In card_ensure_secure_channel: no usable secure channel, initiating one")
            self.card_initiate_secure_channel()
       
    def card_encrypt_secure_channel(self, apdu):
        logger.debug("In card_encrypt_secure_channel()")
        
        # every path that needs encryption goes through here (card_transmit,
        # card_verify_PIN_simple, card_verify_PIN_deprecated), so this is where
        # the channel is guaranteed to exist
        self.card_ensure_secure_channel()
        
        cla= JCconstants.CardEdge_CLA
        ins= 0x82
        p1= 0x00 
        p2= 0x00
        
        # log plaintext apdu (body masked unless the instruction is known to be
        # free of secret material -- see _LOGGABLE_INS)
        logger.debug(f"Plaintext C-APDU: {_redact_apdu(apdu)}")

        (iv, ciphertext, mac)= self.sc.encrypt_secure_channel(bytes(apdu))
        data= list(iv) + [len(ciphertext)>>8, len(ciphertext)&0xff] + list(ciphertext) + [len(mac)>>8, len(mac)&0xff] + list(mac)
        lc= len(data)
        
        encrypted_apdu= [cla, ins, p1, p2, lc]+data
        
        return encrypted_apdu
    
    def card_decrypt_secure_channel(self, response, ins=None):
        logger.debug("In card_decrypt_secure_channel")
        
        if len(response)==0:
            return response
        elif len(response)<18:
            raise SecureChannelError('Encrypted response has wrong length!')
        
        iv= bytes(response[0:16])
        size= ((response[16] & 0xff)<<8) + (response[17] & 0xff)
        ciphertext= bytes(response[18:])
        if len(ciphertext)!=size:
            logger.warning(f'In card_decrypt_secure_channel: ciphertext has wrong length: expected {str(size)} got {str(len(ciphertext))}')
            raise SecureChannelError('Ciphertext has wrong length!')
        
        # take a reference: the channel can be dropped by the card monitor thread
        # (card removed) between the encrypted command and its response
        sc= self.sc
        if (sc is None) or (not sc.initialized_secure_channel):
            raise SecureChannelError('Secure channel was closed before the response could be decrypted!')
        
        plaintext= sc.decrypt_secure_channel(iv, ciphertext)
        
        # log response. The decrypted body routinely carries exported masterseeds,
        # private keys and xprv, so it is masked unless `ins` says otherwise.
        logger.debug( f'Plaintext R-APDU: {_redact_response(plaintext, ins)}')
        
        return plaintext
        
    #################################
    #           SEEDKEEPER          #        
    #################################                               

    def seedkeeper_get_status(self):
        """Return status info specific to SeedKeeper"""
        logger.debug("In seedkeeper_get_status")
        cla= JCconstants.CardEdge_CLA
        ins= 0xA7
        p1= 0x00
        p2= 0x00
        apdu=[cla, ins, p1, p2]
        (response, sw1, sw2)= self.card_transmit(apdu)
        
        if (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x00 and sw2==0x00):
            logger.error(f"Error while fetching SeedKeeper status: no card present (code 0x0000)")
            raise CardNotPresentError(f"Error while fetching SeedKeeper status: no card present (code 0x0000)")
        elif (sw1==0x9c and sw2==0x04):
            logger.error(f"Error while fetching SeedKeeper status: setup not done (code 0x9C04)")
            raise CardSetupNotDoneError(f"Error while fetching SeedKeeper status: setup not done (code 0x9C04)")
        else: 
            logger.error(f"Error while fetching SeedKeeper status: (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Error while fetching SeedKeeper status: (error code {hex(256*sw1+sw2)})", sw1, sw2)
        
        offset=0
        seedKeeper_status={}
        # memory
        nb_secrets = 256*response[offset] + response[offset+1]
        offset+=2
        total_memory = 256*response[offset] + response[offset+1]
        offset+=2
        free_memory = 256*response[offset] + response[offset+1]
        # logs
        offset+=2
        nb_logs_total = 256*response[offset] + response[offset+1]
        offset+=2
        nb_logs_avail = 256*response[offset] + response[offset+1]
        offset+=2
        last_log = response[offset:(offset+7)]
        seedKeeper_status['nb_secrets']= nb_secrets
        seedKeeper_status['total_memory']= total_memory
        seedKeeper_status['free_memory']= free_memory
        seedKeeper_status['nb_logs_total']= nb_logs_total
        seedKeeper_status['nb_logs_avail']= nb_logs_avail
        seedKeeper_status['last_log']= last_log
        return (response, sw1, sw2, seedKeeper_status)

    def seedkeeper_generate_masterseed(self, seed_size, export_rights, label:str):
        logger.debug("In seedkeeper_generate_masterseed")
        cla= JCconstants.CardEdge_CLA
        ins= 0xA0
        p1= seed_size
        p2= export_rights
        
        label= list(label.encode('utf-8'))
        label_size= len(label)
        data= [label_size]+label
        
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            id= (response[0]<<8)+response[1]
            logger.debug(f"Masterseed generated successfully with id: {id}")
            fingerprint_list= response[2:2+4]
            fingerprint= bytes(fingerprint_list).hex()
        else:
            logger.error(f"Error during masterseed generation: {hex(256*sw1+sw2)}")
            id=None
            fingerprint= None
            
        return (response, sw1, sw2, id, fingerprint)
    
    def seedkeeper_generate_2FA_secret(self, export_rights, label:str):
        logger.debug("In seedkeeper_generate_2FA_secret")
        cla= JCconstants.CardEdge_CLA
        ins= 0xAE
        p1= 0x00
        p2= export_rights
        
        label= list(label.encode('utf-8'))
        label_size= len(label)
        data= [label_size]+label
        
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            id= (response[0]<<8)+response[1]
            logger.debug(f"2FA secret generated successfully with id: {id}")
            fingerprint_list= response[2:2+4]
            fingerprint= bytes(fingerprint_list).hex()
        else:
            logger.error(f"Error during masterseed generation: {hex(256*sw1+sw2)}")
            id=None
            fingerprint= None
            
        return (response, sw1, sw2, id, fingerprint)
    
    def seedkeeper_generate_random_secret(self, stype:int, subtype:int, size:int, export_rights:int, label:str, save_entropy:int, entropy: Union[str, bytes]):
        logger.debug("In seedkeeper_generate_random_secret")
        
        if (size<16 or size>64):
            raise RuntimeError('Random secret generation: wrong size')

        # todo check type
        # todo check save_entropy

        cla= JCconstants.CardEdge_CLA
        ins= 0xA3
        p1= size
        p2= export_rights
        
        label_list= list(label.encode('utf-8'))
        label_size= len(label_list)

        if type(entropy) == str:
            entropy_list = list(entropy.encode('utf-8'))
        elif type(entropy) == bytes:
            entropy_list = list(entropy)
        entropy_size= len(entropy_list)

        data= [stype, subtype, save_entropy] + [label_size]+label_list + [entropy_size] + entropy_list
        
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # send apdu
        dic = {}
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            id= (response[0]<<8)+response[1]
            logger.debug(f"Random secret generated successfully with id: {id}")
            fingerprint_list= response[2:2+4]
            fingerprint= bytes(fingerprint_list).hex()
            dic['id']= id
            dic['fingerprint']= fingerprint
            if len(response)>=12:
                id2= (response[6]<<8)+response[7]
                logger.debug(f"Entropy saved successfully with id: {id2}")
                fingerprint_list2= response[8:8+4]
                fingerprint2= bytes(fingerprint_list2).hex()  
                dic['id_entropy']= id2
                dic['fingerprint_entropy']= fingerprint2
        else:
            logger.error(f"Error during masterseed generation: {hex(256*sw1+sw2)}")
            dic['id']= None
            dic['fingerprint']= None
            
        return (response, sw1, sw2, dic)


    def seedkeeper_derive_master_password(self, salt, sid, sid_pubkey=None):
        logger.debug("In seedkeeper_derive_master_password")

        is_secure_export= False if (sid_pubkey is None) else True
        if (is_secure_export):
            raise RuntimeError("is_secure_export currently unsupported for seedkeeper_derive_master_password")

        # the response signature is checked below, which needs the authentikey
        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        cla= JCconstants.CardEdge_CLA
        ins= 0xAF
        p1= 0x02 if is_secure_export else 0x01
        p2= 0x00
        
        if type(salt) == str:
            salt_list = list(salt.encode('utf-8'))
        elif type(salt) == bytes:
            salt_list = list(salt)
        data= [(sid>>8)%256, sid%256] + [len(salt_list)] + salt_list
        
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            dic= {}
            # parse data
            offset = 0;
            response_size= len(response)
            derived_data_size= (response[0]<<8)+response[1]
            derived_data= response[2:(2+derived_data_size)]
            dic['derived_data_list']= derived_data
            dic['derived_data']= bytes(derived_data).hex()
            full_data = response[0:(2+derived_data_size)]
            dic['full_data_list']= full_data
            dic['full_data']= bytes(full_data).hex()
            offset = 2+derived_data_size

            sign_size=  (response[offset]<<8)+response[offset+1]
            offset+=2
            sign= response[offset:(offset+sign_size)]

            # is_secure_export is always False here (the function raises above
            # when it is requested), so the card must return a signature over
            # full_data, never the 20-byte hmac of a secure export. Let a failure
            # propagate: the derived master password must not be returned with an
            # unchecked signature.
            self.parser.verify_signature(full_data, sign, self.parser.authentikey)
            dic['sign_list']=sign
            dic['sign']=bytes(sign).hex()
        else:
            logger.error(f"Error during master password derivation: {hex(256*sw1+sw2)}")
            dic = {}
        
        return (response, sw1, sw2, dic)


    def seedkeeper_import_secret(self, secret_dic, sid_pubkey=None):
        logger.debug("In seedkeeper_import_secret")
        
        is_secure_import= False if (sid_pubkey is None) else True
        if (is_secure_import):
            secret_list= list(bytes.fromhex(secret_dic['secret_encrypted']))
            padded_secret_size = len(secret_list) # encrypted_secret is already padded!
        else:
            secret_list= secret_dic['secret_list']
            secret_size= len(secret_list)
            pad_size = 16 - (secret_size)%16
            padded_secret_size = secret_size + pad_size # padded_secret_size is size of encrypted secret (including padding)

        cla= JCconstants.CardEdge_CLA
        ins= 0xA1
        p1= 0x02 if is_secure_import else 0x01
        
        # OP_INIT
        p2= 0x01        
        header= list(bytes.fromhex(secret_dic['header'][4:])) 
        
        #data= [secret_type, export_rights, rfu1, rfu2, label_size] + label_list + [(sid_pubkey>>8)%256, sid_pubkey%256] + iv 
        # for SeedKeeper v0.2
        #data= [secret_type, export_rights, rfu1, rfu2, label_size] + label_list + [(sid_pubkey>>8)%256, sid_pubkey%256] + iv + padded_secret_size(2b)
        data=  header
        if (is_secure_import):
            iv= list(bytes.fromhex(secret_dic['iv']))
            data+= [(sid_pubkey>>8)%256, sid_pubkey%256] + iv
        data+= [(padded_secret_size>>8)%256, (padded_secret_size%256)]
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1!=0x90 or sw2!=0x00):
            logger.error(f"Error during secret import - OP_INIT: {(sw1*256+sw2):0>4X}")
            raise UnexpectedSW12Error(f"Unexpected error during secure secret import (error code {hex(256*sw1+sw2)})", sw1, sw2)
            
        # OP_PROCESS
        p2= 0x02
        chunk_size=128;
        # if (is_secure_import):
        #     secret_list= list(bytes.fromhex(secret_dic['secret_encrypted']))
        # else:
        #     secret_list= secret_dic['secret_list']
        secret_offset= 0
        secret_remaining= len(secret_list)
        while (secret_remaining>chunk_size):
            data= [(chunk_size>>8), (chunk_size%256)] + secret_list[secret_offset:(secret_offset+chunk_size)]
            lc=len(data)
            apdu=[cla, ins, p1, p2, lc]+data
            response, sw1, sw2 = self.card_transmit(apdu)
            if (sw1!=0x90 or sw2!=0x00):
                logger.error(f"Error during secret import - OP_PROCESS (error code {hex(256*sw1+sw2)})")
                raise UnexpectedSW12Error(f"Unexpected error during secure secret import (error code {hex(256*sw1+sw2)})", sw1, sw2)
            secret_offset+=chunk_size
            secret_remaining-=chunk_size
        
        # OP_FINAL
        p2= 0x03
        data= [(secret_remaining>>8), (secret_remaining%256)] + secret_list[secret_offset:(secret_offset+secret_remaining)]
        if (is_secure_import):
            hmac= list(bytes.fromhex(secret_dic['hmac']))
            data+= [len(hmac)] + hmac
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x9C and sw2==0x33):
            logger.error(f"Error during secret import - OP_FINAL: wrong mac (error code {hex(256*sw1+sw2)})")
            raise SeedKeeperError(f"Error during secret import: wrong mac (error code {hex(256*sw1+sw2)})")
        elif (sw1!=0x90 or sw2!=0x00):
            logger.error(f"Error during secret import - OP_FINAL (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error during secure secret import (error code {hex(256*sw1+sw2)})", sw1, sw2)
        secret_offset+=chunk_size
        secret_remaining=0
        
        # check fingerprint
        id= response[0]*256+response[1]
        fingerprint_list= response[2:6]
        fingerprint_from_seedkeeper= bytes(fingerprint_list).hex()
        if (is_secure_import):
            fingerprint_from_secret= secret_dic['fingerprint'] 
        else:
            fingerprint_from_secret= hashlib.sha256(bytes(secret_list)).hexdigest()[0:8]
        if (fingerprint_from_secret == fingerprint_from_seedkeeper ):
            logger.debug("Fingerprints match !")
        else:
            # The fingerprint exists to detect that the card stored something
            # other than what we sent; for a masterseed that would make funds
            # derived from it unrecoverable. The secret is already on the card
            # under `id`, so report it and let the caller delete it.
            logger.error(f"Fingerprint mismatch: expected {fingerprint_from_secret} but recovered {fingerprint_from_seedkeeper} ")
            raise SeedKeeperError(
                f"Secret import failed: fingerprint mismatch, the card stored something "
                f"different from what was sent (expected {fingerprint_from_secret}, "
                f"card reports {fingerprint_from_seedkeeper}). The secret was saved with "
                f"id {id} and should not be trusted.")

        return id, fingerprint_from_seedkeeper
        
    def seedkeeper_export_secret(self, sid, sid_pubkey= None):
        logger.debug("In seedkeeper_export_secret")

        # Initialise self.parser.authentikey if not done already (If it is none, this function will crash)
        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()
        
        is_secure_export= False if (sid_pubkey is None) else True
        
        cla= JCconstants.CardEdge_CLA
        ins= 0xA2
        p1= 0x02 if is_secure_export else 0x01
        p2= 0x01 # init

        data= [(sid>>8)%256, sid%256]
        if (is_secure_export):
            data+=[(sid_pubkey>>8)%256, sid_pubkey%256]
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # initial call
        logger.debug("in seedkeeper_export_secret: INIT")
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x9c and sw2==0x31):
            logger.warning("Export failed: export not allowed by SeedKeeper policy.")
            raise SeedKeeperError("Export failed: export not allowed by SeedKeeper policy.")
        elif (sw1==0x9c and sw2==0x08):
            logger.warning("Export failed: secret not found")
            raise SeedKeeperError("Export failed: secret not found")
        elif (sw1==0x9c and sw2==0x30):
            logger.warning("Export failed: lock error - try again")
            #TODO: try again?
            raise SeedKeeperError("Export failed: lock error - try again")
        elif (sw1 == 0x9c and sw2 == 0x0f):
            raise SeedKeeperError("Export failed: Invalid Pubkey Selected")
        else:
            logger.warning(f"Unexpected error (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error (error code {hex(256*sw1+sw2)})", sw1, sw2)
        #TODO add more SW support

        # parse header
        secret_dict= self.parser.parse_seedkeeper_header(response)
        # iv
        if (is_secure_export):
            iv=  response[-16:] #todo: parse also in parse_seedkeeper_header()?
            logger.debug("IV:"+ bytes(iv).hex())
            secret_dict['iv_list']=iv
            secret_dict['iv']= bytes(iv).hex()
                
        secret=[]
        p2= 0x02
        apdu=[cla, ins, p1, p2, lc]+data
        while(True):
            logger.debug("in seedkeeper_export_secret: UPDATE")
            response, sw1, sw2 = self.card_transmit(apdu)
            if (sw1==0x90 and sw2==0x00):
                pass
            elif (sw1==0x9c and sw2==0x08):
                logger.warning("Export failed: secret not found")
                raise SeedKeeperError("Export failed: secret not found")
            elif (sw1==0x9c and sw2==0x30):
                logger.warning("Export failed: lock error - try again")
                #TODO: try again?
                raise SeedKeeperError("Export failed: lock error - try again")
            else:
                logger.warning(f"Unexpected error (error code {hex(256*sw1+sw2)})")
                raise UnexpectedSW12Error(f"Unexpected error (error code {hex(256*sw1+sw2)})", sw1, sw2)

            # parse data
            response_size= len(response)
            chunk_size= (response[0]<<8)+response[1]
            chunk= response[2:(2+chunk_size)]
            secret+= chunk
            
            # check if last chunk
            if (chunk_size+2<response_size):
                offset= chunk_size+2
                sign_size=  (response[offset]<<8)+response[offset+1]
                offset+=2
                sign= response[offset:(offset+sign_size)]
                
                # Which form to expect is decided by the export mode *we* asked
                # for, never by the length the card sends back: a plain export is
                # signed with the authentikey, while a secure export carries a
                # 20-byte hmac keyed with the secret shared with the destination
                # device, which only that device can verify.
                full_data=secret_dict['header_list']+secret
                if is_secure_export:
                    if (sign_size!=20):
                        raise SeedKeeperError(
                            f"Export failed: expected a 20-byte hmac for a secure export, got {sign_size} bytes")
                    secret_dict['hmac_list']=sign
                    secret_dict['hmac']=bytes(sign).hex()
                else:
                    self.parser.verify_signature(full_data, sign, self.parser.authentikey)
                    secret_dict['sign_list']=sign
                    secret_dict['sign']=bytes(sign).hex()
                secret_dict['full_data_list']= full_data
                secret_dict['full_data']= bytes(full_data).hex()
                break
        secret_dict['secret_list']= secret
        if is_secure_export:
            secret_dict['secret_encrypted']= bytes(secret).hex()
        else:
            secret_dict['secret']= bytes(secret).hex()
        #logger.debug(f"Secret: {secret_dict['secret']}")
        #TODO: parse secret depending to type for all possible cases
        
        # check fingerprint. Only possible for a plain export: a secure export
        # returns the secret encrypted to the destination device, so the host
        # cannot recompute the digest.
        if not is_secure_export:
            secret_dict['fingerprint_from_secret']= hashlib.sha256(bytes(secret)).hexdigest()[0:8]
            if ( secret_dict['fingerprint_from_secret'] == secret_dict['fingerprint'] ):
                logger.debug("Fingerprints match !")
            else:
                # The exported bytes do not match the digest the card stored
                # alongside them: the secret is corrupt or was tampered with in
                # transit, and a bad seed looks exactly like a good one.
                logger.error(f"Fingerprint mismatch: expected {secret_dict['fingerprint']} but recovered {secret_dict['fingerprint_from_secret']} ")
                raise SeedKeeperError(
                    f"Secret export failed: fingerprint mismatch, the exported secret does "
                    f"not match the fingerprint stored on the card (expected "
                    f"{secret_dict['fingerprint']}, computed "
                    f"{secret_dict['fingerprint_from_secret']}). The secret is corrupt or "
                    f"was tampered with and must not be used.")

        return secret_dict

    def seedkeeper_export_secret_to_satochip(self, sid, sid_pubkey):
        logger.debug("In seedkeeper_export_secret_to_satochip")

        # Initialise self.parser.authentikey if not done already (If it is none, this function will crash)
        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()
        
        cla= JCconstants.CardEdge_CLA
        ins= 0xA8
        p1= 0x00
        p2= 0x00
        
        data= [(sid>>8)%256, sid%256]
        data+=[(sid_pubkey>>8)%256, sid_pubkey%256]
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x9c and sw2==0x31):
            logger.warning("Export failed: export not allowed by SeedKeeper policy.")
            raise SeedKeeperError("Export failed: export not allowed by SeedKeeper policy.")
        elif (sw1==0x9c and sw2==0x08):
            logger.warning("Export failed: secret not found")
            raise SeedKeeperError("Export failed: secret not found")
        elif (sw1 == 0x9c and sw2 == 0x0f):
            raise SeedKeeperError("Export failed: invalid parameter")
        else:
            logger.warning(f"Unexpected error (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error (error code {hex(256*sw1+sw2)})", sw1, sw2)
        #TODO add more SW support

        response_offset= 0
        # parse header
        secret_dict= self.parser.parse_seedkeeper_header(response[response_offset:(response_offset+2+13)])
        response_offset+=15
        # iv
        iv=  response[response_offset:(response_offset+16)] #todo: parse also in parse_seedkeeper_header()?
        response_offset+=16
        logger.debug("IV:"+ bytes(iv).hex())
        secret_dict['iv_list']=iv
        secret_dict['iv']= bytes(iv).hex()
        
        # secret_size
        secret_size = 256*response[response_offset] + response[response_offset+1]
        response_offset+=2

        # secret
        secret = response[response_offset:(response_offset+secret_size)]
        response_offset+=secret_size
        secret_dict['secret_list']= secret
        secret_dict['secret_encrypted']= bytes(secret).hex()
        
        # hmac
        sign_size=  256*response[response_offset] + response[response_offset+1]
        response_offset+=2      
        sign= response[response_offset:(response_offset+sign_size)]
        secret_dict['hmac_list']=sign
        secret_dict['hmac']=bytes(sign).hex()

        full_data=secret_dict['header_list']+secret
        secret_dict['full_data_list']= full_data
        secret_dict['full_data']= bytes(full_data).hex()
        
        return secret_dict
    
    def seedkeeper_list_secret_headers(self):
        logger.debug("In seedkeeper_list_secret_headers")
        cla= JCconstants.CardEdge_CLA
        ins= 0xA6
        p1= 0x00
        
        # init
        headers=[]
        p2= 0x01
        apdu=[cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        
        while (sw1==0x90 and sw2==0x00):
            secret_dict= self.parser.parse_seedkeeper_header(response)
            headers+=[secret_dict]
            #todo: verif signature
            
            # next object
            p2= 0x02
            apdu=[cla, ins, p1, p2]
            response, sw1, sw2 = self.card_transmit(apdu)
        
        if  (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x9C and sw2==0x12):
            logger.debug(f"No more object in memory")
        elif (sw1==0x9C and sw2==0x04):
            logger.warning(f"UninitializedSeedError during object listing: {hex(256*sw1+sw2)}")
            raise UninitializedSeedError("SeedKeeper is not initialized!")
        else:
            logger.warning(f"Unexpected error during object listing (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error during object listing (error code {hex(256*sw1+sw2)})", sw1, sw2)
            
        return headers

    def seedkeeper_reset_secret(self, sid):
        logger.debug("In seedkeeper_reset_secret")

        cla= JCconstants.CardEdge_CLA
        ins= 0xA5
        p1= 0x00
        p2= 0x00
        
        data= [(sid>>8)%256, sid%256]
        lc=len(data)
        apdu=[cla, ins, p1, p2, lc]+data
        
        # send call
        dic ={}
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90 and sw2==0x00):
            dic["is_reset"] = True
            return response, sw1, sw2, dic
        elif (sw1==0x9C and sw2==0x08):
            # logger.debug(f"Error 0x9C08: Secret not found!")
            # raise SeedKeeperError("Reset secret failed: secret not found?")
            dic["is_reset"] = False
            return response, sw1, sw2, dic
        else:
            logger.warning(f"Unexpected error during object deletion (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error during object deletion (error code {hex(256*sw1+sw2)})", sw1, sw2)


    def seedkeeper_print_logs(self, print_all=True):
        logger.debug("In seedkeeper_print_logs")
        cla= JCconstants.CardEdge_CLA
        ins= 0xA9
        p1= 0x00
        
        # init
        p2= 0x01
        apdu=[cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # first log
        logs=[]
        log_size=7;
        if (sw1==0x90 and sw2==0x00):
            nbtotal_logs= response[0]*256+response[1]
            nbavail_logs= response[2]*256+response[3]
            logger.debug("nbtotal_logs: "+ str(nbtotal_logs))
            logger.debug("nbavail_logs: "+ str(nbavail_logs))
            if len(response)>=4+log_size:
                (opins, id1, id2, res)= self.parser.parse_seedkeeper_log(response[4:4+log_size])
                logs=logs+[[opins, id1, id2, res]]
                logger.debug("Latest log: "+ str(logs[0]))
            else:
                logger.debug("No logs available!")           
        elif (sw1==0x9C and sw2==0x04):
            logger.warning(f"UninitializedSeedError during object listing: {hex(256*sw1+sw2)}")
            raise UninitializedSeedError("SeedKeeper is not initialized!")
        else:
            logger.warning(f"Unexpected error during object listing (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error during object listing (error code {hex(256*sw1+sw2)})", sw1, sw2)
            
        #next logs
        p2= 0x02
        apdu=[cla, ins, p1, p2]
        counter=0
        while (print_all and sw1==0x90 and sw2==0x00):
            
            response, sw1, sw2 = self.card_transmit(apdu)
            if (len(response)==0):
                break
                
            while (len(response)>=log_size):
                (opins, id1, id2, res)= self.parser.parse_seedkeeper_log(response[0:log_size])
                logger.debug("Next log: "+ str([opins, id1, id2, res]))
                logs=logs+[[opins, id1, id2, res]]
                response= response[log_size:]
            
            counter+=1
            if (counter>100): # safe break; should never happen
                logger.warning(f"Counter exceeded during log printing: {counter}")
                break
            
        if (sw1!=0x90 or sw2!=0x00):
            logger.warning(f"Error during log printing: {hex(256*sw1+sw2)}")
        
        #debug: print logs
        logger.debug(f"LOGS size: {len(logs)}")
        i=0
        for log in logs:
            (opins, id1, id2, res)= log
            logger.debug(f"index: {i} | {hex(opins)} {id1} {id2} {hex(res)}")
            i+=1
            
        return (logs, nbtotal_logs, nbavail_logs)
    
    def make_header(self, secret_type, export_rights, label, subtype = 0x00):
        id=2*[0x00]
        if type(secret_type) is str:
            itype= dict_swap_keys_values(SEEDKEEPER_DIC_TYPE)[secret_type]
        else:
            itype= secret_type
        origin= 0x00
        if type(export_rights) is str:
            export= dict_swap_keys_values(SEEDKEEPER_DIC_EXPORT_RIGHTS)[export_rights]
        else:
            export= export_rights
        export_counters=3*[0x00]
        fingerprint= 4*[0x00]
        rfu= [subtype, 0x00]
        # label_size must be the UTF-8 byte length, not the character count:
        # the card parses label_size bytes and misaligns every following field otherwise
        label_list= list(label.encode('utf8'))
        label_size= len(label_list)
        header_list= id + [itype, origin, export] + export_counters + fingerprint + rfu + [label_size] + label_list
        header_hex= bytes(header_list).hex()
        return header_hex

    #################################
    #            SATOCASH           #
    #################################

    def satocash_get_status(self):
        logger.debug("In card_get_status")
        cla = JCconstants.CardEdge_CLA
        ins = 0xB0
        p1 = 0x00
        p2 = 0x00
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.card_transmit(apdu)  # todo: try/except if setup not done
        d = {}
        if (sw1 == 0x90) and (sw2 == 0x00):
            # card applet version
            d["protocol_major_version"] = response[0]
            d["protocol_minor_version"] = response[1]
            d["applet_major_version"] = response[2]
            d["applet_minor_version"] = response[3]
            d["protocol_version"] = (d["protocol_major_version"] << 8) + d["protocol_minor_version"]
            self.protocol_version = d["protocol_version"]  # cache version
            # PIN/PUK status
            if len(response) >= 8:
                d["PIN0_remaining_tries"] = response[4]
                d["PUK0_remaining_tries"] = response[5]
                d["PIN1_remaining_tries"] = response[6]
                d["PUK1_remaining_tries"] = response[7]
                self.needs_2FA = d["needs2FA"] = False  # default value
            # 2FA status
            if len(response) >= 9:
                self.needs_2FA = d["needs2FA"] = False if response[8] == 0X00 else True
            # needsPIN (satocash)
            if len(response) >= 10:
                # byte 9 is the PIN flag; self.is_seeded is the Satochip seed
                # flag and is unrelated to it
                self.needsPIN = d["needs_pin"] = False if response[9] == 0X00 else True
            # setup status
            if len(response) >= 11:
                self.setup_done = d["setup_done"] = False if response[10] == 0X00 else True
            else:
                self.setup_done = d["setup_done"] = True
                # secure channel status
            if len(response) >= 12:
                self.needs_secure_channel = d["needs_secure_channel"] = False if response[11] == 0X00 else True
            else:
                self.needs_secure_channel = d["needs_secure_channel"] = False
            # NFC policy
            if len(response) >= 13:
                self.nfc_policy = d["nfc_policy"] = response[12]  # 0:NFC_ENABLED, 1:NFC_DISABLED, 2:NFC_BLOCKED
            else:
                self.nfc_policy = d["nfc_policy"] = 0x00  # NFC_ENABLED by default
            # pin policy
            self.pin_policy = d["pin_policy"] = response[13]
            # RFU policy
            self.rfu_policy = d["rfu_policy"] = response[14]
            # satocash settings
            self.satocash_max_nb_mints = d["max_nb_mints"] = response[15]
            self.satocash_nb_mints = d["nb_mints"] = response[16]
            self.satocash_max_nb_keysets = d["max_nb_keysets"] = response[17]
            self.satocash_nb_keysets = d["nb_keysets"] = response[18]
            self.satocash_max_nb_proofs = d["max_nb_proofs"] = (response[19]<<8) + response[20]
            self.satocash_nb_unspent_proofs = d["nb_unspent_proofs"] = (response[21]<<8) + response[22]
            self.satocash_nb_spent_proofs = d["nb_spent_proofs"] = (response[23] << 8) + response[24]
            self.satocash_nb_proofs = d["nb_proofs"] = self.satocash_nb_unspent_proofs + self.satocash_nb_spent_proofs

        else:
            logger.warning(f"Unexpected error in get_status() (error code {hex(256 * sw1 + sw2)})")
            # raise RuntimeError(f"Unknown error in get_status() (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Unexpected error in satocash_get_status: {hex(256*sw1+sw2)}", sw1, sw2)

        return response, sw1, sw2, d

    def satocash_import_mint(self, url: str):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB1
        p1 = 0x00
        p2 = 0x00

        url_bytes = url.encode('utf-8')
        url_list = list(url_bytes)

        data = [len(url_list)] + url_list
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x90 and sw2==0x00:
            index = response[0]
            return response, sw1, sw2, index
        elif sw1==0x9C and sw2==0x06:
            raise PinRequiredError()
        elif sw1==0x9c and sw2==0x01:
            raise CardMemoryError()
        elif sw1==0x67 and sw2==0x00:
            raise CardWrongLengthError()
        elif sw1==0x9c and sw2==0x0F:
            raise CardInvalidParameter()
        elif sw1==0x9C and sw2==0x60:
            raise CardObjectAlreadyPresentError()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_import_mint: {hex(256*sw1+sw2)}", sw1, sw2)


    def satocash_export_mint(self, index: int):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB2
        p1 = index
        p2 = 0x00

        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x90 and sw2==0x00:
            url_size = response[0]
            url_bytes = bytes(response[1:(url_size+1)])
            try:
                url = url_bytes.decode("utf-8")
            except Exception as ex:
                url = url_bytes.hex()
            return response, sw1, sw2, url

        elif sw1==0x9C and sw2==0x06:
            raise PinRequiredError()
        elif sw1==0x9c and sw2==0x0F:
            raise CardIncorrectP1()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_export_mint: {hex(256*sw1+sw2)}", sw1, sw2)

    def satocash_remove_mint(self, index: int):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB3
        p1 = index
        p2 = 0x00

        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x90 and sw2==0x00:
            return response, sw1, sw2

        # 9C06 SW_UNAUTHORIZED , 9C10 SW_INCORRECT_P1, 9C03 SW_OPERATION_NOT_ALLOWED
        elif sw1==0x9C and sw2==0x06:
            raise PinRequiredError()
        elif sw1==0x9c and sw2==0x0F:
            raise CardIncorrectP1()
        elif sw1==0x9c and sw2==0x03:
            raise CardOperationNotAllowed()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_remove_mint: {hex(256*sw1+sw2)}", sw1, sw2)


    def satocash_import_keyset(self, keyset_id: bytes, mint_index: int, unit: int):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB4
        p1 = 0x00
        p2 = 0x00

        data = list(keyset_id) + [mint_index] + [unit]
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x90 and sw2==0x00:
            index = response[0]
            return response, sw1, sw2, index

        # 9C06 SW_UNAUTHORIZED , 9C01 SW_NO_MEMORY_LEFT , 6700 SW_WRONG_LENGTH , 9C0F SW_INVALID_PARAMETER
        elif sw1==0x9C and sw2==0x06:
            raise PinRequiredError()
        elif sw1==0x9c and sw2==0x01:
            raise CardMemoryError()
        elif sw1==0x67 and sw2==0x00:
            raise CardWrongLengthError()
        elif sw1==0x9c and sw2==0x0F:
            raise CardInvalidParameter()
        elif sw1==0x9C and sw2==0x60:
            raise CardObjectAlreadyPresentError()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_import_keyset: {hex(256*sw1+sw2)}", sw1, sw2)


    def satocash_export_keysets(self, index_list: list[int]):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB5
        p1 = 0x00
        p2 = 0x00

        data = [len(index_list)]
        for index in index_list:
            data += [(index>>8), (index%256)]
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x90 and sw2==0x00:

            response_size = len(response)
            if response_size != 11*len(index_list):
                raise Exception(f"Wrong response length {response_size}, expected {11*len(index_list)}")

            keysets=[]
            keysets_dic = {}
            for pos,value in enumerate(index_list):
                i = pos*11
                keyset_index = response[i]
                keyset_id = bytes(response[(i+1):(i+9)])
                keyset_mint = response[i+9]
                keyset_unit = response[i+10]

                keysets += [{
                    'index':keyset_index,
                    'id': keyset_id,
                    'mint_index': keyset_mint,
                    'unit': keyset_unit
                }]

                keysets_dic[keyset_index] = {
                    'index':keyset_index,
                    'id': keyset_id,
                    'mint_index': keyset_mint,
                    'unit': keyset_unit
                }


            return response, sw1, sw2, keysets, keysets_dic

        # 9C06 SW_UNAUTHORIZED, 6700 SW_WRONG_LENGTH, 9C0F SW_INVALID_PARAMETER
        elif sw1==0x9C and sw2==0x06:
            raise PinRequiredError()
        elif sw1==0x67 and sw2==0x00:
            raise CardWrongLengthError()
        elif sw1==0x9c and sw2==0x0F:
            raise CardInvalidParameter()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_export_keysets: {hex(256*sw1+sw2)}", sw1, sw2)

    def satocash_remove_keyset(self, index: int):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB6
        p1 = index
        p2 = 0x00

        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x90 and sw2==0x00:
            return response, sw1, sw2

        # 9C06 SW_UNAUTHORIZED , 9C10 SW_INCORRECT_P1, 9C03 SW_OPERATION_NOT_ALLOWED
        elif sw1==0x9C and sw2==0x06:
            raise PinRequiredError()
        elif sw1==0x9c and sw2==0x0F:
            raise CardIncorrectP1()
        elif sw1==0x9c and sw2==0x03:
            raise CardOperationNotAllowed()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_remove_mint: {hex(256*sw1+sw2)}", sw1, sw2)

    def satocash_import_proof(self, keyset_index: int, amount_exponent: int, secret_bytes: bytes, unblinded_key_bytes: bytes, p2pk_path_bytes: bytes = b''):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB7
        p1 = 0x00
        p2 = 0x00

        # data: [keyset_index(1b) | amount_exponent(1b) | unblinded_key(33b) | secret(32b)]
        data = [keyset_index, amount_exponent] + list(unblinded_key_bytes) + list(secret_bytes) + list(p2pk_path_bytes)
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            index = 256*response[0] + response[1]
            return response, sw1, sw2, index

        # 9C06 SW_UNAUTHORIZED , 9C01 SW_NO_MEMORY_LEFT , 6700 SW_WRONG_LENGTH , 9C0F SW_INVALID_PARAMETER
        elif sw1 == 0x9C and sw2 == 0x06:
            raise PinRequiredError()
        elif sw1 == 0x9c and sw2 == 0x01:
            raise CardMemoryError()
        elif sw1 == 0x67 and sw2 == 0x00:
            raise CardWrongLengthError()
        elif sw1 == 0x9c and sw2 == 0x0F:
            raise CardInvalidParameter()
        elif sw1 == 0x9c and sw2 == 0x61:
            raise InvalidP2PKPathError()
        elif sw1 == 0x9c and sw2 == 0x62:
            raise ReusedP2PKPathError()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_import_proof: {hex(256 * sw1 + sw2)}", sw1, sw2)

    def satocash_export_proofs(self, index_list: list[int]):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB8
        p1 = 0x00
        p2 = JCconstants.OP_INIT

        #data (OP_INIT): [ proof_index_list_size(1b) | proof_index(2b) ... | 2FA_size(1b) | 2FA ]
        data = [len(index_list)]
        for index in index_list:
            data += [(index>>8), (index%256)]

        # todo: 2FA support

        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        proofs = []

        def parse_proofs_from_rapdu(response: list[int]):
            """ response format [proof_index(2b) | proof_state(1b) | keyset_index(1b) | amount_exponent(1b) | unblinded_key(33b) | secret(32b)]"""
            proof_list = []
            proof_dic = {}
            response_size= len(response)
            pos = 0
            while pos<response_size:
                proof_index= response[pos]*256 + response[pos+1]
                pos+=2
                proof_state = response[pos] & 0x03 # mask state to extract only the spent state
                use_p2pk = (response[pos] & 0x80 == 0x80) # flag is True if the proof is P2PK locked
                pos+=1
                keyset_index = response[pos]
                pos+=1
                proof_amount_exponent = response[pos]
                pos+=1
                unblindex_key_hex = bytes(response[pos:(pos + 33)]).hex()
                pos += 33
                proof_secret_hex = bytes(response[pos:(pos+32)]).hex()
                pos+=32

                dict= {
                    'index':proof_index,
                    'state':proof_state,
                    'use_p2pk': use_p2pk,
                    'keyset_index': keyset_index,
                    'amount': 2**proof_amount_exponent,
                    'secret_hex': proof_secret_hex,
                    'unblinded_key_hex': unblindex_key_hex
                }
                proof_list+=[dict]
                proof_dic[proof_index] = dict

            return proof_list, proof_dic

        # OP_INIT
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            proof_list, proof_dic = parse_proofs_from_rapdu(response)
            proofs += proof_list

        #9C06 SW_UNAUTHORIZED, 9C11 SW_INCORRECT_P2, 6700 SW_WRONG_LENGTH, 9C0F SW_INVALID_PARAMETER,
        elif sw1 == 0x9C and sw2 == 0x06:
            raise PinRequiredError()
        elif sw1 == 0x9c and sw2 == 0x11:
            raise CardIncorrectP2()
        elif sw1 == 0x67 and sw2 == 0x00:
            raise CardWrongLengthError()
        elif sw1 == 0x9c and sw2 == 0x0F:
            raise CardInvalidParameter()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_export_proofs: {hex(256 * sw1 + sw2)}", sw1, sw2)

        # OP_PROCESS
        p2 = JCconstants.OP_PROCESS
        while True:

            # check if all proofs have been recovered
            if len(proofs) == len(index_list):
                return proofs

            apdu = [cla, ins, p1, p2]
            response, sw1, sw2 = self.card_transmit(apdu)
            if sw1 == 0x90 and sw2 == 0x00:
                proof_list, proof_dic = parse_proofs_from_rapdu(response)
                proofs += proof_list

            # exceptions (OP_PROCESS): 9C06 SW_UNAUTHORIZED, 9C11 SW_INCORRECT_P2, 9C13 SW_INCORRECT_INITIALIZATION,
            elif sw1 == 0x9C and sw2 == 0x06:
                raise PinRequiredError()
            elif sw1 == 0x9c and sw2 == 0x11:
                raise CardIncorrectP2()
            elif sw1 == 0x9c and sw2 == 0x13:
                raise CardIncorrectInitialization()
            else:
                raise UnexpectedSW12Error(f"Unexpected error in satocash_export_proofs: {hex(256 * sw1 + sw2)}", sw1, sw2)


    def satocash_export_p2pk_sig(self, proof_index: int):
        cla = JCconstants.CardEdge_CLA
        ins = 0xBA
        p1 = 0x00
        p2 = 0x00

        # data: [index_start(2b) | index_size(2b)]
        data = [(proof_index >> 8), (proof_index % 256)]
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            # response: [pubkey_compressed(33b) | hash(32b) | p2pk_sig(64b)]
            pubkey = bytes(response[0:33])
            hash = bytes(response[33:65])
            sig = bytes(response[65:129])
            return pubkey, hash, sig

        # Exceptions: 9C06 SW_UNAUTHORIZED, 9C0F SW_INVALID_PARAMETER, 6700 SW_WRONG_LENGTH,
        elif sw1 == 0x9C and sw2 == 0x06:
            raise PinRequiredError()
        elif sw1 == 0x9c and sw2 == 0x0F:
            raise CardInvalidParameter()
        elif sw1 == 0x67 and sw2 == 0x00:
            raise CardWrongLengthError()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_get_proof_info: {hex(256 * sw1 + sw2)}", sw1, sw2)

    def satocash_get_proof_info(self, unit: int, info_type: int, index_start: int, index_size: int):
        cla = JCconstants.CardEdge_CLA
        ins = 0xB9
        p1 = unit
        p2 = info_type

        # data: [index_start(2b) | index_size(2b)]
        data = [(index_start>>8), (index_start%256)] + [(index_size>>8), (index_size%256)]
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            return response, sw1, sw2

        # Exceptions: 9C06 SW_UNAUTHORIZED, 9C0F SW_INVALID_PARAMETER, 6700 SW_WRONG_LENGTH,
        elif sw1 == 0x9C and sw2 == 0x06:
            raise PinRequiredError()
        elif sw1 == 0x9c and sw2 == 0x0F:
            raise CardInvalidParameter()
        elif sw1 == 0x67 and sw2 == 0x00:
            raise CardWrongLengthError()
        else:
            raise UnexpectedSW12Error(f"Unexpected error in satocash_get_proof_info: {hex(256 * sw1 + sw2)}", sw1, sw2)

    def satocash_get_bip32_extendedkey(self):
        ''' Get the next BIP32 extended key for p2pk proofs in Satocash.
        The path used for derivation is based on a 4-byte counter managed internally by the Satocash and incremented at the start of each call.
        The BIP32 masterseed is generated randomly internally by the Satocash and never exported.

        Returns: counter(4b), pubkey_compressed(33b)
        '''

        logger.debug("In satocash_get_bip32_extendedkey")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_BIP32_GET_EXTENDED_KEY
        p1 = 0x00
        p2 = 0x00
        data = []
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        (response, sw1, sw2) = self.card_transmit(apdu)
        if sw1 == 0x9C and sw2 == 0x06:
            raise PinRequiredError()
        elif sw1 == 0x9c and sw2 == 0x0F:
            raise CardInvalidParameter()
        elif (sw1 != 0x90) or (sw2 != 0x00):
            raise UnexpectedSW12Error(f"Unexpected error in satocash_get_proof_info: {hex(256 * sw1 + sw2)}", sw1, sw2)

        # parse response
        # response: [ counter(4b) | pubkey(65b) | sig_size(2b) | self-sig | sig_size(2b) | authentikey-sig]
        if len(response) < 73:
            raise UnexpectedSW12Error(
                f"Truncated response in satocash_get_bip32_extendedkey: {len(response)} bytes", sw1, sw2)
        counter = response[0:4]
        pubkey_uncompressed = response[4:69]

        # The authentikey signature covers everything up to its own length
        # field, i.e. counter, pubkey and the self-signature -- the convention
        # used by every signed response in both applets (sign over buffer[0..offset)
        # before appending sign_size||sig). The self-signature proves nothing to
        # a man in the middle, who can simply sign with their own key; the
        # authentikey one is what binds this key to this card.
        msg_size= 69
        sig_size= (response[msg_size]<<8) + response[msg_size+1]
        msg2_size= msg_size + 2 + sig_size
        if sig_size==0:
            raise ValueError("Signature missing")
        if len(response) < msg2_size+2:
            raise UnexpectedSW12Error(
                f"Truncated response in satocash_get_bip32_extendedkey: {len(response)} bytes", sw1, sw2)
        sig2_size= (response[msg2_size]<<8) + response[msg2_size+1]
        if sig2_size==0:
            raise ValueError("Signature missing")
        sig2= response[(msg2_size+2):(msg2_size+2+sig2_size)]
        self.parser.verify_signature(response[0:msg2_size], sig2, self.parser.authentikey)

        # only compress a point that is actually on the curve: the compressed
        # form keeps just x, so an invalid y would otherwise go unnoticed
        ECPubkey(bytes(pubkey_uncompressed))

        pubkey_compressed = pubkey_uncompressed[0:33]
        if pubkey_uncompressed[64]%2 == 0:
            pubkey_compressed[0] = 0x02
        else:
            pubkey_compressed[0] = 0x03

        return bytes(counter), bytes(pubkey_compressed)

    #################################
    #           PERSO PKI           #        
    #################################    
    def card_export_perso_pubkey(self):
        logger.debug("In card_export_perso_pubkey")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_EXPORT_PKI_PUBKEY
        p1= 0x00
        p2= 0x00
        apdu=[cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x6D and sw2==0x00):
            logger.error(f"Error during personalization pubkey export: command unsupported(0x6D00")
            raise CardError(f"Error during personalization pubkey export: command unsupported (0x6D00)")
        else: 
            logger.error(f"Error during personalization pubkey export (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Error during personalization pubkey export (error code {hex(256*sw1+sw2)})", sw1, sw2)
        return response

    def card_import_perso_certificate(self, cert):
        ''' Import a personalisation certificate into the device.

        Parameters:
        the device certificate (base64 encoded)

        '''
        logger.debug("In card_import_perso_certificate")
        cert = list(base64.b64decode(cert))

        # data is cut into chunks, each processed in a different APDU call
        buffer_offset = 0
        buffer_left = len(cert)

        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_IMPORT_PKI_CERTIFICATE
        p1 = 00
        p2 = JCconstants.OP_INIT
        #data(init): [full_size(2b)]
        data = list(buffer_left.to_bytes(2, byteorder='big', signed=False))
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        (response, sw1, sw2) = self.card_transmit(apdu)
        if (sw1==0x9c and sw2==0x40):
            logger.error("Error: Card PKI Already Locked")

        while buffer_left > 0:
            # cla= JCconstants.CardEdge_CLA
            # ins= INS_IMPORT_PKI_CERTIFICATE
            # p1= 00
            p2 = JCconstants.OP_PROCESS
            #data(update): [chunk_offset(2b) | chunk_size(2b) | chunk_data ]
            data = []
            data += list(buffer_offset.to_bytes(2, byteorder='big', signed=False))
            chunk_size = min(128, buffer_left)
            data += list(chunk_size.to_bytes(2, byteorder='big', signed=False))
            data += cert[buffer_offset:(buffer_offset + chunk_size)]
            lc = len(data)
            apdu = [cla, ins, p1, p2, lc] + data
            buffer_offset += chunk_size
            buffer_left -= chunk_size
            response, sw1, sw2 = self.card_transmit(apdu)
            if sw1!=0x90 or sw2!=0x00:
                logger.error("APDU Send Failed")
                break

        return

    def card_export_perso_certificate(self):
        logger.debug("In card_export_perso_certificate")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_EXPORT_PKI_CERTIFICATE
        p1= 0x00
        p2= 0x01 #init
        
        #init
        apdu=[cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x6D and sw2==0x00):
            logger.error(f"Error during personalization certificate export: command unsupported(0x6D00)")
            raise CardError(f"Error during personalization certificate export: command unsupported (0x6D00)")
        elif (sw1==0x00 and sw2==0x00):
            logger.error(f"Error during personalization certificate export: no card present(0x0000)")
            raise CardNotPresentError(f"Error during personalization certificate export: no card present (0x0000)")
        else: 
            logger.error(f"Error during personalization certificate export: (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Error during personalization certificate export: (error code {hex(256*sw1+sw2)})", sw1, sw2)
        
        certificate_size= (response[0] & 0xFF)*256 + (response[1] & 0xFF)
        if (certificate_size==0):
            return "(empty)"
                
        # UPDATE apdu: certificate data in chunks
        p2= 0x02 #update
        certificate= certificate_size*[0]
        chunk_size=128;
        chunk=[]
        remaining_size= certificate_size;
        cert_offset=0;
        while(remaining_size>128):
            # data=[ chunk_offset(2b) | chunk_size(2b) ]
            data= [ ((cert_offset>>8)&0xFF), (cert_offset&0xFF) ]
            data+= [ 0,  (chunk_size & 0xFF) ] 
            apdu=[cla, ins, p1, p2, len(data)]+data
            response, sw1, sw2 = self.card_transmit(apdu)
            certificate[cert_offset:(cert_offset+chunk_size)]=response[0:chunk_size]
            remaining_size-=chunk_size;
            cert_offset+=chunk_size;
        
        # last chunk
        data= [ ((cert_offset>>8)&0xFF), (cert_offset&0xFF) ]
        data+= [ 0,  (remaining_size & 0xFF) ] 
        apdu=[cla, ins, p1, p2, len(data)]+data
        response, sw1, sw2 = self.card_transmit(apdu)
        certificate[cert_offset:(cert_offset+remaining_size)]=response[0:remaining_size]    
        
        # parse and return raw certificate
        self.cert_pem= self.parser.convert_bytes_to_string_pem(certificate)
        return self.cert_pem

    def card_import_ndef_authentikey(self, ndef_authentikey_bytes: bytes):
        logger.debug("In card_import_ndef_authentikey")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_IMPORT_PKI_NDEF_AUTHENTIKEY
        p1 = 0x00
        p2 = 0x00

        if len(ndef_authentikey_bytes) != 32:
           raise Exception(f"Error in card_import_ndef_authentikey: wrong privkey length {len(ndef_authentikey_bytes)} instead of {32}")

        apdu=[cla, ins, p1, p2, len(ndef_authentikey_bytes)] + list(ndef_authentikey_bytes)
        response, sw1, sw2 = self.card_transmit(apdu)

        return response, sw1, sw2

    def card_challenge_response_pki(self, pubkey):
        logger.debug("In card_challenge_response_pki")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CHALLENGE_RESPONSE_PKI
        p1= 0x00
        p2= 0x00
        
        challenge_from_host= urandom(32)
        
        apdu=[cla, ins, p1, p2, len(challenge_from_host)]+ list(challenge_from_host)
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # verify challenge-response
        verif= self.parser.verify_challenge_response_pki(response, challenge_from_host, pubkey)
        
        return verif;
    
    def card_verify_authenticity(self, backend: str = "auto"):
        logger.debug('In card_verify_authenticity')
        
        # get certificate from device
        txt_ca = txt_subca = txt_device = "(empty)"
        cert_pem=txt_error=""
        try:
            cert_pem=self.card_export_perso_certificate()
            logger.debug('Cert PEM: '+ str(cert_pem))
        except CardError as ex:
            txt_error= ''.join(["Unable to get device certificate: feature unsupported! \n", 
                                "Authenticity validation is only available starting with Satochip v0.12 and higher"])
        except CardNotPresentError as ex:
            txt_error= "No card found! Please insert card."
        except UnexpectedSW12Error as ex:
            txt_error= "Exception during device certificate export: " + str(ex)
        
        if cert_pem=="(empty)":
            txt_error= "Device certificate is empty: the card has not been personalized!"
        
        if txt_error!="":
            return False, txt_ca, txt_subca, txt_device, txt_error

        # Perform some checks on the certificate
        validator = CertificateValidator(backend=backend)

        # Check that the certificate subject matches the device serial number
        cert_dict =  validator.parse_pem_certificate(cert_pem)
        subject_dict= cert_dict['subject']
        logger.debug(f'In card_verify_authenticity subject_dict= {subject_dict}')
        subject= subject_dict.get(b'CN', None).decode('utf-8')
        logger.debug(f'In card_verify_authenticity subject= {subject}')
        logger.debug(f'In card_verify_authenticity UID_SHA1= {self.UID_SHA1}')
        if subject.lower() != self.UID_SHA1.lower():
            txt_error= f"Certificate subject {subject} does not match the card serial number {self.UID_SHA1}!"
            return False, txt_ca, txt_subca, txt_device, txt_error

        ## check the certificate chain from root CA to device
        is_valid_chain, device_pubkey, txt_ca, txt_subca, txt_device, txt_error= validator.validate_certificate_chain(cert_pem, self.card_type)
        if not is_valid_chain:
            return False, txt_ca, txt_subca, txt_device, txt_error
        
        # perform challenge-response with the card to ensure that the key is correctly loaded in the device
        is_valid_chalresp, txt_error = self.card_challenge_response_pki(device_pubkey)
        if not is_valid_chalresp:
            return False, txt_ca, txt_subca, txt_device, txt_error

        return True, txt_ca, txt_subca, txt_device, txt_error
    
    #################################
    #            SATODIME           #
    #################################
    
    def satodime_set_unlock_secret(self, unlock_secret=[]):
        if unlock_secret==[]:
            # No secret known: the all-zero placeholder must not be mistaken for
            # one, or every unlock code would be computed from zeros while the
            # client believed it was the owner.
            unlock_secret= SIZE_UNLOCK_SECRET*[0x00]
            self.is_owner= False
        else:
            self.is_owner= True
        self.unlock_secret=unlock_secret
    def satodime_set_unlock_counter(self, unlock_counter=[]):
        if unlock_counter==[]:
            unlock_counter= SIZE_UNLOCK_COUNTER*[0x00]
        self.unlock_counter=unlock_counter
    def satodime_increment_unlock_counter(self):
        counter_int= int.from_bytes( self.unlock_counter, byteorder='big', signed=False)
        counter_int+=1
        self.unlock_counter= list( counter_int.to_bytes(4, byteorder='big', signed=False))
        
    def satodime_get_status(self):
        """Return status info specific to Satodime"""
        logger.debug("In satodime_get_status")
        cla= JCconstants.CardEdge_CLA
        ins= 0x50
        p1= 0x00
        p2= 0x00
        apdu=[cla, ins, p1, p2]
        (response, sw1, sw2)= self.card_transmit(apdu)
        
        if (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x00 and sw2==0x00):
            logger.error(f"Error while fetching Satodime status: no card present (code 0x0000)")
            raise CardNotPresentError(f"Error while fetching Satodime status: no card present (code 0x0000)")
        elif (sw1==0x9c and sw2==0x04):
            logger.error(f"Error while fetching Satodime status: setup not done (code 0x0000)")
            raise CardSetupNotDoneError(f"Error while fetching Satodime status: setup not done (code 0x9c04)")
        else: 
            logger.error(f"Error while fetching Satodime status: (error code {hex(256*sw1+sw2)})")
            raise UnexpectedSW12Error(f"Error while fetching Satodime status: (error code {hex(256*sw1+sw2)})", sw1, sw2)
        
        offset=0
        satodime_status={}
        satodime_status['unlock_counter']= response[offset:(offset+SIZE_UNLOCK_COUNTER)]
        self.unlock_counter=satodime_status['unlock_counter']
        offset+=SIZE_UNLOCK_COUNTER
        satodime_status['max_num_keys']= response[offset]
        offset+=1
        satodime_status['satodime_keys_status']=  response[offset:]
        return (response, sw1, sw2, satodime_status)
        # max_num_keys= response[0]
        # satodime_keys_status= response[1:]
        # return (response, sw1, sw2, max_num_keys, satodime_keys_status)
        
    def satodime_get_keyslot_status(self, key_nbr: int):
        logger.debug("In satodime_get_keyslot_status")
        cla= JCconstants.CardEdge_CLA
        ins= 0x51
        p1= (key_nbr%256)
        p2= 0x00
        apdu=[cla, ins, p1, p2]
        
        (response, sw1, sw2)= self.card_transmit(apdu)
        
        if (sw1==0x90 and sw2==0x00):
            pass
        elif (sw1==0x00 and sw2==0x00):
            logger.error(f"Error while fetching Satodime key {key_nbr} status: no card present (code 0x0000)")
            raise CardNotPresentError(f"Error while fetching Satodime key {key_nbr} status: no card present (code 0x0000)")
        
        # parse info
        keyslot_status= self.parser.parse_satodime_get_keyslot_status(response)
        return (response, sw1, sw2, keyslot_status)
        
    def satodime_set_keyslot_status_part0(self, key_nbr: int, RFU1:int, RFU2:int, key_asset:int, key_slip44, key_contract, key_tokenid):
        
        logger.debug("In satodime_set_keyslot_status")
        cla= JCconstants.CardEdge_CLA
        ins= 0x52
        p1= (key_nbr%256)
        p2= 0x00
        datasize= SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID
        apduheader=[cla, ins, p1, p2, datasize]
        
        if key_slip44==[]: key_slip44= [0x80, 0x00, 0x00, 0x00]
        if key_contract==[]: key_contract= SIZE_CONTRACT*[0x00]
        if key_tokenid==[]: key_tokenid= SIZE_TOKENID*[0x00]
        if type(key_slip44) is bytes: key_slip44= list(key_slip44)
        if type(key_contract) is bytes: key_contract= list(key_contract)
        if type(key_tokenid) is bytes: key_tokenid= list(key_tokenid)
        
        # compute unlock_code
        unlock_code= list( hmac.new(bytes(self.unlock_secret), bytes(apduheader+ self.unlock_counter), hashlib.sha1).digest() )
        
        data= self.unlock_counter + unlock_code + [RFU1%256, RFU2%256, (key_asset%256)] + key_slip44 + key_contract + key_tokenid
        if len(data) != datasize:
           raise Exception(f"Error in satodime_set_keyslot_status: wrong status length {len(data)} instead of {datasize}")
        apdu=apduheader+data
        
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.debug(f"In satodime_set_keyslot_status_part0 error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2

        self.satodime_increment_unlock_counter() 
        
        return (response, sw1, sw2)
        
    def satodime_set_keyslot_status_part1(self, key_nbr: int, key_data):
        
        logger.debug("In satodime_set_keyslot_status")
        cla= JCconstants.CardEdge_CLA
        ins= 0x52
        p1= (key_nbr%256)
        p2= 0x01
        datasize= SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_DATA
        apduheader=[cla, ins, p1, p2, datasize]
        
        if key_data==[]: key_data= SIZE_DATA*[0x00]
        if type(key_data) is bytes: key_data= list(key_data)
        
        # compute unlock_code
        unlock_code= list( hmac.new(bytes(self.unlock_secret), bytes(apduheader+ self.unlock_counter), hashlib.sha1).digest() )
        
        data= self.unlock_counter + unlock_code + key_data
        if len(data) != datasize:
           raise Exception(f"Error in satodime_set_keyslot_status: wrong status length {len(data)} instead of {datasize}")
        apdu=apduheader+data
        
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.debug(f"In satodime_set_keyslot_status_part1 error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2

        self.satodime_increment_unlock_counter() 
        
        return (response, sw1, sw2)  
        
    def satodime_get_pubkey(self, key_nbr: int):
        logger.debug("In satodime_get_pubkey")
        cla= JCconstants.CardEdge_CLA
        ins= 0x55
        p1= (key_nbr%256)
        p2= 0x00
    
        apdu=[cla, ins, p1, p2]
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            # never parse an error payload; same shape as satodime_seal_key(),
            # satodime_unseal_key() and satodime_get_privkey(), which all check
            # this already
            logger.debug(f"In satodime_get_pubkey error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2, [], []

        if self.parser.authentikey is None: # Need to cache the pubkey if this hasn't been done already
            self.card_export_authentikey()
        
        # parse answer
        (pubkey_list, pubkey_comp_list, sig_list)= self.parser.parse_satodime_get_pubkey(response)
        
        return (response, sw1, sw2, pubkey_list, pubkey_comp_list)
        
    def satodime_get_privkey(self, key_nbr: int):
        logger.debug("In satodime_get_privkey")
        cla= JCconstants.CardEdge_CLA
        ins= 0x56
        p1= (key_nbr%256)
        p2= 0x00
        datasize= SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE
        apduheader=[cla, ins, p1, p2, datasize]
        
        # compute unlock_code or use default
        unlock_code= list( hmac.new(bytes(self.unlock_secret), bytes(apduheader+ self.unlock_counter), hashlib.sha1).digest() )
               
        data= self.unlock_counter + unlock_code
        if len(data) != datasize:
            raise Exception(f"Error in satodime_get_privkey: wrong data length {len(data)} instead of {datasize}")
        apdu=apduheader+data
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.debug(f"In satodime_get_privkey error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2, [], []

        self.satodime_increment_unlock_counter()

        if self.parser.authentikey is None:  # Need to cache the pubkey if this hasn't been done already
            self.card_export_authentikey()

        # parse answer
        (entropy_list, privkey_list, sig_list) = self.parser.parse_satodime_get_privkey(response, key_nbr)

        return response, sw1, sw2, entropy_list, privkey_list


    def satodime_seal_key(self, key_nbr: int, entropy_user):
    
        logger.debug("In satodime_seal_key")
        cla= JCconstants.CardEdge_CLA
        ins= 0x57
        p1= (key_nbr%256)
        p2= 0x00
        datasize= SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_ENTROPY
        apduheader=[cla, ins, p1, p2, datasize]
        
        if type(entropy_user) is bytes: entropy_user= list(entropy_user)
        
        # compute unlock_code
        unlock_code= list( hmac.new(bytes(self.unlock_secret), bytes(apduheader+ self.unlock_counter), hashlib.sha1).digest() )
                  
        data= self.unlock_counter + unlock_code + entropy_user
        if len(data) != datasize:
            raise Exception(f"Error in satodime_seal_key: wrong data length {len(data)} instead of {datasize}")
        apdu=apduheader+data
        
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.debug(f"In satodime_seal_key error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2, [], []

        self.satodime_increment_unlock_counter()

        if self.parser.authentikey is None:  # Need to cache the pubkey if this hasn't been done already
            self.card_export_authentikey()
        # parse answer
        (pubkey_list, pubkey_comp_list, sig_list)= self.parser.parse_satodime_get_pubkey(response)
        
        return (response, sw1, sw2, pubkey_list, pubkey_comp_list)
        
    def satodime_unseal_key(self, key_nbr: int):
        logger.debug("In satodime_unseal_key")
        cla= JCconstants.CardEdge_CLA
        ins= 0x58
        p1= (key_nbr%256)
        p2= 0x00
        datasize= SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE
        apduheader=[cla, ins, p1, p2, datasize]
        
        # compute unlock_code
        unlock_code= list( hmac.new(bytes(self.unlock_secret), bytes(apduheader+ self.unlock_counter), hashlib.sha1).digest() )
        
        data= self.unlock_counter + unlock_code
        if len(data) != datasize:
            raise Exception(f"Error in satodime_unseal_key: wrong data length {len(data)} instead of {datasize}")
        apdu=apduheader+data
        
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.debug(f"In satodime_unseal_key error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2, [], []

        self.satodime_increment_unlock_counter()

        if self.parser.authentikey is None: # Need to cache the pubkey if this hasn't been done already
            self.card_export_authentikey()

        # parse answer
        (entropy_list, privkey_list, sig_list)= self.parser.parse_satodime_get_privkey(response, key_nbr)
        
        return response, sw1, sw2, entropy_list, privkey_list
    
    def satodime_reset_key(self, key_nbr: int):
        logger.debug("In satodime_reset_key")
        cla= JCconstants.CardEdge_CLA
        ins= 0x59
        p1= (key_nbr%256)
        p2= 0x00
        datasize= SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE
        apduheader=[cla, ins, p1, p2, datasize]

        # compute unlock_code
        unlock_code= list( hmac.new(bytes(self.unlock_secret), bytes(apduheader+ self.unlock_counter), hashlib.sha1).digest() )
        
        data= self.unlock_counter + unlock_code
        if len(data) != datasize:
            raise Exception(f"Error in satodime_unseal_key: wrong data length {len(data)} instead of {datasize}")
        apdu=apduheader+data
        
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.debug(f"In satodime_unseal_key error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2

        self.satodime_increment_unlock_counter()

        return response, sw1, sw2
    
    def satodime_initiate_ownership_transfer(self):
        
        logger.debug("In satodime_initiate_ownership_transfer")
        cla= JCconstants.CardEdge_CLA
        ins= 0x5A
        p1= 0x00
        p2= 0x00
        datasize= SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE
        apduheader=[cla, ins, p1, p2, datasize]
        
        # compute unlock_code
        unlock_code= list( hmac.new(bytes(self.unlock_secret), bytes(apduheader+ self.unlock_counter), hashlib.sha1).digest() )
                
        data=self.unlock_counter +  unlock_code
        apdu= apduheader+data
        (response, sw1, sw2)= self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            logger.warning(f"In satodime_initiate_ownership_transfer error {hex(sw1 * 256 + sw2)}")
            return response, sw1, sw2

        self.satodime_increment_unlock_counter() 
        
        return response, sw1, sw2
    
    #################################
    #            HELPERS            #        
    ################################# 
    
    #deprecated: since satochip applet v0.12, authentikey is generated once at initialization and does not derive from the seed
    def get_authentikey_from_masterseed(self, masterseed):
        # compute authentikey locally from masterseed
        # authentikey privkey is first 32 bytes of HmacSha512('Bitcoin seed2', masterseed)
        bytekey= bytes('Bitcoin seed2', 'utf8') #b'Bitcoin seed2'
        byteseed= bytes(masterseed)
        mac= hmac.new(bytekey, byteseed, hashlib.sha512).digest()[0:32]
        priv= ECPrivkey(mac)
        pub= priv.get_public_key_bytes(True)
        pub_hex= pub.hex()
        logger.debug('Authentikey_local= ' + pub_hex)
        
        return pub_hex


    #################################
    #         CARD  ERRORS          #
    ################################# 
    
class ApduError(Exception):
    def __init__(self, message="", sw1=0x00, sw2=0x00, ins=0x00):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2= sw2
        self.ins= ins

# Generic
class CardSelectError(ApduError):
    def __init__(self, message="", ins=0x00):
        super().__init__(message, 0x6A, 0x82, ins)

class CardSetupNotDoneError(ApduError):
    def __init__(self, message="Card setup not done!", ins=0x00):
        super().__init__(message, 0x9c, 0x04, ins)

class IncorrectP1Error(ApduError):
    def __init__(self, message="", ins=0x00):
        super().__init__(message, 0x9c, 0x10, ins)

class UnsupportedFeatureError(ApduError):
    def __init__(self, message="Unsupported feature!", ins=0x00):
        super().__init__(message, 0x6d, 0x00, ins)

# Satodime
class UnknownProtocolMediaError(ApduError):
    def __init__(self, message="", ins=0x00):
        super().__init__(message, 0x9c, 0x54, ins)

class IncorrectProtocolMediaError(ApduError):
    def __init__(self, message="", ins=0x00):
        super().__init__(message, 0x9c, 0x53, ins)

class IncorrectKeyslotStateError(ApduError):
    def __init__(self, message="", ins=0x00):
        super().__init__(message, 0x9c, 0x52, ins)

class IncorrectUnlockCodeError(ApduError):
    def __init__(self, message="", ins=0x00):
        super().__init__(message, 0x9c, 0x51, ins)

class IncorrectUnlockCounterError(ApduError):
    def __init__(self, message="", ins=0x00):
        super().__init__(message, 0x9c, 0x50, ins)

# Satocash
class InvalidP2PKPathError(ApduError):
    def __init__(self, message="Invalid key derivation path for P2PK proof", ins=0x00):
        super().__init__(message, 0x9c, 0x61, ins)

class ReusedP2PKPathError(ApduError):
    def __init__(self, message="Key derivation path for P2PK proof has already been used", ins=0x00):
        super().__init__(message, 0x9c, 0x62, ins)

class AuthenticationError(Exception):
    """Raised when the command requires authentication first"""
    pass

class IdentityBlockedError(Exception):
    """Raised when a PIN or PUK is blocked after to many wrong atempts"""
    pass

class UninitializedSeedError(Exception):
    """Raised when the device is not yet seeded"""
    pass

#TODO: set sw1 and sw2 arguments in call!
class UnexpectedSW12Error(Exception):
    """Raised when the device returns an unexpected error code"""
    def __init__(self, message, sw1=0x00, sw2=0x00):            
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw12hex = hex(sw1*256+sw2)

class PinRequiredError(Exception):
    """Raised when the device needs a correct PIN to continue"""
    pass

class WrongPinError(Exception):
    """Raised when the provided PIN code is wrong"""
    def __init__(self, message, pin_left):            
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.pin_left = pin_left

class PinBlockedError(Exception):
    """Raised when the card PIN is blocked"""
    pass

class CardResetToFactoryError(Exception):
    """Raised when the card has been reset to factory"""
    pass

class CardError(Exception):
    """Raised when the device returns an error code"""
    pass

class CardNotPresentError(Exception):
    """Raised when the device returns an error code"""
    pass

class SeedKeeperError(Exception):
    """Raised when an error is returned by the SeedKeeper"""
    pass   
    
class CardMemoryError(Exception):
    """Raised when there is not enough memory in the card"""
    def __init__(self, message="Not enough memory available"):
        super().__init__(message)
        self.sw1 = 0x9c
        self.sw2 = 0x01
        self.sw12hex = hex(256 * self.sw1 + self.sw2)

class CardWrongLengthError(Exception):
    """Raised when data provided to card has not the expected length"""
    def __init__(self, message="Wrong length error"):
        super().__init__(message)
        self.sw1 = 0x67
        self.sw2 = 0x00
        self.sw12hex = hex(256*self.sw1 + self.sw2)

class CardInvalidParameter(Exception):
    """Raised when data provided to card is not valid"""
    def __init__(self, message="Data provided to card is invalid"):
        super().__init__(message)
        self.sw1 = 0x9c
        self.sw2 = 0x0f
        self.sw12hex = hex(256*self.sw1 + self.sw2)

class CardIncorrectP1(Exception):
    """Raised when APDU P1 parameter provided to card is not valid"""
    def __init__(self, message="P1 parameter provided to card is invalid"):
        super().__init__(message)
        self.sw1 = 0x9c
        self.sw2 = 0x10
        self.sw12hex = hex(256 * self.sw1 + self.sw2)

class CardIncorrectP2(Exception):
    """Raised when APDU P2 parameter provided to card is not valid"""
    def __init__(self, message="P2 parameter provided to card is invalid"):
        super().__init__(message)
        self.sw1 = 0x9c
        self.sw2 = 0x11
        self.sw12hex = hex(256 * self.sw1 + self.sw2)

class CardOperationNotAllowed(Exception):
    """Raised when a requested operation is not allowed by the card for various reasons"""
    def __init__(self, message="Operation is not allowed by the card policy"):
        super().__init__(message)
        self.sw1 = 0x9c
        self.sw2 = 0x03
        self.sw12hex = hex(256 * self.sw1 + self.sw2)

class CardIncorrectInitialization(Exception):
    """Raised when multiple commands for an instruction are not requested in the correct order"""
    def __init__(self, message="Incorrect initialization of operations"):
        super().__init__(message)
        self.sw1 = 0x9c
        self.sw2 = 0x13
        self.sw12hex = hex(256 * self.sw1 + self.sw2)

class CardObjectAlreadyPresentError(Exception):
    """Raised when object imported to the card is already present"""
    def __init__(self, message="Imported object is already present"):
        super().__init__(message)
        self.sw1 = 0x9c
        self.sw2 = 0x60
        self.sw12hex = hex(256*self.sw1 + self.sw2)


if __name__ == "__main__":

    cardconnector= CardConnector()
    cardconnector.card_get_ATR()
    cardconnector.card_select()
    #cardconnector.card_setup()
    cardconnector.card_bip32_get_authentikey()
    #cardconnector.card_bip32_get_extendedkey()
    cardconnector.card_disconnect()
