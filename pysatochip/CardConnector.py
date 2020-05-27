from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.util import toHexString, toBytes
from smartcard.sw.SWExceptions import SWException

from .JCconstants import JCconstants
from .CardDataParser import CardDataParser
from .TxParser import TxParser
from .ecc import ECPubkey, msg_magic
from .SecureChannel import SecureChannel
    
import base64
import logging 
from os import urandom


#debug
import sys
import traceback

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

MSG_WARNING= ("Before you request bitcoins to be sent to addresses in this "
                    "wallet, ensure you can pair with your device, or that you have "
                    "its seed (and passphrase, if any).  Otherwise all bitcoins you "
                    "receive will be unspendable.")
                    
MSG_USE_2FA= ("Do you want to use 2-Factor-Authentication (2FA)?\n\n"
                "With 2FA, any transaction must be confirmed on a second device such as \n"
               "your smartphone. First you have to install the Satochip-2FA android app on \n"
               "google play. Then you have to pair your 2FA device with your Satochip \n"
               "by scanning the qr-code on the next screen. \n"
               "Warning: be sure to backup a copy of the qr-code in a safe place, \n"
               "in case you have to reinstall the app!")
               
# simple observer that will print on the console the card connection events.
class LogCardConnectionObserver(CardConnectionObserver):
    def update( self, cardconnection, ccevent ):
        if 'connect'==ccevent.type:
            logger.info( 'connecting to' + repr(cardconnection.getReader()) )
        elif 'disconnect'==ccevent.type:
            logger.info( 'disconnecting from' + repr(cardconnection.getReader()) )
        elif 'command'==ccevent.type:
            if (ccevent.args[0][1] in (JCconstants.INS_SETUP, JCconstants.INS_SET_2FA_KEY,
                                        JCconstants.INS_BIP32_IMPORT_SEED, JCconstants.INS_BIP32_RESET_SEED,
                                        JCconstants.INS_CREATE_PIN, JCconstants.INS_VERIFY_PIN,
                                        JCconstants.INS_CHANGE_PIN, JCconstants.INS_UNBLOCK_PIN)):
                logger.info(f"> {toHexString(ccevent.args[0][0:5])}{(len(ccevent.args[0])-5)*' *'}")
            else:
                logger.info(f"> {toHexString(ccevent.args[0])}")
        elif 'response'==ccevent.type:
            if []==ccevent.args[0]:
                logger.info( f'< [] {toHexString(ccevent.args[-2:])}')
            else:
                logger.info( f'< {toHexString(ccevent.args[0])} {toHexString(ccevent.args[-2:])}')

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
            #TODO check ATR and check if more than 1 card?
            logger.info(f"+Inserted: {toHexString(card.atr)}")
            self.cc.card_present= True
            self.cc.cardservice= card
            self.cc.cardservice.connection = card.createConnection()
            self.cc.cardservice.connection.connect()
            self.cc.cardservice.connection.addObserver(self.observer)
            try:
                (response, sw1, sw2) = self.cc.card_select()
                if sw1!=0x90 or sw2!=0x00:
                    self.cc.card_disconnect()
                    break
                (response, sw1, sw2, status)= self.cc.card_get_status()
                if (sw1!=0x90 or sw2!=0x00) and (sw1!=0x9C or sw2!=0x04):
                    self.cc.card_disconnect()
                    break
                if (self.cc.needs_secure_channel):
                    self.cc.card_initiate_secure_channel()
                    
            except Exception as exc:
                logger.info(f"Error during connection: {repr(exc)}")
            if self.cc.client:
                self.cc.client.request('update_status',True)                
                
        for card in removedcards:
            logger.info(f"-Removed: {toHexString(card.atr)}")
            self.cc.card_disconnect()
                

class CardConnector:

    # Satochip supported version tuple
    # v0.4: getBIP32ExtendedKey also returns chaincode
    # v0.5: Support for Segwit transaction
    # v0.6: bip32 optimization: speed up computation during derivation of non-hardened child
    # v0.7: add 2-Factor-Authentication (2FA) support
    # v0.8: support seed reset and pin change
    # v0.9: patch message signing for alts
    # v0.10: sign tx hash
    # v0.11: support for (mandatory) secure channel
    SATOCHIP_PROTOCOL_MAJOR_VERSION=0
    SATOCHIP_PROTOCOL_MINOR_VERSION=11
    SATOCHIP_PROTOCOL_VERSION= (SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+SATOCHIP_PROTOCOL_MINOR_VERSION
    SATOCHIP_LIB_REVISION= 'a'
    
    # define the apdus used in this script
    BYTE_AID= [0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70] #SatoChip

    def __init__(self, client=None, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.info(f"Logging set to level: {str(loglevel)}")
        logger.debug("In __init__")
        self.logger= logger
        self.parser=CardDataParser(loglevel)
        self.client=client
        self.client.cc=self
        self.cardtype = AnyCardType() #TODO: specify ATR to ignore connection to wrong card types?
        self.needs_2FA = None
        self.is_seeded= None
        self.setup_done= None
        self.needs_secure_channel= None
        self.sc = None
        # cache PIN
        self.pin_nbr=None
        self.pin=None
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
     
    ###########################################
    #                   Applet management                        #
    ###########################################
    
    # def card_transmit_old(self, plain_apdu):
        # if self.card_present:
            # try:
                # #encrypt apdu
                # ins= plain_apdu[1]
                # if (self.needs_secure_channel) and (ins not in [0xA4, 0x81, 0x82, JCconstants.INS_GET_STATUS]):
                    # logger.info("Plaintext C-APDU: "+str(toHexString(plain_apdu))) #TODO: mask sensitive info
                    # apdu = self.card_encrypt_secure_channel(plain_apdu)
                # else:
                    # apdu= plain_apdu
                    
                # # transmit apdu
                # (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)
                
                # #decrypt response
                # if (sw1==0x90) and (sw2==0x00):
                    # if (self.needs_secure_channel) and (ins not in [0xA4, 0x81, 0x82, JCconstants.INS_GET_STATUS]):
                        # response= self.card_decrypt_secure_channel(response)
                        # logger.info("Plaintext R-APDU: "+str(toHexString(response)))
                
                # # PIN authentication is required
                # if (sw1==0x9C) and (sw2==0x06):
                    # (response, sw1, sw2)= self.card_verify_PIN()
                    
                    # #reencrypt apdu
                    # if (self.needs_secure_channel) and (ins not in [0xA4, 0x81, 0x82, JCconstants.INS_GET_STATUS]):
                        # apdu = self.card_encrypt_secure_channel(plain_apdu)
                    # else:
                        # apdu= plain_apdu
                    # (response, sw1, sw2)= self.cardservice.connection.transmit(apdu)
                
                # return (response, sw1, sw2)
                
            # except Exception as exc:
                # logger.info(f"Error during connection:{repr(exc)} {traceback.format_exc()}")
                # self.client.request('show_error',"Error during connection:"+repr(exc))
                # return ([], 0x00, 0x00)
        # else:
            # self.client.request('show_error','No Satochip found! Please insert card!')
            # return ([], 0x00, 0x00)
            # #TODO return errror or throw exception?

    def card_transmit(self, plain_apdu):
        logger.debug("In card_transmit")
        while(self.card_present):
            try:
                #encrypt apdu
                ins= plain_apdu[1]
                if (self.needs_secure_channel) and (ins not in [0xA4, 0x81, 0x82, JCconstants.INS_GET_STATUS]):
                    apdu = self.card_encrypt_secure_channel(plain_apdu)
                else:
                    apdu= plain_apdu
                    
                # transmit apdu
                (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)
                
                # PIN authentication is required
                if (sw1==0x9C) and (sw2==0x06):
                    (response, sw1, sw2)= self.card_verify_PIN()
                #decrypt response
                elif (sw1==0x90) and (sw2==0x00):
                    if (self.needs_secure_channel) and (ins not in [0xA4, 0x81, 0x82, JCconstants.INS_GET_STATUS]):
                        response= self.card_decrypt_secure_channel(response)
                    return (response, sw1, sw2)
                else:
                    return (response, sw1, sw2)
                
            except Exception as exc:
                logger.warning(f"Error during connection: {repr(exc)}")
                self.client.request('show_error',"Error during connection:"+repr(exc))
                return ([], 0x00, 0x00)
        
        # no card present
        self.client.request('show_error','No Satochip found! Please insert card!')
        return ([], 0x00, 0x00)
        #TODO return errror or throw exception?
            
    def card_get_ATR(self):
        logger.debug('In card_get_ATR()')
        return self.cardservice.connection.getATR()
    
    def card_disconnect(self):
        logger.debug('In card_disconnect()')
        self.pin= None #reset PIN
        self.pin_nbr= None
        self.is_seeded= None
        self.needs_2FA = None
        self.setup_done= None
        self.needs_secure_channel= None
        self.card_present= False
        if self.cardservice:
            self.cardservice.connection.disconnect()
            self.cardservice= None
        if self.client:
            self.client.request('update_status',False)
        
    def get_sw12(self, sw1, sw2):
        return 16*sw1+sw2

    def card_select(self):
        logger.debug("In card_select")#debug
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08]
        apdu = SELECT + CardConnector.BYTE_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        
        #reset secure channel if needed
        if (self.needs_secure_channel): 
            self.card_initiate_secure_channel()
        return (response, sw1, sw2)

    def card_get_status(self):
        logger.debug("In card_get_status")#debug
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_GET_STATUS
        p1= 0x00
        p2= 0x00
        apdu=[cla, ins, p1, p2]
        (response, sw1, sw2)= self.card_transmit(apdu)
        d={}
        if (sw1==0x90) and (sw2==0x00):
            d["protocol_major_version"]= response[0]
            d["protocol_minor_version"]= response[1]
            d["applet_major_version"]= response[2]
            d["applet_minor_version"]= response[3]
            d["protocol_version"]= (d["protocol_major_version"]<<8)+d["protocol_minor_version"] 
            if len(response) >=8:
                d["PIN0_remaining_tries"]= response[4]
                d["PUK0_remaining_tries"]= response[5]
                d["PIN1_remaining_tries"]= response[6]
                d["PUK1_remaining_tries"]= response[7]
                self.needs_2FA= d["needs2FA"]= False #default value
            if len(response) >=9:
                self.needs_2FA= d["needs2FA"]= False if response[8]==0X00 else True
            if len(response) >=10:
                self.is_seeded= d["is_seeded"]= False if response[9]==0X00 else True
            if len(response) >=11:
	                self.setup_done= d["setup_done"]= False if response[10]==0X00 else True    
            else:
                self.setup_done= d["setup_done"]= True    
            if len(response) >=12:
                self.needs_secure_channel= d["needs_secure_channel"]= False if response[11]==0X00 else True    
            else:
                self.needs_secure_channel= d["needs_secure_channel"]= False
        
        elif (sw1==0x9c) and (sw2==0x04):
            self.setup_done= d["setup_done"]= False  
            self.is_seeded= d["is_seeded"]= False
            self.needs_secure_channel= d["needs_secure_channel"]= False
            
        else:
            logger.warning(f"In card_get_status: unknown get-status() error! sw12={hex(sw1)} {hex(sw2)}")#debugSatochip
            raise RuntimeError('Unknown get-status() error code:'+hex(sw1)+' '+hex(sw2))
            
        return (response, sw1, sw2, d)

    def card_setup(self,
                    pin_tries0, ublk_tries0, pin0, ublk0,
                    pin_tries1, ublk_tries1, pin1, ublk1,
                    memsize, memsize2,
                    create_object_ACL, create_key_ACL, create_pin_ACL,
                    option_flags=0, hmacsha160_key=None, amount_limit=0):
        
        logger.debug("In card_setup")
        # to do: check pin sizes < 256
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
        return (response, sw1, sw2)

    ###########################################
    #                        BIP32 commands                      #
    ###########################################

    def card_bip32_import_seed(self, seed):
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
            self.is_seeded= True
        return authentikey

    def card_reset_seed(self, pin, hmac=[]):
        logger.debug("In card_reset_seed")
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

    ''' Allows to compute coordy of authentikey externally to optimize computation time-out
        coordy value is verified by the chip before being accepted '''
    def card_bip32_set_authentikey_pubkey(self, response):
        logger.debug("In card_bip32_set_authentikey_pubkey")
        cla= JCconstants.CardEdge_CLA
        ins= 0x75
        p1= 0x00
        p2= 0x00

        authentikey= self.parser.parse_bip32_get_authentikey(response)
        if authentikey:
            coordy= authentikey.get_public_key_bytes(compressed=False)
            coordy= list(coordy[33:])
            data= response + [len(coordy)&0xFF00, len(coordy)&0x00FF] + coordy
            lc= len(data)
            apdu=[cla, ins, p1, p2, lc]+data
            (response, sw1, sw2) = self.card_transmit(apdu)
        return authentikey

    def card_bip32_get_extendedkey(self, path):
        logger.debug("In card_bip32_get_extendedkey")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_GET_EXTENDED_KEY
        p1= len(path)//4
        p2= 0x40 #option flags: 0x80:erase cache memory - 0x40: optimization for non-hardened child derivation
        lc= len(path)
        apdu=[cla, ins, p1, p2, lc]
        apdu+= path

        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        # send apdu
        while (True):
            (response, sw1, sw2) = self.card_transmit(apdu)

            # if there is no more memory available, erase cache...
            #if self.get_sw12(sw1,sw2)==JCconstants.SW_NO_MEMORY_LEFT:
            if (sw1==0x9C) and (sw2==0x01):
                logger.info("card_bip32_get_extendedkey(): Reset memory...")#debugSatochip
                apdu[3]=apdu[3]^0x80
                response, sw1, sw2 = self.card_transmit(apdu)
                apdu[3]=apdu[3]&0x7f # reset the flag
            # other (unexpected) error
            if (sw1!=0x90) or (sw2!=0x00):
                raise UnexpectedSW12Error('Unexpected error code SW12='+hex(sw1)+" "+hex(sw2))
            # check for non-hardened child derivation optimization
            elif ( (response[32]&0x80)== 0x80):
                logger.info("card_bip32_get_extendedkey(): Child Derivation optimization...")#debugSatochip
                (pubkey, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                coordy= pubkey.get_public_key_bytes(compressed=False)
                coordy= list(coordy[33:])
                authcoordy= self.parser.authentikey.get_public_key_bytes(compressed=False)
                authcoordy= list(authcoordy[33:])
                data= response+[len(coordy)&0xFF00, len(coordy)&0x00FF]+coordy
                apdu_opt= [cla, 0x74, 0x00, 0x00, len(data)]
                apdu_opt= apdu_opt+data
                response_opt, sw1_opt, sw2_opt = self.card_transmit(apdu_opt)
            #at this point, we have successfully received a response from the card
            else:
                (key, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                return (key, chaincode)

    ###########################################
    #                      Signing commands                      #
    ###########################################
    
    def card_sign_message(self, keynbr, pubkey, message, hmac=b''):
        logger.debug("In card_sign_message")
        if (type(message)==str):
            message = message.encode('utf8')

        # return signature as byte array
        # data is cut into chunks, each processed in a different APDU call
        chunk= 128 # max APDU data=255 => chunk<=255-(4+2)
        buffer_offset=0
        buffer_left=len(message)

        # CIPHER_INIT - no data processed
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_MESSAGE
        p1= keynbr # 0xff=>BIP32 otherwise STD
        p2= JCconstants.OP_INIT
        lc= 0x4
        apdu=[cla, ins, p1, p2, lc]
        for i in reversed(range(4)):
            apdu+= [((buffer_left>>(8*i)) & 0xff)]

        # send apdu
        (response, sw1, sw2) = self.card_transmit(apdu)

        # CIPHER PROCESS/UPDATE (optionnal)
        while buffer_left>chunk:
            #cla= JCconstants.CardEdge_CLA
            #ins= INS_COMPUTE_CRYPT
            #p1= key_nbr
            p2= JCconstants.OP_PROCESS
            lc= 2+chunk
            apdu=[cla, ins, p1, p2, lc]
            apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
            apdu+= message[buffer_offset:(buffer_offset+chunk)]
            buffer_offset+=chunk
            buffer_left-=chunk
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)

        # CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left #following while condition, buffer_left<=chunk
        #cla= JCconstants.CardEdge_CLA
        #ins= INS_COMPUTE_CRYPT
        #p1= key_nbr
        p2= JCconstants.OP_FINALIZE
        lc= 2+chunk+ len(hmac)
        apdu=[cla, ins, p1, p2, lc]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= message[buffer_offset:(buffer_offset+chunk)]+hmac
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # parse signature from response
        if (sw1!=0x90 or sw2!=0x00):
            logger.warning("In card_sign_message(): error sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
            compsig=b''
        else:
            compsig=self.parser.parse_message_signature(response, message, pubkey)
                
        return (response, sw1, sw2, compsig)

    # This method was deprecated since it does the same as the more generic card_sign_message()
    # This allows to simplify code, facilitate maintenance and reduce surface.
    # def card_sign_short_message(self, keynbr, message, hmac=b''):
        # if (type(message)==str):
            # message = message.encode('utf8')

        # # for message less than one chunk in size
        # cla= JCconstants.CardEdge_CLA
        # ins= JCconstants.INS_SIGN_SHORT_MESSAGE
        # p1= keynbr # oxff=>BIP32 otherwise STD
        # p2= 0x00
        # lc= message.length+2+len(hmac)
        # apdu= [cla, ins, p1, p2, lc]
        # apdu+= [(message.length>>8 & 0xFF), (message.length & 0xFF)]
        # apdu+= message+ hmac
        # # send apdu
        # response, sw1, sw2 = self.card_transmit(apdu)
        # return (response, sw1, sw2)

    def card_parse_transaction(self, transaction, is_segwit=False):
        logger.debug("In card_parse_transaction")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_PARSE_TRANSACTION
        p1= JCconstants.OP_INIT
        p2= 0X01 if is_segwit else 0x00

        # init transaction data and context
        txparser= TxParser(transaction)
        while not txparser.is_parsed():

            chunk= txparser.parse_segwit_transaction() if is_segwit else txparser.parse_transaction()
            lc= len(chunk)
            apdu=[cla, ins, p1, p2, lc]
            apdu+=chunk

            # log state & send apdu
            #if (txparser.is_parsed():
                #lc= 86 # [hash(32) | sigsize(2) | sig | nb_input(4) | nb_output(4) | coord_actif_input(4) | amount(8)]
                #logCommandAPDU("cardParseTransaction - FINISH",cla, ins, p1, p2, data, lc)
            #elif p1== JCconstants.OP_INIT:
                #logCommandAPDU("cardParseTransaction-INIT",cla, ins, p1, p2, data, lc)
            #elif p1== JCconstants.OP_PROCESS:
                #logCommandAPDU("cardParseTransaction - PROCESS",cla, ins, p1, p2, data, lc)

            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)

            # switch to process mode after initial call to parse
            p1= JCconstants.OP_PROCESS
        
        #parse response
        (tx_hash, needs_2fa)= self.parser.parse_parse_transaction(response)
        
        return (response, sw1, sw2, tx_hash, needs_2fa)

    def card_sign_transaction(self, keynbr, txhash, chalresponse):
        logger.debug("In card_sign_transaction")
        #if (type(chalresponse)==str):
        #    chalresponse = list(bytes.fromhex(chalresponse))
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_TRANSACTION
        p1= keynbr
        p2= 0x00

        if len(txhash)!=32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")
        elif chalresponse==None:
            data= txhash
        else:
            if len(chalresponse)!=20:
                raise ValueError("Wrong Challenge response length:"+ str(len(chalresponse)) + "(should be 20)")
            data= txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)
    
    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse):
        logger.debug("In card_sign_transaction_hash")
        #if (type(chalresponse)==str):
        #    chalresponse = list(bytes.fromhex(chalresponse))
        cla= JCconstants.CardEdge_CLA
        ins= 0x7A
        p1= keynbr
        p2= 0x00

        if len(txhash)!=32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")
        elif chalresponse==None:
            data= txhash
        else:
            if len(chalresponse)!=20:
                raise ValueError("Wrong Challenge response length:"+ str(len(chalresponse)) + "(should be 20)")
            data= txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)
     
    ###########################################
    #                         2FA commands                        #
    ###########################################
     
    def card_set_2FA_key(self, hmacsha160_key, amount_limit):
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
        return (response, sw1, sw2)

    def card_reset_2FA_key(self, chalresponse):
        logger.debug("In card_reset_2FA_key")
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
            # extract IV & id_2FA
            IV= response[0:16]
            id_2FA= response[16:36]
            msg_out=IV
            # id_2FA is 20 bytes, should be 32 => use sha256
            from hashlib import sha256
            id_2FA= sha256(bytes(id_2FA)).hexdigest()
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
    #                         PIN commands                        #
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

    def card_verify_PIN(self):
        logger.debug("In card_verify_PIN")
        if not self.card_present:
            self.client.request('show_error', 'No Satochip found! Please insert card!')
            return
        while (True):
            if self.pin is None:
                # (response, sw1, sw2, d)=self.card_get_status() # get number of pin tries remaining
                # if d.get("PIN0_remaining_tries",-1)==1:
                    # msg = "WARNING: ONLY ONE ATTEMPT REMAINING! Enter the PIN for your Satochip: "
                # else:
                    # msg = 'Enter the PIN for your Satochip: '
                msg = 'Enter the PIN for your Satochip: '
                (is_PIN, pin_0)= self.client.PIN_dialog(msg)
                if not is_PIN:
                    raise RuntimeError(('Device cannot be unlocked without PIN code!'))
                pin_0=list(pin_0)
            else:
                pin_0= self.pin
            cla= JCconstants.CardEdge_CLA
            ins= JCconstants.INS_VERIFY_PIN
            apdu=[cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
            
            if (self.needs_secure_channel):
	                apdu = self.card_encrypt_secure_channel(apdu)
            response, sw1, sw2 = self.cardservice.connection.transmit(apdu)
            
            # correct PIN: cache PIN value
            if sw1==0x90 and sw2==0x00: 
                self.set_pin(0, pin_0) 
                return (response, sw1, sw2)     
            # wrong PIN, get remaining tries available (since v0.11)
            elif sw1==0x63 and (sw2 & 0xc0)==0xc0:
                self.set_pin(0, None) #reset cached PIN value
                pin_left= (sw2 & ~0xc0)
                msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
                self.client.request('show_error', msg)
            # wrong PIN (legacy before v0.11)    
            elif sw1==0x9c and sw2==0x02:
                self.set_pin(0, None) #reset cached PIN value
                (response2, sw1b, sw2b, d)=self.card_get_status() # get number of pin tries remaining
                pin_left= d.get("PIN0_remaining_tries",-1)
                msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
                self.client.request('show_error', msg)
            # blocked PIN
            elif sw1==0x9c and sw2==0x0c:
                msg = ("Too many failed attempts! Your Satochip has been blocked! You need your PUK code to unblock it.")
                self.client.request('show_error', msg)
                raise RuntimeError('Device blocked with error code:'+hex(sw1)+' '+hex(sw2))

    def set_pin(self, pin_nbr, pin):
        self.pin_nbr=pin_nbr
        self.pin=pin
        return

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
        
        # correct PIN: cache PIN value
        if sw1==0x90 and sw2==0x00: 
            self.set_pin(pin_nbr, new_pin) 
        # wrong PIN, get remaining tries available (since v0.11)
        elif sw1==0x63 and (sw2 & 0xc0)==0xc0:
            self.set_pin(pin_nbr, None) #reset cached PIN value
            pin_left= (sw2 & ~0xc0)
            msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
            self.client.request('show_error', msg)
        # wrong PIN (legacy before v0.11)    
        elif sw1==0x9c and sw2==0x02: 
            self.set_pin(pin_nbr, None) #reset cached PIN value
            (response2, sw1b, sw2b, d)=self.card_get_status() # get number of pin tries remaining
            pin_left= d.get("PIN0_remaining_tries",-1)
            msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
            self.client.request('show_error', msg)
        # blocked PIN
        elif sw1==0x9c and sw2==0x0c:
            msg = ("Too many failed attempts! Your Satochip has been blocked! You need your PUK code to unblock it.")
            self.client.request('show_error', msg)
            raise RuntimeError('Device blocked with error code:'+hex(sw1)+' '+hex(sw2))
	        
        return (response, sw1, sw2)      

    def card_unblock_PIN(self, pin_nbr, ublk):
        logger.debug("In card_unblock_PIN")
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_UNBLOCK_PIN
        p1= pin_nbr
        p2= 0x00
        lc= len(ublk)
        apdu=[cla, ins, p1, p2, lc] + ublk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # wrong PUK, get remaining tries available (since v0.11)
        if sw1==0x63 and (sw2 & 0xc0)==0xc0:
            self.set_pin(pin_nbr, None) #reset cached PIN value
            pin_left= (sw2 & ~0xc0)
            msg = ("Wrong PUK! {} tries remaining!").format(pin_left)
            self.client.request('show_error', msg)
        # wrong PUK (legacy before v0.11)    
        elif sw1==0x9c and sw2==0x02: 
            self.set_pin(pin_nbr, None) #reset cached PIN value
            (response2, sw1b, sw2b, d)=self.card_get_status() # get number of pin tries remaining
            pin_left= d.get("PUK0_remaining_tries",-1)
            msg = ("Wrong PUK! {} tries remaining!").format(pin_left)
            self.client.request('show_error', msg)
        # blocked PUK
        elif sw1==0x9c and sw2==0x0c:
            msg = ("Too many failed attempts! Your Satochip has been blocked!")
            self.client.request('show_error', msg)
            raise RuntimeError('Device blocked with error code:'+hex(sw1)+' '+hex(sw2))
        
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
    
    #####################
    
    def card_init_connect(self):
        logger.debug("In card_init_connect")
        logger.info("ATR: "+str(self.card_get_ATR()))
        #response, sw1, sw2 = self.card_select() #TODO: remove?
        
        # check setup
        while(self.card_present):
            (response, sw1, sw2, d)=self.card_get_status()
            
            # check version
            if  (self.setup_done):
                v_supported= CardConnector.SATOCHIP_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"In card_init_connect(): Satochip version={hex(v_applet)} Electrum supported version= {hex(v_supported)}")#debugSatochip
                if (v_supported<v_applet):
                    msg=(_('The version of your Satochip is higher than supported by Electrum. You should update Electrum to ensure correct functioning!')+ '\n' 
                                + f'    Satochip version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                + f'    Supported version: {CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION}.{CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION}')
                    self.client.request('show_error', msg)
                
                if (self.needs_secure_channel):
                    self.card_initiate_secure_channel()
                
                break 
                
            # setup device (done only once)
            else:
                # PIN dialog
                msg = _("Enter a new PIN for your Satochip:")
                msg_confirm = _("Please confirm the PIN code for your Satochip:")
                msg_error = _("The PIN values do not match! Please type PIN again!")
                (is_PIN, pin_0)= self.client.PIN_setup_dialog(msg, msg_confirm, msg_error)
                
                pin_0= list(pin_0)
                self.set_pin(0, pin_0) #cache PIN value in client
                pin_tries_0= 0x05;
                ublk_tries_0= 0x01;
                # PUK code can be used when PIN is unknown and the card is locked
                # We use a random value as the PUK is not used currently and is not user friendly
                ublk_0= list(urandom(16)); 
                pin_tries_1= 0x01
                ublk_tries_1= 0x01
                pin_1= list(urandom(16)); #the second pin is not used currently
                ublk_1= list(urandom(16));
                secmemsize= 32 # number of slot reserved in memory cache
                memsize= 0x0000 # RFU
                create_object_ACL= 0x01 # RFU
                create_key_ACL= 0x01 # RFU
                create_pin_ACL= 0x01 # RFU
                
                #setup
                (response, sw1, sw2)=self.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1!=0x90 or sw2!=0x00:       
                    logger.info(f"In card_init_connect(): unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")#debugSatochip
                    raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
            
        # verify pin:
        try:
            self.card_verify_PIN()
        except Exception as exc:
            self.client.request('show_error', repr(exc))
            return
        
        # get authentikey
        try:
            authentikey=self.card_bip32_get_authentikey()
        except UninitializedSeedError:
            # Option: setup 2-Factor-Authentication (2FA)
            self.init_2FA()
                    
            # seed dialog...
            logger.info("In card_init_connect(): import seed...") #debugSatochip
            (mnemonic, passphrase, seed)= self.client.seed_wizard()                    
            if seed:
                seed= list(seed)
                authentikey= self.card_bip32_import_seed(seed)
                if authentikey:
                    self.client.request('show_success','Seed successfully imported to Satochip!')
                else:
                    self.client.request('show_error','Error when importing seed to Satochip!')
            else: #if cancel
                self.client.request('show_message','Seed import cancelled!')
                
        hex_authentikey= authentikey.get_public_key_hex(compressed=True)
        logger.info(f"In card_init_connect(): authentikey={hex_authentikey}")#debugSatochip       
        
    def init_2FA(self):
        logger.debug("In init_2FA")
        if not self.needs_2FA:
            use_2FA=self.client.request('yes_no_question', MSG_USE_2FA)
            if (use_2FA):
                secret_2FA= urandom(20)
                secret_2FA_hex=secret_2FA.hex()
                amount_limit= 0 # i.e. always use 
                try:
                    # the secret must be shared with the second factor app (eg on a smartphone)
                    msg= 'Scan this QR code on your second device \nand securely save a backup of this 2FA-secret: \n'+secret_2FA_hex
                    (event, values)= self.client.request('QRDialog', secret_2FA_hex, None, "Satochip-Bridge: QR Code", True, msg)
                    if event=='Ok':
                        # further communications will require an id and an encryption key (for privacy). 
                        # Both are derived from the secret_2FA using a one-way function inside the Satochip
                        (response, sw1, sw2)=self.card_set_2FA_key(secret_2FA, amount_limit)
                        if sw1!=0x90 or sw2!=0x00:                 
                            logger.warning("In init_2FA(): unable to set 2FA!  sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
                            self.client.request('show_error', 'Unable to setup 2FA with error code:'+hex(sw1)+' '+hex(sw2))
                            #raise RuntimeError('Unable to setup 2FA with error code:'+hex(sw1)+' '+hex(sw2))
                        else:
                            self.needs_2FA=True
                            self.client.request('show_success', '2FA enabled successfully!')
                    else: # Cancel
                        self.client.request('show_message', '2FA activation canceled!')
                except Exception as e:
                    logger.warning("In init_2FA(): exception during 2FA activation: "+str(e))    
                    self.client.request('show_error', 'Exception during 2FA activation: '+str(e))
        else:
            self.client.request('show_message', '2FA is already activated!')
    
    ###########################################
    #                         Secure Channel                        #
    ###########################################
    
    def card_initiate_secure_channel(self):
        logger.debug("In card_initiate_secure_channel()")
        cla= JCconstants.CardEdge_CLA
        ins= 0x81
        p1= 0x00 
        p2= 0x00
        
        # get sc
        self.sc= SecureChannel(logger.getEffectiveLevel())
        pubkey= list(self.sc.sc_pubkey_serialized)
        lc= len(pubkey) #65
        apdu=[cla, ins, p1, p2, lc] + pubkey
        
        # send apdu 
        response, sw1, sw2 = self.card_transmit(apdu) 
        
        # parse response and extract pubkey...
        peer_pubkey = self.parser.parse_initiate_secure_channel(response)
        peer_pubkey_bytes= peer_pubkey.get_public_key_bytes(compressed=False)
        self.sc.initiate_secure_channel(peer_pubkey_bytes)
        
        return peer_pubkey             
       
    def card_encrypt_secure_channel(self, apdu):
        logger.debug("In card_encrypt_secure_channel()")
        cla= JCconstants.CardEdge_CLA
        ins= 0x82
        p1= 0x00 
        p2= 0x00
        
        # log plaintext apdu
        if (apdu[1] in (JCconstants.INS_SETUP, JCconstants.INS_SET_2FA_KEY,
                                JCconstants.INS_BIP32_IMPORT_SEED, JCconstants.INS_BIP32_RESET_SEED,
                                JCconstants.INS_CREATE_PIN, JCconstants.INS_VERIFY_PIN,
                                JCconstants.INS_CHANGE_PIN, JCconstants.INS_UNBLOCK_PIN)):
            logger.info(f"Plaintext C-APDU: {toHexString(apdu[0:5])}{(len(apdu)-5)*' *'}")
        else:
            logger.info(f"Plaintext C-APDU: {toHexString(apdu)}")
            
        # for encryption, the data is padded with PKCS#7
        blocksize= 16
        size=len(apdu)
        padsize= blocksize - (size%blocksize)
        apdu= apdu+ [padsize]*padsize
        
        (iv, ciphertext, mac)= self.sc.encrypt_secure_channel(bytes(apdu))
        data= list(iv) + [len(ciphertext)>>8, len(ciphertext)&0xff] + list(ciphertext) + [len(mac)>>8, len(mac)&0xff] + list(mac)
        lc= len(data)
        
        encrypted_apdu= [cla, ins, p1, p2, lc]+data
        
        return encrypted_apdu
    
    def card_decrypt_secure_channel(self, response):
        logger.debug("In card_decrypt_secure_channel")
        
        if len(response)==0:
            return response
        elif len(response)<18:
            raise RuntimeError('Encrypted response has wrong lenght!')
        
        iv= bytes(response[0:16])
        size= ((response[16] & 0xff)<<8) + (response[17] & 0xff)
        ciphertext= bytes(response[18:])
        if len(ciphertext)!=size:
            logger.warning(f'In card_decrypt_secure_channel: ciphertext has wrong length: expected {str(size)} got {str(len(ciphertext))}')
            raise RuntimeError('Ciphertext has wrong lenght!')
            
        plaintext= self.sc.decrypt_secure_channel(iv, ciphertext)
        
        #remove padding
        #logger.debug(f'Plaintext with padding: {toHexString(plaintext)}')
        plaintext= list(plaintext)
        pad= plaintext[-1]
        plaintext=plaintext[0:-pad]
        #logger.debug(f'Plaintext without padding: {toHexString(plaintext)}')
        
        #log response
        logger.info( f'Plaintext R-APDU: {toHexString(plaintext)}')
        
        return plaintext
    
class AuthenticationError(Exception):
    """Raised when the command requires authentication first"""
    pass

class UninitializedSeedError(Exception):
    """Raised when the device is not yet seeded"""
    pass

class UnexpectedSW12Error(Exception):
    """Raised when the device returns an unexpected error code"""
    pass

if __name__ == "__main__":

    cardconnector= CardConnector()
    cardconnector.card_get_ATR()
    cardconnector.card_select()
    #cardconnector.card_setup()
    cardconnector.card_bip32_get_authentikey()
    #cardconnector.card_bip32_get_extendedkey()
    cardconnector.card_disconnect()