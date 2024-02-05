from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.util import toHexString, toBytes
from smartcard.sw.SWExceptions import SWException

import logging 
import time

#debug
import sys
import traceback
import os 

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# a card observer that detects inserted/removed cards and initiate connection
class RemovalObserver(CardObserver):
    """A simple card observer that is notified
    when cards are inserted/removed from the system and
    prints the list of cards
    """
    def __init__(self, cc):
        self.cc=cc
        #self.observer = LogCardConnectionObserver() #ConsoleCardConnectionObserver()
            
    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            if card.atr == [59, 141, 1, 128, 251, 160, 0, 0, 3, 151, 66, 84, 70, 89, 4, 1, 207]: continue # Ignore Windows Hello for Business virtual device (3B 8D 01 80 FB A0 00 00 03 97 42 54 46 59 04 01 CF)
            #TODO check ATR and check if more than 1 card?
            logger.info(f"+Inserted: {toHexString(card.atr)}")
            #print(f"+Inserted: {toHexString(card.atr)}")
            self.cc.card_event= "card_added"
            self.cc.card_present= True
            self.cc.cardservice= card
            self.cc.cardservice.connection = card.createConnection()
            self.cc.cardservice.connection.connect()
            #self.cc.cardservice.connection.addObserver(self.observer)
            try:
                (response, sw1, sw2) = self.cc.card_select()
                if sw1!=0x90 or sw2!=0x00:
                    self.cc.card_disconnect()
                    break
                
            except Exception as exc:
                logger.warning(f"Error during connection: {repr(exc)}")
         
                
        for card in removedcards:
            logger.info(f"-Removed: {toHexString(card.atr)}")
            #print(f"-Removed: {toHexString(card.atr)}")
            self.cc.card_event= "card_removed"
            self.cc.card_disconnect()
            #print("Please insert card again...")
            
class CardConnector:

    # define the apdus used in this script
    BYTE_AID= [0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70] #SatoChip
    SATOCHIP_AID= [0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70] #SatoChip
    SEEDKEEPER_AID= [0x53,0x65,0x65,0x64,0x4b,0x65,0x65,0x70,0x65,0x72]  #SatoChip
 
    def __init__(self, client=None, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        self.logger= logger
        self.client=client
        self.card_event= None
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

    def card_transmit(self, plain_apdu):
        logger.debug("In card_transmit")
        while(self.card_present):
            try:

                # transmit apdu
                (response, sw1, sw2) = self.cardservice.connection.transmit(plain_apdu)
                
                # PIN authentication is required
                if (sw1==0x9C) and (sw2==0x06):
                    (response, sw1, sw2)= self.card_verify_PIN()

                else:
                    return (response, sw1, sw2)
                
            except Exception as exc:
                logger.warning(f"Error during connection: {repr(exc)}")
                #self.client.request('show_error',"Error during connection:"+repr(exc))
                return ([], 0x00, 0x00)
        
        # no card present
        #self.client.request('show_error','No Satochip found! Please insert card!')
        return ([], 0x00, 0x00)
        #TODO return errror or throw exception?

    def card_select(self):
        logger.debug("In card_select")
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08]
        apdu = SELECT + CardConnector.SATOCHIP_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        
        if sw1==0x90 and sw2==0x00:
            self.card_type="Satochip"
        else:
            SELECT = [0x00, 0xA4, 0x04, 0x00, 0x0A]
            apdu = SELECT + CardConnector.SEEDKEEPER_AID
            (response, sw1, sw2) = self.card_transmit(apdu)
            if sw1==0x90 and sw2==0x00:
                self.card_type="SeedKeeper"
        
        return (response, sw1, sw2)            
    
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
    
    def card_get_status(self):
        logger.debug("In card_get_status")
        cla= 0xB0
        ins= 0x3C
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
            logger.warning(f"[card_get_status] unknown get-status() error! sw12={hex(sw1)} {hex(sw2)}")
            #raise RuntimeError('Unknown get-status() error code:'+hex(sw1)+' '+hex(sw2))
            
        return (response, sw1, sw2, d)
    
    def card_reset_factory(self):
        logger.debug("In card_reset_factory")
        apdu = [0xB0, 0xFF, 0x00, 0x00, 0x00]
        (response, sw1, sw2) = self.card_transmit(apdu)
        return (response, sw1, sw2)          
