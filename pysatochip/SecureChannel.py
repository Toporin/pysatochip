from ecdsa import ECDH
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey

import pyaes
import hmac
import logging 
from os import urandom
from hashlib import sha1, sha256

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class SecureChannel:

    def __init__(self, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        self.initialized_secure_channel= False
        self.sc_privkey= None
        self.sc_pubkey= None
        self.sc_peer_pubkey= None
        self.sc_IV= None
        self.sc_IVcounter= None
        self.shared_key = None
        self.derived_key = None
        self.mac_key = None
        
        self.ecdh = ECDH(curve=SECP256k1)
        self.ecdh.generate_private_key()
        self.sc_pubkey = self.ecdh.get_public_key()
        self.sc_pubkey_serialized= self.sc_pubkey.to_string(encoding='uncompressed')
        
    def initiate_secure_channel(self, peer_pubkey_bytes):
        logger.debug("In initiate_secure_channel()")
        
        self.sc_IVcounter= 1
        
        #using ecdsa
        self.sc_peer_pubkey= VerifyingKey.from_string(peer_pubkey_bytes,  curve=SECP256k1)
        self.ecdh.load_received_public_key(self.sc_peer_pubkey)
        self.shared_key = self.ecdh.generate_sharedsecret_bytes()
        
        #logger.debug("Shared key:"+ self.shared_key.hex()) #debug
        
        mac = hmac.new(self.shared_key, "sc_key".encode('utf-8'), sha1)
        self.derived_key= mac.digest()[:16]
        mac = hmac.new(self.shared_key, "sc_mac".encode('utf-8'), sha1)
        self.mac_key= mac.digest()
        
        # alternative derivation
        # tmp_key= sha256(self.shared_key).digest()
        # self.derived_key = tmp_key[:16]
        # tmp_key= sha256(tmp_key).digest()
        # self.mac_key= tmp_key[:20]
        
        # logger.debug("Derived_key key:"+ self.derived_key.hex()) #debug
        # logger.debug("Mac_key key:"+ self.mac_key.hex()) #debug
        
        self.initialized_secure_channel= True
            
    def encrypt_secure_channel(self, data_bytes):
        logger.debug("In encrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        
        ## for encryption, the data is padded with PKCS#7 (done by PADDING_DEFAULT)
        # blocksize= 16
        # size=len(apdu)
        # padsize= blocksize - (size%blocksize)
        # apdu= apdu+ [padsize]*padsize
        
        key= self.derived_key
        iv= urandom(12)+(self.sc_IVcounter).to_bytes(4, byteorder='big')
        
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_DEFAULT)
        ciphertext = aes.feed(data_bytes) + aes.feed()
        
        self.sc_IVcounter+=2
        
        data_to_mac= iv + len(ciphertext).to_bytes(2, byteorder='big') + ciphertext
        mac = hmac.new(self.mac_key, data_to_mac, sha1).digest()
        
        return (iv, ciphertext, mac)
    
    
    def decrypt_secure_channel(self, iv, ciphertext):
        logger.debug("In decrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        
        key= self.derived_key
        
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_DEFAULT)
        decrypted = aes.feed(ciphertext) + aes.feed() 
        
        # #remove padding (already done with PADDING_DEFAULT)
        # #logger.debug(f'Plaintext with padding: {toHexString(plaintext)}')
        # plaintext= list(plaintext)
        # pad= plaintext[-1]
        # plaintext=plaintext[0:-pad]
        # #logger.debug(f'Plaintext without padding: {toHexString(plaintext)}')
        
        return list(decrypted)
            
class UninitializedSecureChannelError(Exception):    
    """Raised when the secure channel is not initialized"""
    pass   