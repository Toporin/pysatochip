import pyaes
import hmac
import logging 
from os import urandom
from hashlib import sha1, sha256

from . import ec_backend

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
        
        # fresh ephemeral keypair per session. Both are plain bytes now: the
        # scalar multiplication is done by ec_backend rather than by ecdsa,
        # whose non-constant-time implementation leaked the private key
        # through timing (CVE-2024-23342, issue #8).
        self.sc_privkey, self.sc_pubkey_serialized = ec_backend.generate_keypair()
        self.sc_pubkey = self.sc_pubkey_serialized  # uncompressed, 65 bytes
        
    def initiate_secure_channel(self, peer_pubkey_bytes):
        logger.debug("In initiate_secure_channel()")
        
        self.sc_IVcounter= 1
        
        # ecdh_shared_x() rejects a peer point that is not on the curve (as
        # VerifyingKey.from_string(validate_point=True) used to) and returns the
        # raw x-coordinate the applet derives on its side
        self.sc_peer_pubkey= peer_pubkey_bytes
        self.shared_key = ec_backend.ecdh_shared_x(self.sc_privkey, peer_pubkey_bytes)
        
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