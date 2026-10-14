import hmac
import logging 
from os import urandom
from hashlib import sha1

from . import aes_backend
from . import set_log_level
from . import ec_backend

logger = logging.getLogger(__name__)
# NB: no logger.setLevel() here on purpose. Module loggers must stay at NOTSET
# so that a level set on the `pysatochip` package logger cascades to all of
# them -- see pysatochip.set_log_level().

class SecureChannel:

    def __init__(self, loglevel= None):
        # `loglevel` is a convenience for pysatochip.set_log_level(): it sets the
        # level of the whole package, not of this instance. Leave it as None to
        # let the application own its logging configuration.
        if loglevel is not None:
            set_log_level(loglevel)
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
        
        self.initialized_secure_channel= True
            
    def encrypt_secure_channel(self, data_bytes):
        logger.debug("In encrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        
        key= self.derived_key
        # 96 bits of randomness plus the session counter. The host uses the odd
        # counters and the applet the even ones, so the two directions can never
        # collide on an IV within a session.
        iv= urandom(12)+(self.sc_IVcounter).to_bytes(4, byteorder='big')

        # AES-128-CBC + PKCS#7, as fixed by the applet. aes_backend picks a
        # hardened implementation (cryptography / pycryptodomex) and only falls
        # back to the pure-python pyaes when neither is installed.
        ciphertext = aes_backend.cbc_encrypt(key, iv, data_bytes)

        self.sc_IVcounter+=2
        
        data_to_mac= iv + len(ciphertext).to_bytes(2, byteorder='big') + ciphertext
        mac = hmac.new(self.mac_key, data_to_mac, sha1).digest()
        
        return (iv, ciphertext, mac)
    
    
    def decrypt_secure_channel(self, iv, ciphertext):
        logger.debug("In decrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        
        key= self.derived_key

        # The card response carries no MAC (the applet does not send one), so
        # everything here is attacker-malleable on a hostile reader/PCSC path.
        # Validate the shape and the padding and surface a SecureChannelError
        # rather than letting a mangled response through, or letting whatever
        # the cipher backend happens to raise escape to the caller.
        if len(iv) != aes_backend.AES_BLOCK_SIZE:
            raise SecureChannelError(
                f'Wrong IV length: expected {aes_backend.AES_BLOCK_SIZE} got {len(iv)}')
        try:
            decrypted = aes_backend.cbc_decrypt(key, iv, ciphertext)
        except aes_backend.InvalidPaddingError as ex:
            raise SecureChannelError(f'Failed to decrypt card response: {ex}')

        return list(decrypted)
            
class UninitializedSecureChannelError(Exception):    
    """Raised when the secure channel is not initialized"""
    pass


class SecureChannelError(Exception):
    """Raised when a secure channel message is malformed or undecryptable"""
    pass
