import sys
import os 
import logging 
#from OpenSSL.crypto import load_certificate, load_privatekey
#from OpenSSL.crypto import X509Store, X509StoreContext
import OpenSSL

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class CertificateValidator:
   
    def __init__(self, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        
    def validate_certificate_chain(self, device_pem, device_type):
        logger.debug("In validate_certificate_chain")
        
        txt_ca=txt_subca=txt_device=txt_error=""
        device_pubkey= bytes(65*[0])
        
        # load subca according to device type
        directory=os.path.join(os.path.dirname(__file__), "cert")
        path_ca = os.path.join(directory, 'ca.cert')
        if device_type=="SeedKeeper":
            path_subca = os.path.join(directory, 'subca-seedkeeper.cert')
        elif device_type=="Satochip":
            path_subca = os.path.join(directory, 'subca-satochip.cert')
        elif device_type=="SatoDime":
            path_subca = os.path.join(directory, 'subca-satodime.cert')
        else:
            txt_error= "Unknown card_type: "+ str(device_type)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        
        # for testing purpose only!
        TEST=False
        if TEST:
            #path_ca = os.path.join(directory, 'bad-ca.cert') #for testing purpose!
            path_ca = os.path.join(directory, 'test-ca.cert') #for testing purpose!
            path_subca = os.path.join(directory, 'test-subca-seedkeeper.cert') #for testing purpose! 
            
        # todo: FileNotFoundError
        with open(path_ca, 'r', encoding='utf-8') as f:
                    ca_pem = f.read()
                    #logger.debug("CA pem: " + ca_pem)
        with open(path_subca, 'r', encoding='utf-8') as f:
                    subca_pem = f.read()
                    #logger.debug("SUBCA pem: " + subca_pem)
        
        try:
            parsed_ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_pem)
            txt_ca= OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, parsed_ca).decode("utf-8")
            logger.debug("CA cert: " + txt_ca)
            parsed_subca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, subca_pem)
            txt_subca= OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, parsed_subca).decode("utf-8")
            logger.debug("SUBCA cert: " + txt_subca)
            parsed_device = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, device_pem)
            txt_device= OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, parsed_device).decode("utf-8")
            logger.debug("DEVICE cert: " + txt_device)
        except OpenSSL.crypto.Error as ex:
            txt_error= "Exception during pem certificates parsing: "+ str(ex)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        
        # extract pubkey from device certificate
        device_pkey= parsed_device.get_pubkey()
        device_pkey_asn1= OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, device_pkey)
        logger.debug("DEVICE pubkey asn1: " + device_pkey_asn1.hex())
        device_pubkey= device_pkey_asn1[-65:]
        
        # add ca in store
        store = OpenSSL.crypto.X509Store()
        store.add_cert(parsed_ca)
        
        try:
            # Check the chain certificate before adding it to the store.
            store_ctx = OpenSSL.crypto.X509StoreContext(store, parsed_subca)
            store_ctx.verify_certificate()
            store.add_cert(parsed_subca)
        except OpenSSL.crypto.X509StoreContextError as ex:
            txt_error= "Exception during subca validation: "+ str(ex)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
            
        try:
            # Now check the end-entity certificate.
            store_ctx = OpenSSL.crypto.X509StoreContext(store, parsed_device)
            store_ctx.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError as ex:
            txt_error= "Exception during device certificate validation: "+ str(ex)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        
        if TEST:
            txt_error= "WARNING: Chain certificate validated with TEST CA! NOT FOR PRODUCTION!"
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        
        return True, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        
        