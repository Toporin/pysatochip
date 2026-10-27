import os
import logging

try:
    import OpenSSL
    HAS_OPENSSL = True
except Exception:  # pragma: no cover - optional dependency
    OpenSSL = None
    HAS_OPENSSL = False


from . import set_log_level

logger = logging.getLogger(__name__)

# root CA and subCA certificates shipped with the package
CERT_DIR = os.path.join(os.path.dirname(__file__), "cert")
# NB: no logger.setLevel() here on purpose. Module loggers must stay at NOTSET
# so that a level set on the `pysatochip` package logger cascades to all of
# them -- see pysatochip.set_log_level().

class CertificateValidator:
    """Validate device certificate chains using OpenSSL or pure Python."""

    def __init__(self, backend: str = "auto", loglevel: int = None):
        """Create a validator.

        :param backend: ``'openssl'``, ``'pycryptodomex'`` or ``'auto'``.
            In ``auto`` mode OpenSSL is used when available.
        :param loglevel: convenience for pysatochip.set_log_level(); sets the
            level of the whole package, not of this instance. None leaves the
            application's logging configuration alone.
        """
        self.backend = backend
        if loglevel is not None:
            set_log_level(loglevel)
        logger.debug("In __init__")
    
    def validate_certificate_chain(self, device_pem, device_type):
        logger.debug("In validate_certificate_chain")
        
        USE_TEST_CA=True
        
        (is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error)= self._validate_chain(device_pem, device_type, use_test=False)
        if is_valid:
            return (is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error)
        elif USE_TEST_CA: # check with test ca:
            logger.warning("Certificate chains NOT VALID for production PKI")
            (is_valid_test, device_pubkey_test, txt_ca_test, txt_subca_test, txt_device_test, txt_error_test)= self._validate_chain(device_pem, device_type, use_test=True)
            if is_valid_test:
                is_valid_test= False
                txt_error_test= "WARNING: Chain certificate validated with TEST CA! NOT FOR PRODUCTION!"
                return (is_valid_test, device_pubkey_test, txt_ca_test, txt_subca_test, txt_device_test, txt_error_test)
            else:
                return (is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error)
            
        return (is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error)
        
    
    def _validate_chain(self, device_pem, device_type, use_test=False):
        logger.debug("In validate_certificate_chain")
        
        txt_ca=txt_subca=txt_device=txt_error=""
        device_pubkey= bytes(65*[0])
        
        # load subca according to device type
        directory=CERT_DIR
        if not use_test:
            path_ca = os.path.join(directory, 'ca.cert')
            if device_type=="SeedKeeper":
                path_subca = os.path.join(directory, 'subca-seedkeeper.cert')
            elif device_type=="Satochip":
                path_subca = os.path.join(directory, 'subca-satochip.cert')
            elif device_type=="Satodime":
                path_subca = os.path.join(directory, 'subca-satodime.cert')
            else:
                txt_error= "Unknown card_type: "+ str(device_type)
                return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
         
        else: # for testing purpose only!
            path_ca = os.path.join(directory, 'test-ca.cert') #for testing purpose!
            if device_type=="SeedKeeper":
                path_subca = os.path.join(directory, 'test-subca-seedkeeper.cert')
            elif device_type=="Satochip":
                path_subca = os.path.join(directory, 'test-subca-satochip.cert')
            elif device_type=="Satodime":
                path_subca = os.path.join(directory, 'test-subca-satodime.cert')
            else:
                txt_error= "Unknown card_type: "+ str(device_type)
                return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
            
            
        # a missing certificate (e.g. not bundled by a frozen app) means the chain cannot be validated
        try:
            with open(path_ca, 'r', encoding='utf-8') as f:
                ca_pem = f.read()
            with open(path_subca, 'r', encoding='utf-8') as f:
                subca_pem = f.read()
        except OSError as ex:
            logger.warning(f"Unable to load CA certificate: {ex}")
            txt_error= f"Unable to load CA certificate: {ex}"
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        use_openssl = HAS_OPENSSL and self.backend != "pycryptodomex"
        if self.backend == "openssl" and not HAS_OPENSSL:
            txt_error = "OpenSSL backend requested but pyOpenSSL is not available"
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        if use_openssl:
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

            # if use_test:
                # txt_error= "WARNING: Chain certificate validated with TEST CA! NOT FOR PRODUCTION!"
                # return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

            return True, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        else:
            return self._validate_chain_pycryptodomex(ca_pem, subca_pem, device_pem)

    def _validate_chain_pycryptodomex(self, ca_pem, subca_pem, device_pem):
        """Verify the certificate chain without pyOpenSSL.

        ASN.1 parsing is done with pycryptodomex; the signature checks go
        through ec_backend (see issue #8 -- this used to call into `ecdsa`).
        """
        txt_ca = txt_subca = txt_device = "OpenSSL module not available"
        device_pubkey = bytes(65 * [0])
        try:
            from Cryptodome.Util.asn1 import DerSequence, DerSetOf, DerObjectId, DerBitString, DerObject
            import re, base64
            from datetime import datetime

            from . import ec_backend

            # signatureAlgorithm OID -> hash name understood by ec_backend
            HASHES = {
                '1.2.840.10045.4.3.2': 'sha256',
                '1.2.840.10045.4.3.3': 'sha384',
                '1.2.840.10045.4.3.4': 'sha512',
            }
            # namedCurve OID -> curve name. The Satochip chain uses a secp384r1
            # root CA which signs secp256k1 subCAs, so both are needed.
            CURVES = {
                '1.3.132.0.10': 'secp256k1',
                '1.3.132.0.34': 'secp384r1',
                '1.2.840.10045.3.1.7': None,  # secp256r1: not supported
            }

            def der_from_pem(pem):
                m = re.search(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", pem, re.S)
                if not m:
                    raise ValueError("Invalid PEM certificate")
                return base64.b64decode(''.join(m.group(1).split()))

            OID_NAMES = {
                '2.5.4.3': b'CN',
                '2.5.4.6': b'C',
                '2.5.4.10': b'O',
                '2.5.4.11': b'OU',
                '2.5.4.7': b'L',
                '2.5.4.8': b'ST',
                '1.2.840.113549.1.9.1': b'emailAddress',
            }

            def parse_name(der):
                seq = DerSequence(); seq.decode(der)
                attrs = {}
                for rdn in seq:
                    set_seq = DerSetOf(); set_seq.decode(rdn)
                    attr_seq = DerSequence(); attr_seq.decode(set_seq[0])
                    oid = DerObjectId(); oid.decode(attr_seq[0])
                    value_obj = DerObject(); value_obj.decode(attr_seq[1])
                    key = OID_NAMES.get(oid.value, oid.value.encode())
                    attrs[key] = value_obj.payload.decode('utf-8').encode()
                return attrs

            def parse_cert(pem):
                der = der_from_pem(pem)
                seq = DerSequence(); seq.decode(der)
                tbs_der = seq[0]
                sig_seq = DerSequence(); sig_seq.decode(seq[1])
                oid = DerObjectId(); oid.decode(sig_seq[0])
                sig_oid = oid.value
                sig_bit = DerBitString(); sig_bit.decode(seq[2])
                sig_der = sig_bit.value
                tbs_seq = DerSequence(); tbs_seq.decode(tbs_der)
                issuer = parse_name(tbs_seq[3])
                validity_seq = DerSequence(); validity_seq.decode(tbs_seq[4])
                not_after_obj = DerObject(); not_after_obj.decode(validity_seq[1])
                na = not_after_obj.payload.decode('utf-8')
                if len(na) == 13:
                    expiry = datetime.strptime(na, "%y%m%d%H%M%SZ")
                else:
                    expiry = datetime.strptime(na, "%Y%m%d%H%M%SZ")
                subject = parse_name(tbs_seq[5])
                spki_seq = DerSequence(); spki_seq.decode(tbs_seq[6])
                algo_seq = DerSequence(); algo_seq.decode(spki_seq[0])
                curve_oid = None
                if len(algo_seq) > 1:
                    curve_oid_obj = DerObjectId(); curve_oid_obj.decode(algo_seq[1])
                    curve_oid = curve_oid_obj.value
                pub_bit = DerBitString(); pub_bit.decode(spki_seq[1])
                pub_bytes = pub_bit.value
                is_expired = datetime.utcnow() > expiry
                return {
                    'tbs': tbs_der,
                    'sig': sig_der,
                    'sig_oid': sig_oid,
                    'pub_bytes': pub_bytes,
                    'curve_oid': curve_oid,
                    'issuer': issuer,
                    'subject': subject,
                    'is_expired': is_expired,
                }

            def verify_cert(issuer_pub_bytes, issuer_curve, cert_info):
                hashalg = HASHES.get(cert_info['sig_oid'])
                if hashalg is None:
                    raise ValueError(
                        "Unsupported signature algorithm: " + str(cert_info['sig_oid']))
                if issuer_curve == 'secp384r1':
                    # libsecp256k1 cannot do P-384; ec_backend uses cryptography
                    # or pycryptodomex for this curve
                    is_valid = ec_backend.verify_p384(
                        issuer_pub_bytes, cert_info['tbs'], cert_info['sig'], hashalg)
                elif issuer_curve == 'secp256k1':
                    is_valid = ec_backend.verify_message(
                        issuer_pub_bytes, cert_info['tbs'], cert_info['sig'], hashalg)
                else:
                    raise ValueError("Unsupported issuer curve: " + str(issuer_curve))
                if not is_valid:
                    raise ValueError("Bad certificate signature")

            def pubkey_curve(cert_info):
                curve = CURVES.get(cert_info['curve_oid'])
                return cert_info['pub_bytes'], curve

            ca_info = parse_cert(ca_pem)
            ca_pub, ca_curve = pubkey_curve(ca_info)
            subca_info = parse_cert(subca_pem)
            verify_cert(ca_pub, ca_curve, subca_info)
            subca_pub, subca_curve = pubkey_curve(subca_info)
            device_info = parse_cert(device_pem)
            verify_cert(subca_pub, subca_curve, device_info)
            device_pubkey = device_info['pub_bytes']
            return True, device_pubkey, txt_ca, txt_subca, txt_device, ""
        except Exception as ex:
            txt_error = str(ex)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
    def parse_pem_certificate(self, cert_pem):
        """Parse a PEM certificate and return basic fields."""

        if self.backend == "openssl":
            if not HAS_OPENSSL:
                raise RuntimeError("OpenSSL backend requested but pyOpenSSL is not available")
        if HAS_OPENSSL and self.backend != "pycryptodomex":
            cert_dict = {}
            cert_x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
            issuer = cert_x509.get_issuer()
            subject = cert_x509.get_subject()
            cert_dict['is_expired'] = cert_x509.has_expired()
            cert_dict['issuer'] = dict(issuer.get_components())
            cert_dict['subject'] = dict(subject.get_components())
            return cert_dict

        return self._parse_pem_certificate_pycryptodomex(cert_pem)

    def _parse_pem_certificate_pycryptodomex(self, cert_pem):
        from Cryptodome.Util.asn1 import DerSequence, DerSetOf, DerObjectId, DerObject
        import base64, re
        from datetime import datetime

        OID_NAMES = {
            '2.5.4.3': b'CN',
            '2.5.4.6': b'C',
            '2.5.4.10': b'O',
            '2.5.4.11': b'OU',
            '2.5.4.7': b'L',
            '2.5.4.8': b'ST',
            '1.2.840.113549.1.9.1': b'emailAddress',
        }

        def der_from_pem(pem):
            m = re.search(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", pem, re.S)
            if not m:
                raise ValueError("Invalid PEM certificate")
            return base64.b64decode(''.join(m.group(1).split()))

        def parse_name(der):
            seq = DerSequence(); seq.decode(der)
            attrs = {}
            for rdn in seq:
                set_seq = DerSetOf(); set_seq.decode(rdn)
                attr_seq = DerSequence(); attr_seq.decode(set_seq[0])
                oid = DerObjectId(); oid.decode(attr_seq[0])
                value_obj = DerObject(); value_obj.decode(attr_seq[1])
                key = OID_NAMES.get(oid.value, oid.value.encode())
                attrs[key] = value_obj.payload.decode('utf-8').encode()
            return attrs

        der = der_from_pem(cert_pem)
        seq = DerSequence(); seq.decode(der)
        tbs_der = seq[0]
        tbs_seq = DerSequence(); tbs_seq.decode(tbs_der)
        issuer = parse_name(tbs_seq[3])
        validity_seq = DerSequence(); validity_seq.decode(tbs_seq[4])
        not_after_obj = DerObject(); not_after_obj.decode(validity_seq[1])
        na = not_after_obj.payload.decode('utf-8')
        if len(na) == 13:
            expiry = datetime.strptime(na, "%y%m%d%H%M%SZ")
        else:
            expiry = datetime.strptime(na, "%Y%m%d%H%M%SZ")
        subject = parse_name(tbs_seq[5])
        is_expired = datetime.utcnow() > expiry
        return {'issuer': issuer, 'subject': subject, 'is_expired': is_expired}
        
