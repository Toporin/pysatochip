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

# v0.11.a: initial version
# v0.11.1: new versioning, minor changes
# v0.11.2: use ecdsa & pyaes libraries instead of cryptography for ecdh key exchange
# v0.11.3: add support for altcoin message signing in CardConnector.card_sign_message()
# v0.11.4: minor improvements & more error checks
PYSATOCHIP_REVISION= 4
PYSATOCHIP_VERSION= str(SATOCHIP_PROTOCOL_MAJOR_VERSION) + '.' + str(SATOCHIP_PROTOCOL_MINOR_VERSION) + '.' + str(PYSATOCHIP_REVISION)