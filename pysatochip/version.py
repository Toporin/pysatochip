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
PYSATOCHIP_REVISION= '1'
PYSATOCHIP_VERSION= str(SATOCHIP_PROTOCOL_MAJOR_VERSION) + '.' + str(SATOCHIP_PROTOCOL_MINOR_VERSION) + '.' + str(PYSATOCHIP_REVISION)