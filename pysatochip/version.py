# Satochip supported version tuple
# v0.4: getBIP32ExtendedKey also returns chaincode
# v0.5: Support for Segwit transaction
# v0.6: bip32 optimization: speed up computation during derivation of non-hardened child
# v0.7: add 2-Factor-Authentication (2FA) support
# v0.8: support seed reset and pin change
# v0.9: patch message signing for alts
# v0.10: sign tx hash
# v0.11: support for (mandatory) secure channel
# v0.12: card label & support for encrypted seed import from SeedKeeper
# v0.14: Schnorr signatures, nostr event signatures, Liquid-Bitcoin support (export Master Blinding Key)
SATOCHIP_PROTOCOL_MAJOR_VERSION=0
SATOCHIP_PROTOCOL_MINOR_VERSION=14
SATOCHIP_PROTOCOL_VERSION= (SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+SATOCHIP_PROTOCOL_MINOR_VERSION

# SeedKeeper supported version tuple
# v 0.1: initial version
# v 0.2: WIP
SEEDKEEPER_PROTOCOL_MAJOR_VERSION=0
SEEDKEEPER_PROTOCOL_MINOR_VERSION=2
SEEDKEEPER_PROTOCOL_VERSION= (SEEDKEEPER_PROTOCOL_MAJOR_VERSION<<8)+SEEDKEEPER_PROTOCOL_MINOR_VERSION

# Satodime supported version tuple
# v 0.1: initial version
SATODIME_PROTOCOL_MAJOR_VERSION=0
SATODIME_PROTOCOL_MINOR_VERSION=1
SATODIME_PROTOCOL_VERSION= (SATODIME_PROTOCOL_MAJOR_VERSION<<8)+SATODIME_PROTOCOL_MINOR_VERSION

# PYSATOCHIP version
# v0.11.a: initial version
# v0.11.1: new versioning, minor changes
# v0.11.2: use ecdsa & pyaes libraries instead of cryptography for ecdh key exchange
# v0.11.3: add support for altcoin message signing in CardConnector.card_sign_message()
# v0.11.4: minor improvements & more error checks
# v0.12.1: add SeedKeeper support
# v0.12.2: add list of 2FA servers to select
# v0.12.3: patch: downgrade pyscard version in requirements to solve conflicts
# v0.14.1: add Satodime support
# v0.14.2: minor improvements & corrections to support Satochip & Satodime
# v0.14.3: add CLI & bugfix 
# v0.15.1: support for SeedKeeper v0.2
# v0.15.2: add NDEF support
# v0.15.3: add support for Schnorr signatures & single-key wallet in Satochip
# v0.15.4: add support for Nostr event signature
# v0.15.5: add support for Liquid-Bitcoin Master Blinding Key export + Enable/disable optional features.
PYSATOCHIP_MAJOR_VERSION= 0
PYSATOCHIP_MINOR_VERSION= 15
PYSATOCHIP_REVISION= 5
PYSATOCHIP_VERSION= str(PYSATOCHIP_MAJOR_VERSION) + '.' + str(PYSATOCHIP_MINOR_VERSION) + '.' + str(PYSATOCHIP_REVISION)