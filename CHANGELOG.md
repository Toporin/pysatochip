# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.6]:

### Changed 

 - Refactor & simplify PIN verification with new method card_verify_PIN_simple(). State management when PIN verification fails (wrong PIN, card removed, Pin blocked...) is handled in the client app, not in pysatochip
 - Remove some exception handling in card_transmit(), usually exceptions should be handled in calling method or in client app
 - Get rid of most 'self.client.request()' callbacks, except for updating status when inserting/removing card physically
 - Add more specific exceptions classes

## [0.12.5]:

### Changed 

 - Remove pyopenssl from dependencies
 - Use cryptography package to verify certificates chain
 - Remove pyaes (mandatory) dependency for AES, use cryptography instead 
 - If present, pyaes and Cryptodome can also be used

## [0.12.4]:

### Changed 

 - Patch dependencies version in requirements.txt (use >= instead of ==)
 - Patch https://github.com/Toporin/pysatochip/issues/3

## [0.12.3]: 

### Changed 

- Patch: allow pyscard >= v1.9.9 in requirements to solve conflicts in some (windows) build.

## [0.12.2]: 

### Added 

- Allow user to select 2FA server from a list.

## [0.12.1]: 

### Added 

- add support for SeedKeeper v0.1
SeedKeeper is a smartcard device that can be used to securely store seeds and other sensitive data for long term protection.

- add support for perso pki
During personalization, each card (Satochip and SeedKeeper) can be optionally signed and certified by a PKI.
Each card generates its own private/public keypair that is signed by the PKI, and the certificte is stored inside the card for future validation.
This is not supported by Satochip applet version<12

## [0.11.4]: 

### Added 

- add this changelog
- add new check for error code returned by the card
- add MANIFEST.in

### Changed

- change some warning message

### Fixed

- include README.md, LICENSE & CHANGELOG.md to source distributable

## [0.11.3]:

### Added 

- add support for altcoin message signing in CardConnector.card_sign_message()

## [0.11.2]: 

#### Changed

- use ecdsa & pyaes libraries instead of cryptography for ecdh key exchange

## [0.11.1]: 

### Changed

- change License to LGPLv3
- minor code changes

## [0.11.a]: 

### Added

- Pysatochip v0.11.a - Initial commit
- WIP: Integration library with support for Satochip applet up to version 0.11.

