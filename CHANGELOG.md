# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.15.1]:

Add support for Seedkeeper v0.2:
* add support for BIP85 derivation for Masterseed secrets stored in seedkeeper (v0.2 only)
* add support for secret export to satochip using seedkeeper_export_secret_to_satochip()
* add seedkeeper_generate_random_secret() + seedkeeper_derive_master_password() + BIP39 Mnemonic v2 
* add NFC policy support (enable/disable/deactivate)
* implement new Factory Reset mechanism for SeedKeeper v0.2
* add support for secret reset
* Update test suite for seedkeeper

CLI:
* add support to get PIN data from environment variable 'PYSATOCHIP_PIN' when available

Factory reset:
* In CardConnector, use a flag 'mode_factory_reset' to switch in and out of factory reset mode. Flag must be set to True for reset factory
* Add card_reset_factory_signal() in CardConnector to send a reset-to-factory command. Several commands must be send to reset the card, with the card must be disconnected between each command.

Porting simplified PIN method from Pysatochip v0.12.6:
* Refactor & simplify PIN verification with new method card_verify_PIN_simple(). 
* State management when PIN verification fails (wrong PIN, card removed, Pin blocked...) is handled in the client app, not in pysatochip
* Remove some exception handling in card_transmit(), usually exceptions should be handled in calling method or in client app
* Get rid of most 'self.client.request()' callbacks, except for updating status when inserting/removing card physically
* Add more specific exceptions classes

Patches:
* Add SecureChannelError Exception class
* Update status after successful setup
* Raise specific error when card not setup during PIN verification

## [0.14.3]:

 - Add CLI to access module functionality (Including code from Seedkeeper & satodime tools)
 - Fix some bugs
 - Re-Org constants a bit for less duplication
 - More doc

To use the Command Line Interface, additional dependencies need to be installed using this command: `pip install "pysatochip[CLI]"` or `pip install -e ".[CLI]"` (local install). 

## [0.14.2]:

Some minor improvements & corrections to support Satochip & Satodime.
 - Patch https://github.com/Toporin/pysatochip/issues/3
 - Satodime support: add is_owner field
 - Satodime support: add key_tokenid_int field

## [0.14.1]:

- Add support for Satodime : the open-source bearer crypto card
Website: satodime.io
Github: https://github.com/Toporin/Satodime-Applet

### Added 
 
 - Add support for Satodime
 - Add test-subca-satochip certificate (for testing only)
 
### Changed

- Refactor card_select() to choose card_applets to select
    
    A list of targeted applets is provided in CardConnector constructor through variable 'card_filter'.
    When a card is inserted, the application only attempts to select these applets.
    Selection is attempted in the order in which the applets are listed in card_filter.
    Supported applets are 'satochip', 'seedkeeper' & 'satodime'

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

