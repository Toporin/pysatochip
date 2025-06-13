#!/usr/bin/env python3
#
# Copyright (c) 2023 Stephen Rothery - https://github.com/3rdIteration
# Includes code from SeedKeeper, Electrum-Satochip by Toporin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import traceback
from getpass import getpass
from hashlib import sha256
from os import urandom, environ
import base64
import cbor2 # for cashu
import binascii
import json
import logging
import sys
import time
from typing import Tuple, Dict, List, Any

import click
import websockets
import asyncio
import math
from ecdsa import SECP256k1, ECDH
from mnemonic import Mnemonic
from nostr.event import Event, EventKind
from smartcard.System import readers

from pysatochip.CardConnector import (CardConnector, IncorrectUnlockCodeError, IncorrectUnlockCounterError,
                                      IdentityBlockedError, WrongPinError, CardObjectAlreadyPresentError)
from pysatochip.JCconstants import *
from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST
from pysatochip.SecretDecryption import Decrypt_Secret
from pysatochip.electrum_mnemonic import Mnemonic as electrum_mnemonic
from pysatochip.electrum_mnemonic import seed_type as electrum_seedtype
from pysatochip.util import list_hyphenated_values, dict_swap_keys_values

# CardConnector Object used by everything
global cc

logging.basicConfig(level=logging.WARNING, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


def mnemonic_to_masterseed(bip39_mnemonic, bip39_passphrase, mnemonic_type):
    print(mnemonic_type)
    mnemonic_masterseed = None
    if "BIP39" in mnemonic_type:
        mnemonic_obj = Mnemonic("english")
        if mnemonic_obj.check(bip39_mnemonic):
            mnemonic_masterseed = Mnemonic.to_seed(bip39_mnemonic, bip39_passphrase)
        else:
            raise Exception("Invalid Mnemonic Checksum (Perhaps an Electrum seed?)")

    if "Electrum" in mnemonic_type:
        if len(electrum_seedtype(bip39_mnemonic)) > 0:
            mnemonic_masterseed = electrum_mnemonic.mnemonic_to_seed(bip39_mnemonic, bip39_passphrase)
        else:
            raise Exception("Invalid Mnemonic Checksum (Perhaps an BIP39 seed?)")

    return mnemonic_masterseed


def mnemonic_to_entropy(bip39_mnemonic, wordlist):
    print(f"Worldlist: {wordlist}")

    mnemonic_obj = Mnemonic(wordlist)
    entropy = mnemonic_obj.to_entropy(bip39_mnemonic)

    return entropy # bytearray


def entropy_to_mnemonic(entropy_bytes, wordlist):
    print(f"Worldlist: {wordlist}")

    mnemonic_obj = Mnemonic(wordlist)
    mnemonic = mnemonic_obj.to_mnemonic(entropy_bytes)

    return mnemonic # str


def do_challenge_response(msg):
    (id_2FA, msg_out) = cc.card_crypt_transaction_2FA(msg, True)
    d = {}
    d['msg_encrypt'] = msg_out
    d['id_2FA'] = id_2FA
    logger.info("id_2FA: " + id_2FA)

    reply_encrypt = None
    hmac = 20 * "00"  # bytes.fromhex(20*"00") # default response (reject)
    status_msg = ""
    for server in SERVER_LIST:
        print("Confirm Action on your 2fa device to proceed...")
        try:
            Satochip2FA.do_challenge_response(d, server_name=server)
            # decrypt and parse reply to extract challenge response
            reply_encrypt = d['reply_encrypt']
            break
        except Exception as e:
            status_msg += f"\nFailed to contact cosigner! \n=>trying another server\n\n"
            print(status_msg)
            # self.handler.show_error(f"No response received from '{server}', trying another server")
    if reply_encrypt is not None:
        reply_decrypt = cc.card_crypt_transaction_2FA(reply_encrypt, False)
        logger.info("challenge:response= " + reply_decrypt)
        reply_decrypt = reply_decrypt.split(":")
        hmac = reply_decrypt[1]
    return hmac  # return a hexstring


async def broadcast_event_async(event, relay_url):
    """Broadcasts a Nostr event to a relay via websocket"""
    logger.debug(f"Event string to publish: {event}")

    try:
        async with websockets.connect(relay_url) as websocket:
            logger.debug(f"Connected to {relay_url}")
            await websocket.send(event)

            print("Event sent, awaiting response...")

            response = await websocket.recv()
            print(f"Received response: {response}")

    except Exception as e:
        logger.warning(f"Error broadcasting event: {e}")


def broadcast_event(event, relay):
    """Synchronous wrapper for broadcast_event_async"""
    #loop = asyncio.get_event_loop()./
    loop = asyncio.new_event_loop()
    loop.run_until_complete(broadcast_event_async(event, relay))


# Accept any prefix of a command name.
#
# from <https://click.palletsprojects.com/en/8.0.x/advanced/?#command-aliases>
class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail(f"Too many matches: {', '.join(sorted(matches))}")

    def resolve_command(self, ctx, args):
        # always return the full command name
        _, cmd, args = super().resolve_command(ctx, args)
        return cmd.name, cmd, args


@click.command(cls=AliasedGroup)
@click.option("--verbose", is_flag=True, help="Provide detailed logs")
@click.option("--devicefilter", default=None, help="Filter only certain devices [satochip, seedkeeper, satodime]")
def main(verbose, devicefilter):

    loglevel = logging.WARNING
    if verbose:
        loglevel = logging.DEBUG
        logger.setLevel(loglevel)
        logger.debug("In main()")

    # Unless devicefilter has been specified, infer it based off the command (if possible)
    if not devicefilter:
        command_type = sys.argv[1].split("-")[0]
        if command_type in ["satochip", "seedkeeper", "satodime", "satocash"]:
            devicefilter = command_type

    if "util-" not in sys.argv[1][:5]:
        global cc
        # Connect to the card and get ready for a command
        cc = CardConnector(None, loglevel, devicefilter)

        time.sleep(1)  # give some time to initialize reader...
        try:
            status = cc.card_get_status()
        except Exception as ex:
            logger.critical("Card Connect Failed")
            exit(ex)

        if (cc.needs_secure_channel):
            cc.card_initiate_secure_channel()

        if status[3]['setup_done'] == False and cc.card_type != "Satodime":
            print()
            print("WARNING: Card Setup Not Complete, operating with default PIN")
            print(" (This state is only useful for Personalisation of PKI)")
            print("CARD NOT SAFE TO USE UNTIL SETUP COMPLETE")
            print("RUN CARD SETUP UNLESS YOU KNOW EXACTLY WHAT YOU ARE DOING!!!")
            print()
            cc.set_pin(0, [0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30]) #Default card PIN

    else:
        pass

    logger.debug("In main() end")

"""##############################
#        COMMON FUNCTIONS       #        
##############################"""

@main.command()
def common_get_card_type():
    """Return detected card type"""
    print(cc.card_type)

@main.command()
@click.option("--plain-apdu", default=None, help="APDU to Transmit (List of Bytes)")
def common_transmit(plain_apdu):
    """Transmits a plain APDU"""
    print(cc.card_transmit(plain_apdu))

@main.command()
def common_get_card_ATR():
    """Get ATR for Card"""
    print(cc.card_get_ATR())

@main.command()
def common_get_card_CPLC():
    """Get CPLC Data for Card"""
    print(cc.card_get_CPLC())

@main.command()
def common_get_card_IIN():
    """Get IIN for Card"""
    print(cc.card_get_IIN())

@main.command()
def common_get_card_CIN():
    """Get CIN for Card"""
    print(cc.card_get_CIN())

@main.command()
def common_get_card_uid_sha1():
    """Get the Serial Number for the Device (Used this as the Subject CN for a personalisation certificate)"""
    print(cc.UID_SHA1.lower())

@main.command()
def common_get_card_status():
    """Get a summary of the device status"""
    response, sw1, sw2, status_dic = cc.card_get_status()
    print(status_dic)

@main.command()
def common_get_card_label():
    """Retrieves the plain text label for the card"""
    try:
        if cc.card_type != "Satodime":
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
        (response, sw1, sw2, label) = cc.card_get_label()
        print("Device Label:", label)
    except Exception as e:
        print(e)

@main.command()
@click.option("--label", default="", help="Device Label.")
def common_set_card_label(label):
    """Sets a plain text label for the card (Optional)"""
    try:
        if cc.card_type != "Satodime":
            # TODO: for satodime, may fail if performed via NFC (needs ownership)
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
        (response, sw1, sw2) = cc.card_set_label(label)
        if sw1 != 0x90 or sw2 != 0x00:
            print("ERROR: Set Label Failed")
        else:
            print("Device Label Updated")
    except Exception as e:
        print(e)

@main.command()
def common_get_card_ndef():
    """Retrieves the ndef tag for the card"""
    try:
        if cc.card_type != "Satodime":
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
        (response, sw1, sw2, ndef_bytes) = cc.card_get_ndef()
        print("Device ndef:", ndef_bytes.hex())
    except Exception as e:
        print(e)

@main.command()
@click.option("--ndef", default="", help="Device NDEF in hexadecimal.")
def common_set_card_ndef(ndef):
    """Sets a ndef value for the card (Optional)
    For example:
    - google.com is 000fD1010B5502676F6F676C652E636F6D
    - Android app org.satochip.satodimeapp is 002Ad40f18616e64726f69642e636f6d3a706b676f72672e7361746f636869702e7361746f64696d65617070
    """
    try:
        if cc.card_type != "Satodime":
            # TODO: for satodime, may fail if performed via NFC (needs ownership)
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)

        ndef_bytes = bytes.fromhex(ndef)
        (response, sw1, sw2) = cc.card_set_ndef(ndef_bytes)
        if sw1 != 0x90 or sw2 != 0x00:
            print("ERROR: Set ndef Failed with error code: {hex(256*sw1+sw2)}")
        else:
            print("Device ndef Updated")
    except Exception as e:
        print(e)

@main.command()
@click.option("--nfc-policy", default=0, help="NFC Policy: 0 = NFC_ENABLED, 1 = NFC_DISABLED, 2 = NFC_BLOCKED")
def common_set_nfc_policy(nfc_policy):
    """Sets the NFC interface policy: enable/disable/block card communication through NFC.
    The default policy is 'NFC_ENABLED'. The NFC policy can only be set via the contact (USB) interface. 
    WARNING: if the policy is set to 2 (NFC_BLOCKED), it can only be reenabled through a factory reset!"""

    try:
        if (nfc_policy == 2):
            if click.confirm("Are you sure that you want to block NFC interface? NFC can only be reenabled with factory reset!", default=False):
                # we don't try to recover PIN from environment variables for destructive operations
                pin = getpass("Enter your PIN:") 
            else:
                print("Blocking NFC interface cancelled!")
                exit()
        else: 
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")

        cc.card_verify_PIN(pin)
        (response, sw1, sw2) = cc.card_set_nfc_policy(nfc_policy)
        if (sw1 == 0x90 and sw2 == 0x00):
            print("NFC policy applied successfully!")
        elif (sw1 == 0x9C and sw2 == 0x48):
            print("Cannot set the NFC policy through the NFC interface, use contact interface instead")
        elif (sw1 == 0x9C and sw2 == 0x49):
            print("Cannot set the NFC policy: NFC interface is BLOCKED, a factory reset is required to reenable NFC!")
        else:
            print(f"Failed to set NFC policy with error code: {hex(256*sw1+sw2)}")

    except Exception as e:
        print(e)

@main.command()
@click.option("--feature-id", default=0, help="Feature ID: 0 = FEATURE_ID_SCHNORR, 1 = FEATURE_ID_NOSTR, 2 = FEATURE_ID_LIQUID")
@click.option("--feature-policy", default=0, help="Feature Policy: 0 = FEATURE_ENABLED, 1 = FEATURE_DISABLED, 2 = FEATURE_BLOCKED")
def common_set_feature_policy(feature_id, feature_policy):
    """Sets the feature usage policy: enable/disable/block the feature with given ID.
    WARNING: if the policy is set to 2 (FEATURE_BLOCKED), it can only be reenabled through a factory reset!"""

    try:
        if (feature_policy == 2):
            if click.confirm("Are you sure that you want to block feature? Feature can only be reenabled with factory reset!", default=False):
                # we don't try to recover PIN from environment variables for destructive operations
                pin = getpass("Enter your PIN:")
            else:
                print("Blocking feature cancelled!")
                exit()
        else:
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")

        cc.card_verify_PIN(pin)
        (response, sw1, sw2) = cc.card_set_feature_policy(feature_id, feature_policy)
        if (sw1 == 0x90 and sw2 == 0x00):
            print("New feature policy applied successfully!")
        elif (sw1 == 0x9C and sw2 == 0x4B):
            print("Cannot set the feature policy: feature is BLOCKED, a factory reset is required to reenable it!")
        else:
            print(f"Failed to set feature policy with error code: {hex(256*sw1+sw2)}")

    except Exception as e:
        print(e)

@main.command()
@click.option("--label", default="", help="Card Label")
def common_initial_setup(label):
    """Run the initial card setup process"""

    if cc.card_type == "Satodime":
        pin_0 = list("1234".encode('utf8')) # This isn't actually used in Satodime, so can be anything
    else:
        pin = getpass("Enter your PIN:")
        pin2 = getpass("Enter your PIN again to confirm:")
        if pin != pin2:
            print("ERROR! The two PINs provided do not match! ")
            exit()
        pin_0 = list(pin.encode('utf8'))

    # Just stick with the defaults from SeedKeeper tool
    pin_tries_0 = 0x05
    ublk_tries_0 = 0x01
    # PUK code can be used when PIN is unknown and the card is locked
    # We use a random value as the PUK is not used currently and is not user friendly
    ublk_0 = list(urandom(16))
    pin_tries_1 = 0x01
    ublk_tries_1 = 0x01
    pin_1 = list(urandom(16))  # the second pin is not used currently
    ublk_1 = list(urandom(16))
    secmemsize = 32  # 0x0000 # => for satochip - TODO: hardcode value?
    memsize = 0x0000  # RFU
    create_object_ACL = 0x01  # RFU
    create_key_ACL = 0x01  # RFU
    create_pin_ACL = 0x01  # RFU

    (response, sw1, sw2) = cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0, pin_tries_1, ublk_tries_1, pin_1, ublk_1, secmemsize, memsize, create_object_ACL, create_key_ACL, create_pin_ACL, option_flags=0, hmacsha160_key=None, amount_limit=0)
    if sw1 != 0x90 or sw2 != 0x00:
        if cc.card_type == "Satodime":
            print("Error: Claim Satodime Ownership Failed")
        else:
            print("ERROR: Setup Failed")
        exit()
    else:
        if cc.card_type == "Satodime":
            print("Success: Satodime Ownership Claimed")
        else:
            print("Setup Succeeded")

    if cc.card_type == "Satodime":
        unlock_counter = response[0:SIZE_UNLOCK_COUNTER]
        unlock_secret = response[SIZE_UNLOCK_COUNTER:(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_SECRET)]
        print()
        print("Satodime Secrets (Needed to operate via NFC)")
        print("Unlock Secret:", bytes(unlock_secret).hex())
        print("Unlock Counter:", bytes(unlock_counter).hex())
        print()

    if len(label) > 0:
        common_set_card_label(["--label", label])

"""##############################
#        COMMON PIN MGMT        #        
##############################"""

@main.command()
def common_verify_PIN():
    """Verify that the pin supplied by --pin matches the current device pin"""
    try:
        pin = getpass("Enter your PIN:")
        (response, sw1, sw2) = cc.card_verify_PIN(pin)
        if sw1 != 0x90 or sw2 != 0x00:
            print("ERROR: Incorrect Pin Supplied")
        else:
            print("Correct Pin Verified")

    except Exception as e:
        print(e)

@main.command()
def common_change_PIN():
    """Change the card PIN"""

    pin = getpass("Enter your current PIN:")
    new_pin = getpass("Enter your new PIN:")
    new_pin2 = getpass("Confirm your new PIN:")
    if new_pin != new_pin2:
        print("ERROR! The two new PINs provided do not match!")
        exit()

    pin = list(pin.encode('utf8'))
    new_pin = list(new_pin.encode('utf8'))
    response, sw1, sw2 = cc.card_change_PIN(0, pin, new_pin)
    if sw1 == 0x90 and sw2 == 0x00:
        print("Success: Pin Changed")
    if sw1 == 0x63:
        print("Failed: Incorrect PIN")

"""##############################
#           COMMON PKI          #        
##############################"""

@main.command()
def common_export_perso_pubkey():
    """Export the personalisation pubkey from the device"""
    try:
        # PIN required except for satodime
        if cc.card_type != "Satodime":
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
        print(binascii.hexlify(bytearray(cc.card_export_perso_pubkey())).decode())
    except Exception as e:
        print(e)

@main.command()
@click.option("--cert", default=None, help="The device certificate (base64 encoded)")
@click.option("--cert-file", default=None, help="The device certificate file (base64 encoded)")
def common_import_perso_certificate(cert, cert_file):
    """Import a personalisation certificate into the device"""
    if cert_file:
        with open(cert_file, 'r', encoding='utf-8') as f:
                    cert = f.read()
        cert = cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")

    # TODO: can only import certificate before setup is done
    # no user pin required
    cc.card_import_perso_certificate(cert)

@main.command()
def common_export_perso_certificate():
    """Export the personalisation certificate that is on the device"""
    if cc.card_get_status()[3]['setup_done'] == False:
        print("Unable to perform this function until setup is complete")
        return
    try:
        # PIN required except for satodime
        if cc.card_type != "Satodime":
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
        print(cc.card_export_perso_certificate())
    except Exception as e:
        print(e)

@main.command()
@click.option("--privkey", default=None, help="The device NDEF authentikey to import (hex encoded)")
def common_import_ndef_authentikey(privkey):
    """Import the NDEF authentikey privkey on the card."""
    try:
        print(f"cardtype: {cc.card_type}")

        # PIN required except for satodime
        if cc.card_type != "Satodime":
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)

        privkey_bytes = bytes.fromhex(privkey)
        response, sw1, sw2 = cc.card_import_ndef_authentikey(privkey_bytes)

        print(f"response: {hex(sw1*256+sw2)}")

    except Exception as e:
        print(e)

@main.command()
def common_verify_authenticity():
    if cc.card_get_status()[3]['setup_done'] == False:
        print("Unable to perform this function until setup is complete")
        return

    """Verify the authenticy of the currently connected card"""
    try:

        # PIN required except for satodime
        if cc.card_type != "Satodime":
            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)

        is_authentic, txt_ca, txt_subca, txt_device, txt_error = cc.card_verify_authenticity()
        print("Card is authentic:", is_authentic)
        print("CA Cert:", txt_ca)
        print("SubCA Cert:", txt_subca)
        print("Device Cert:", txt_device)
        print("Error:", txt_error)
    except Exception as e:
        print(e)

"""##############################
#        SATOCHIP IMPORTS       #        
##############################"""

@main.command()
@click.option("--use-passphrase", is_flag=True, help="Use a BIP39 Passphrase")
def satochip_import_new_mnemonic(use_passphrase):
    """Generates and imports a new BIP39 mnemonic to the SatoChip Device"""
    if click.confirm("WARNING: This tool should only be used to generate a new seed if run in a secure, offline environment. (Like TAILS Linux)  \nAre you sure that you want to do this?", default=False):
        passphrase = ""
        if use_passphrase:
            passphrase = input("Enter your passphrase:")
        mnemo = Mnemonic("english")
        words = mnemo.generate(strength=256)
        seed = mnemo.to_seed(words, passphrase=passphrase)
        print("Mnemonic Words:", words)
        print("BIP39 Passphrase you entered:", passphrase)
        print("Be sure to note these words down...")
        if click.confirm(
                "WARNING: These seed words are your wallet, back them up in a secure, offline place and don't share them with anyone.  \nConfirm when you have written them down",
                default=False):
            try:
                # get PIN from environment variable or interactively
                if 'PYSATOCHIP_PIN' in environ:
                    pin= environ.get('PYSATOCHIP_PIN')
                    print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
                else:
                    pin = getpass("Enter your PIN:")
                cc.card_verify_PIN(pin)
                cc.card_bip32_import_seed(seed)
                print("Seed Successfully Imported")
            except Exception as e:
                print(e)

@main.command()
def satochip_import_unencrypted_masterseed():
    """Imports a BIP39 Seed (In Hexidecimal Format) to the SatoChip Device"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        seed = input("Enter your BIP39 Seed hex (Masterseed):") 
        cc.card_bip32_import_seed(seed)
        print("Seed Successfully Imported")
    except Exception as e:
        print(e)

@main.command()
@click.option("--use-passphrase", is_flag=True, help="Use a BIP39 Passphrase")
@click.option("--electrum", is_flag=True, help="Treat the seed as an Electrum Type seed (As opposed to BIP39)")
def satochip_import_unencrypted_mnemonic(use_passphrase, electrum):
    """Imports a mnemonic Seed (In Electrum or BIP39 Format) to the SatoChip Device"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        mnemonic_type = "BIP39"
        if electrum: 
            mnemonic_type = "Electrum"
        mnemonic = input("Enter your mnemonic seed:")
        passphrase = ""
        if use_passphrase:
            passphrase = input("Enter your passphrase:") 
        seed = mnemonic_to_masterseed(mnemonic, passphrase, mnemonic_type)
        cc.card_bip32_import_seed(seed)
        print("Seed Successfully Imported")
    except Exception as e:
        print(e)

@main.command()
@click.option("--json-file", required=True, help="A file containing the encrypted JSON Masterseed (Returned by seedkeeper_export_secret())")
def satochip_import_encrypted_masterseed(json_file):
    """Imports an encrypted seed backup. (The type typically exported from a SeedKeeper device)"""
    try:
        f = open(json_file)
        secret_json = json.load(f)

        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        cc.card_import_encrypted_secret(secret_json['secrets'][0])
        print("Success: Masterseed Imported")
    except Exception as e:
        print(e)

@main.command()
@click.option("--json-file", required=True, help="A file containing the encrypted JSON 2FA key (Returned by seedkeeper_export_secret())")
def satochip_import_encrypted_2fa_key(json_file):
    """Imports an encrypted seed backup. (The type typically exported from a SeedKeeper device)"""
    if click.confirm("WARNING: This will import AND enable 2FA on your Satochip device using the key provided. \nAre you sure that you want to do this?", default=False):
        try:
            f = open(json_file)
            secret_json = json.load(f)

            # get PIN from environment variable or interactively
            if 'PYSATOCHIP_PIN' in environ:
                pin= environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
            cc.card_import_encrypted_secret(secret_json['secrets'][0])
            print("Success: 2FA Key Imported and Enabled")
        except Exception as e:
            print(e)

@main.command()
@click.option("--pubkey", required=True, help="the pubkey in uncompressed form (65 bytes) as a hex_string or bytes or list of int")
def satochip_import_trusted_pubkey(pubkey):
    """Imports a trusted pubkey"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        pubkey_hex = cc.card_import_trusted_pubkey(pubkey)
        print(f"Successfully imported trusted_pubkey: {pubkey_hex}")
    except Exception as e:
        print(e)

@main.command()
def satochip_export_trusted_pubkey():
    """Exports the current trusted pubkey"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        print(cc.card_export_trusted_pubkey())
    except Exception as e:
        print(e)

@main.command()
def common_export_authentikey():
    """Exports the device Authentikey"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        print(cc.card_export_authentikey().get_public_key_hex(False))
    except Exception as e:
        print(e)

@main.command()
def satochip_reset_seed():
    """Wipes the seed that is currently on the device."""
    if click.confirm("Are you sure that you want to wipe the device seed? (This will cause an UNRECOVERABLE LOSS OF FUNDS if you don't have a working backup", default=False):
        try:
            # we don't try to recover PIN from environment variables for destructive operations
            pin = getpass("Enter your PIN:") 
            cc.card_verify_PIN(pin)
            if cc.needs_2FA:
                cc.card_bip32_get_authentikey()
                authentikeyx = bytearray(cc.parser.authentikey_coordx).hex()
                msg = {'action': "reset_seed", 'authentikeyx': authentikeyx}

                msg = json.dumps(msg)
                hmac = do_challenge_response(msg)

                # send request
                (response, sw1, sw2) = cc.card_reset_seed(cc.pin, hmac)

            else:
                (response, sw1, sw2) = cc.card_reset_seed(cc.pin)

            if (sw1 == 0x90 and sw2 == 0x00):
                print("Seed reset successfully!\nYou can now load a new seed")
            else:
                print(f"Failed to reset seed with error code: {hex(256*sw1+sw2)}")

        except Exception as e:
            print(e)

@main.command()
def satochip_bip32_get_authentikey():
    """Export the BIP32 Authentikey"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        print(cc.card_bip32_get_authentikey().get_public_key_hex(False))
    except Exception as e:
        print(e)

@main.command()
@click.option("--path", default="m/44'/0'/0'/0", help="path (str | bytes): the BIP32 path; if given as a string, it will be converted to bytes (4 bytes for each path index)")
def satochip_bip32_get_extendedkey(path):
    """Get extended pubkey and chaincode for a given derivation path (m/44'/0'/0'/0 by default)"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        (key, chaincode) = cc.card_bip32_get_extendedkey(path)
        print("Key: ", key.get_public_key_hex(True))
        print("Chaincode: ", chaincode.hex())
    except Exception as e:
        print(e)

@main.command()
@click.option("--path", default="m/44'/0'/0'/0", help="The BIP32 path to retrieve the xpub for")
@click.option("--xtype", default="standard", help="xtype (str): the type of transaction such as  'standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh'")
@click.option("--is-mainnet", default=True, help="is_mainnet (bool): is mainnet or testnet")
def satochip_bip32_get_xpub(path, xtype, is_mainnet):
    """Get extended public key (xpub) for a given derivation path (m/44'/0'/0'/0 by default) and script type (p2pkh by default)"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        print(cc.card_bip32_get_xpub(path, xtype, is_mainnet))
    except Exception as e:
        print(e)

@main.command()
def satochip_bip32_get_liquid_master_blinding_key():
    """Get the Liquid-Bitcoin Master Blinding Key. This is required on the host side to unblind output amounts in Liquid-Bitcoin confidential transactions"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        master_blinding_key = bytes(cc.card_bip32_get_liquid_master_blinding_key())
        print(f"Liquid-Bitcoin Master Blinding Key: {master_blinding_key.hex()}")

    except Exception as e:
        print(e)

"""##############################
#       SATOCHIP PRIVKEY        #        
##############################"""

@main.command()
@click.option("--keyslot", required=True, help="the keyslot where the key should be imported (0-16)")
@click.option("--privkey", required=True, help="the 32byte private key in hex format")
def satochip_import_privkey(keyslot, privkey):
    """Imports a given private ECkey into the card at given keyslot
    The keyslot provided should be available.
    The private key should be in hex format (exactly 64 hex chars)
    """
    try:
        keyslot = int(keyslot)
        # convert privkey hex to bytes
        privkey_bytes = bytes.fromhex(privkey)

        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        # check if 2FA is required
        if (cc.needs_2FA==None):
            (response, sw1, sw2, d) = cc.card_get_status()
        if cc.needs_2FA:
            raise ValueError("Required 2FA not supported currently!")
        # import private key
        cc.satochip_import_privkey(keyslot, privkey_bytes)
        print(f"Private key imported successfully!")

    except Exception as ex:
        print(f"Exception during private key import: {ex}")


@main.command()
@click.option("--keyslot", required=True, help="the keyslot where the key should be imported (0-16)")
def satochip_reset_privkey(keyslot):
    """Reset the private ECkey at given keyslot"""
    try:
        keyslot = int(keyslot)

        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        # check if 2FA is required
        hmac=b''
        if (cc.needs_2FA==None):
            (response, sw1, sw2, d) = cc.card_get_status()
        if cc.needs_2FA:
            raise ValueError("Required 2FA not supported currently!")
        # reset private key
        cc.satochip_reset_privkey(keyslot)
        print(f"Private key reset successfully!")

    except Exception as ex:
        print(f"Exception during private key import: {ex}")

@main.command()
@click.option("--keyslot", required=True, help="the keyslot where the key should be imported (0-16)")
def satochip_get_pubkey_from_keyslot(keyslot):
    """return the public key associated with a particular private key stored
    at a given keyslot.
    """
    try:
        keyslot = int(keyslot)

        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        # check if 2FA is required
        hmac=b''
        if (cc.needs_2FA==None):
            (response, sw1, sw2, d) = cc.card_get_status()
        if cc.needs_2FA:
            raise ValueError("Required 2FA not supported currently!")
        # export pubkey
        pubkey = cc.satochip_get_pubkey_from_keyslot(keyslot)
        print(f"pubkey for slot {keyslot}: {pubkey.get_public_key_bytes(compressed=False).hex()}")
        print(f"pubkey for slot {keyslot}: {pubkey.get_public_key_bytes(compressed=True).hex()}")

    except Exception as ex:
        print(f"Exception during private key import: {ex}")


"""##############################
#       SATOCHIP SIGNATURE      #        
##############################"""

@main.command()
@click.option("--keyslot", default="255", help="keyslot of the private key (for single-key wallet")
@click.option("--path", default="m/44'/0'/0'/0/0", help="path: the full BIP32 path of the address")
@click.option("--hash", required=True, help="The hash to sign as hex string")
def satochip_sign_hash(hash: str, keyslot, path):
    """Sign a hash with the Satochip"""

    hash_bytes = bytes.fromhex(hash)
    hash_list = list(hash_bytes)

    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        # check if 2FA is required
        hmac=b''
        if cc.needs_2FA is None:
            (response, sw1, sw2, d) = cc.card_get_status()
        if cc.needs_2FA:
            raise ValueError("Required 2FA not supported currently!")
        # derive key and sign message
        keyslot = int(keyslot)
        if keyslot == 0xFF:
            # 0xFF is for extended key, used if no keyslot is provided
            (depth, bytepath)= cc.parser.bip32path2bytes(path)
            (pubkey, chaincode)= cc.card_bip32_get_extendedkey(bytepath)
        (response2, sw1, sw2) = cc.card_sign_transaction_hash(keyslot, hash_list, hmac)
        if response2 == []:
            print("Wrong signature: the 2FA device may have rejected the action.")
        else:
            print("Signature (hex):", bytes(response2).hex())

    except Exception as e:
        print(e)

@main.command()
@click.option("--keyslot", default="255", help="keyslot of the private key (for single-key wallet")
@click.option("--path", default="m/44'/0'/0'/0/0", help="path: the full BIP32 path of the address")
@click.option("--hash", required=True, help="The hash to sign as hex string")
def satochip_sign_schnorr_hash(hash: str, keyslot, path):
    """Sign a hash with the Satochip using schnorr signature
    If keyslot is provided, use the private key loaded at given keyslot.
    Else if path is provided, use key derived from the BIP32 seed at given path.
    If none is provided, use default path m/44'/0'/0'/0/0 and BIP32 derivation.
    """

    # todo: check version support (must be >=0.14)

    hash_bytes = bytes.fromhex(hash)
    hash_list = list(hash_bytes)

    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        # check if 2FA is required
        hmac = None
        if cc.needs_2FA is None:
            (response, sw1, sw2, d) = cc.card_get_status()
        if cc.needs_2FA:
            raise ValueError("Required 2FA not supported currently!")
        # derive key
        keyslot = int(keyslot)
        if keyslot == 0xFF:
            # 0xFF is for extended key, used if no keyslot is provided
            (depth, bytepath) = cc.parser.bip32path2bytes(path)
            (pubkey, chaincode) = cc.card_bip32_get_extendedkey(bytepath)
            print(f"pubkey for BIP32 derivation: {pubkey.get_public_key_bytes(compressed=False).hex()}")
        else:
            pubkey = cc.satochip_get_pubkey_from_keyslot(keyslot)
            print(f"pubkey for slot {keyslot}: {pubkey.get_public_key_bytes(compressed=False).hex()}")

        # tweak key
        tweak = None
        (response, sw1, sw2) = cc.card_taproot_tweak_privkey(keyslot, tweak, bypass_flag=False)
        print(f"pubkey after tweak: {bytes(response).hex()}")

        # sign hash
        (response2, sw1, sw2) = cc.card_sign_schnorr_hash(keyslot, hash_list, hmac)
        if response2 == []:
            print("Wrong signature: the 2FA device may have rejected the action.")
        else:
            print("Signature (hex):", bytes(response2).hex())

    except Exception as e:
        print(e)


@main.command()
@click.option("--keyslot", default="255", help="keyslot of the private key (for single-key wallet")
@click.option("--path", default="m/44'/0'/0'/0/0", help="path: the full BIP32 path of the address")
@click.option("--message", prompt="Enter your message", help="Message for the Nostr event")
@click.option("--kind", default="1", help="Kind for the Nostr event")
@click.option("--broadcast", is_flag=True, default=False, help="Broadcast the event to the relay")
@click.option("--relay", default="wss://relay.damus.io", help="Nostr relay URL to use")
def satochip_sign_nostr_event(keyslot, path: str, message: str, kind: str, broadcast: bool, relay: str):
    """Sign a Nostr event with the Satochip using schnorr signature.
    The signed event can also be brodacasted on request.
    If keyslot is provided, use the private key loaded at given keyslot.
    Else if path is provided, use key derived from the BIP32 seed at given path.
    If none is provided, use default path m/44'/0'/0'/0/0 and BIP32 derivation.
    """

    # todo: check version support (must be >=0.14)

    # derive & export pubkey from card
    compressed_pubkey = None
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        # check if 2FA is required
        if cc.needs_2FA == None:
            (response, sw1, sw2, d) = cc.card_get_status()
        if cc.needs_2FA:
            raise ValueError("Required 2FA not supported currently!")

        # derive key
        keyslot = int(keyslot)
        if keyslot == 0xFF:
            # 0xFF is for extended key, used if no keyslot is provided
            (depth, bytepath) = cc.parser.bip32path2bytes(path)
            (pubkey, chaincode) = cc.card_bip32_get_extendedkey(bytepath)
            print(f"pubkey for BIP32 derivation: {pubkey.get_public_key_bytes(compressed=False).hex()}")
        else:
            pubkey = cc.satochip_get_pubkey_from_keyslot(keyslot)

        # export pubkey
        #pubkey = cc.satochip_get_pubkey_from_keyslot(keyslot)
        compressed_pubkey = pubkey.get_public_key_bytes(compressed=True).hex()
        print(f"Recovered pubkey: {compressed_pubkey}")

    except Exception as ex:
        print(f"Exception during public key export: {ex}")

    # Create Nostr event
    kind = int(kind)
    event = Event(
        kind=EventKind(kind),
        content=message,
        public_key=compressed_pubkey[2:] # remove compression byte
    )
    event_id = event.id
    print(f"Unsigned event: {event.to_message()}")
    print(f"Unsigned event id: {event_id}")

    # Sign the event
    signature = ""
    try:
        click.echo("Signing event")
        hash_bytes = bytes.fromhex(event_id)
        hash_list = list(hash_bytes)

        # tweak key (or bypass)
        # todo: currently bypass tweak by default
        tweak = None
        (response, sw1, sw2) = cc.card_taproot_tweak_privkey(keyslot, tweak, bypass_flag=True)
        print(f"pubkey after tweak: {bytes(response).hex()}")

        # sign hash
        hmac = None # 2FA not supported yet
        (response2, sw1, sw2) = cc.card_sign_schnorr_hash(keyslot, hash_list, hmac)
        if response2 == []:
            print("Wrong signature: the 2FA device may have rejected the action.")
        else:
            signature = str(bytes(response2).hex())

    except Exception as e:
        print(e)

    # Display, verify & broadcast the event
    event.signature = signature
    print(f"Signed event: {event.to_message()}")
    print(f"Signed event Hash: {event.id}")

    # Validate the Signature
    is_verified = event.verify()
    print(f"Signed event is_verified: {is_verified}")

    if broadcast:
        click.echo("\nBroadcasting event to relay...")
        broadcast_event(event.to_message(), relay)

@main.command()
@click.option("--keyslot", default="255", help="keyslot of the private key (for single-key wallet")
@click.option("--path", default="m/44'/0'/0'/0/0", help="path: the full BIP32 path of the address")
@click.option("--message", required=True, help="The message to sign")
def satochip_sign_message(message, keyslot, path):
    """Sign a Message with the Satochip"""
    message_byte = message.encode('utf8')

    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        # check if 2FA is required
        hmac=b''
        if (cc.needs_2FA==None):
            (response, sw1, sw2, d) = cc.card_get_status()
        if cc.needs_2FA:
            # challenge based on sha256(btcheader+msg)
            # format & encrypt msg
            msg = {'action':"sign_msg", 'msg':message}
            msg = json.dumps(msg)
            # do challenge-response with 2FA device...
            hmac = do_challenge_response(msg)
            hmac = bytes.fromhex(hmac)
        # derive key
        keyslot= int(keyslot)
        if keyslot == 0xFF:
            # 0xFF is for extended key, used if no keyslot is provided
            (depth, bytepath)= cc.parser.bip32path2bytes(path)
            (pubkey, chaincode)= cc.card_bip32_get_extendedkey(bytepath)
        else:
            pubkey = cc.satochip_get_pubkey_from_keyslot(keyslot)
        # sign message
        (response2, sw1, sw2, compsig) = cc.card_sign_message(keyslot, pubkey, message_byte, hmac)
        if  compsig == b'':
            print("Wrong signature: the 2FA device may have rejected the action.")
        else:
            print("Signature (Base64):", base64.b64encode(compsig).decode())

    except Exception as e:
        print(e)


@main.command()
@click.option("--keyslot", default="255", help="keyslot of the private key (for single-key wallet")
@click.option("--path", default="m/44'/0'/0'/0/0", help="path: the full BIP32 path of the address")
@click.option("--message", required=False, help="The message to sign as 0-32 bytes hex string")
@click.option("--aggpk", required=False, help="The aggregated pubkey as 32-byte hex string")
@click.option("--extra", required=False, help="Extra data as 0-32 bytes hex string")
def satochip_musig2_generate_nonce(keyslot, path, message, aggpk, extra):

    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        # derive key
        keyslot = int(keyslot)
        if keyslot == 0xFF:
            # 0xFF is for extended key, used if no keyslot is provided
            (depth, bytepath) = cc.parser.bip32path2bytes(path)
            (pubkey, chaincode) = cc.card_bip32_get_extendedkey(bytepath)

        # setup satochip using python3 -B satochip_cli.py common-initial-setup
        # first import test privkey "0202020202020202020202020202020202020202020202020202020202020202" in keyslot 1
        # using python3 -B satochip_cli.py satochip-import-privkey --keyslot 1 --privkey 0202020202020202020202020202020202020202020202020202020202020202
        # corresponding pubkey is 024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766
        # using python3 -B satochip_cli.py satochip-get-pubkey-from-keyslot --keyslot 1

        #aggpk = bytes.fromhex("0707070707070707070707070707070707070707070707070707070707070707")
        #msg = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        #msg = bytes.fromhex("")
        #msg = None
        #extra = bytes.fromhex("0808080808080808080808080808080808080808080808080808080808080808")
        # "expected_secnonce": "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
        # "expected_pubnonce": "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A"

        if aggpk is not None:
            aggpk = bytes.fromhex(aggpk)
        if message is not None:
            message = bytes.fromhex(message)
        if extra is not None:
            extra = bytes.fromhex(extra)

        pubnonce, encrypted_secnonce = cc.card_musig2_generate_nonce(keynbr=keyslot, aggpk=aggpk, msg=message, extra=extra)
        print(f"pubnonce: {pubnonce.hex()}")
        print(f"encrypted_secnonce: {encrypted_secnonce.hex()}")

    except Exception as e:
        print(e)


@main.command()
@click.option("--keyslot", default="255", help="keyslot of the private key (for single-key wallet")
@click.option("--path", default="m/44'/0'/0'/0/0", help="path: the full BIP32 path of the address")
@click.option("--secnonce", required=True, help="The encrypted secnonce as 144 bytes hex string")
@click.option("--b", required=True, help="The b value as 32 bytes hex string")
@click.option("--ea", required=True, help="The e*a as 32-byte hex string")
@click.option("--r_has_even_y", required=True, help="has_even_y(R) as true or false")
@click.option("--ggacc_is_1", required=True, help="true if g*gacc is equal to 1, false otherwise")
def satochip_musig2_sign_hash(keyslot, path, secnonce, b, ea, r_has_even_y, ggacc_is_1):

    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        # derive key
        keyslot = int(keyslot)
        if keyslot == 0xFF:
            # 0xFF is for extended key, used if no keyslot is provided
            (depth, bytepath) = cc.parser.bip32path2bytes(path)
            (pubkey, chaincode) = cc.card_bip32_get_extendedkey(bytepath)

        # test vector
        # setup satochip using python3 -B satochip_cli.py common-initial-setup
        # first import test privkey 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671 in keyslot
        # using python3 -B satochip_cli.py satochip-import-privkey --keyslot 0 --privkey 7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671
        # corresponding pubkey is 03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9
        # using python3 -B satochip_cli.py satochip-get-pubkey-from-keyslot --keyslot 0

        #secnonce = bytes.fromhex("508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9")
        # b = bytes.fromhex("f6311d2583176bb178ec12973b760a2d733544d4c72b4b3a8c260f7679f7d9c6")
        # ea = bytes.fromhex("f696bb3be7fc4ee399c173813d0bddded1471cfe8acf5f729b1610d489eb3600")
        # r_has_even_y = False
        # ggacc_is_1 = True
        # psig_expected = "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB"

        secnonce = bytes.fromhex(secnonce)
        secnonce = secnonce + (144 - len(secnonce)) * bytes.fromhex("00")  # pad to reach 144 bytes

        b = bytes.fromhex(b)
        ea = bytes.fromhex(ea)
        r_has_even_y = (r_has_even_y.lower() == "true")
        print(f"r_has_even_y: {r_has_even_y}")
        ggacc_is_1 = (ggacc_is_1.lower() == "true")
        print(f"ggacc_is_1: {ggacc_is_1}")

        psig = cc.card_musig2_sign_hash(keynbr=keyslot, secnonce=secnonce, b=b, ea=ea, r_has_even_y=r_has_even_y, ggacc_is_1=ggacc_is_1)
        print(f"psig: {psig.hex()}")

    except Exception as e:
        print(e)




"""##############################
#          SATOCHIP 2FA         #        
##############################"""

@main.command()
def satochip_import_unencrypted_2fa_key():
    """Imports an encrypted seed backup. (The type typically exported from a SeedKeeper device)"""
    try:
        if click.confirm("WARNING: This will import AND enable 2FA on your Satochip device using the key provided. \nAre you sure that you want to do this?", default=False):
            # we don't try to recover PIN from evironment variables for particularly sensitive operations
            pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
            
            key = input("Enter your 2FA key (in hex):")
            cc.card_set_2FA_key(key)
            print("Success: 2FA Key Imported and Enabled")
    except Exception as e:
        print(e)

@main.command()
def satochip_disable_2fa():
    """Disables 2fa on the Satochip."""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        msg = {'action': "reset_2FA"}
        msg = json.dumps(msg)

        hmac = do_challenge_response(msg)

        # send request
        (response, sw1, sw2) = cc.card_reset_2FA_key(hmac)

        if (sw1 == 0x90 and sw2 == 0x00):
            print("2fa reset successfully!")
        else:
            print(f"Failed to reset 2fa with error code: {hex(256*sw1+sw2)}")

    except Exception as e:
        print(e)

"""##############################
#           FACTORY RESET       #
##############################"""

@main.command()
def common_reset_factory():
    """Initiate the card Factory Reset Process using the legacy or new approach based on card type and version

    factory reset support:
    SeedKeeper: all versions support factory reset
    Satodime: no factory reset support (simply reset all vaults on the card)
    Satochip: factory reset introduced in v0.12-0.4
    
    new version currently only implemented on SeedKeeper v0.2 and higher
    """

    if cc.card_type == "SeedKeeper":
        # get version
        (response, sw1, sw2, d) = cc.card_get_status()
        version = d["protocol_version"]
        if (version >= 2):
            print("This SeedKeeper supports factory reset (new version)!")
            common_reset_factory_new()
        else: 
            print("This SeedKeeper supports factory reset (legacy)!")
            common_reset_factory_legacy()
    
    elif cc.card_type == "Satodime":
        print("Satodime does not support factory reset!")
        return

    elif cc.card_type == "Satochip":
        # get version
        (response, sw1, sw2, d) = cc.card_get_status()
        version = ((d["protocol_major_version"]<<24)
                    + (d["protocol_minor_version"]<<16)
                    + (d["applet_major_version"]<<8)
                    + (d["applet_minor_version"]))
        version_min = (12<<16)+4 # v0.12-0.4
        if (version >= version_min):
            print("This Satochip supports factory reset (legacy)!")
            common_reset_factory_legacy() 
        else:
            print("Satochip below version v0.12-0.4 do not support factory reset!")
            return

    elif cc.card_type == "Satocash":
        # satocash only supports factory reset v2
        common_reset_factory_new()

    else:
        print(f"Unsupported card type: {cc.card_type}")
        return

    return


def common_reset_factory_legacy():
    """Initiate the Factory Reset Process
    Legacy approach based on sending a specifi APDU a certain number of time
    """    
    print("WARNING: FACTORY RESET WITHOUT A WORKING BACKUP WILL LEAD TO UNRECOVERABLE LOSS OF FUNDS")
    logger.info("In common_reset_factory_legacy")
    apdu = [0xB0, 0xFF, 0x00, 0x00, 0x00]  # Reset APDU
    while(True):
        if click.confirm("Are you sure that you want to perform a factory reset?", default=False):
            (response, sw1, sw2) = cc.card_transmit(apdu)
            if sw1 == 0x9c and sw2 == 0x04:
                print("Factory Reset Failed (setup not done)")
                #print("In addition to the factory-reset command, you also need to add the '--enablefactoryreset' argument to enable it")
                break
            if sw1 == 0x00 and sw2 == 0x00:
                print("Card Connection Failed!")
                break
            if sw1 == 0xFF and sw2 == 0x00:
                cc.card_disconnect()
                print("CARD HAS BEEN RESET TO FACTORY!")
                break
            elif sw1 == 0xFF and sw2 == 0xFF:
                print("RESET ABORTED: you must remove card after each reset!")
                break
            elif sw1 == 0xFF and sw2 > 0x00:
                print("Remaining counter: " + str(sw2))
                print("Please remove and reinsert card, then confirm that you want to continue...")
            elif sw1 == 0x6F and sw2 == 0x00:
                print("The factory reset failed")
                print("Unknown error" + str(hex(256 * sw1 + sw2)))
                break
            elif sw1 == 0x6D and sw2 == 0x00:
                print("The factory reset failed")
                print("Instruction not supported - error code: " + str(hex(256 * sw1 + sw2)))
                break
            else:
                print("The factory reset has been cancelled")
                break
    return

def common_reset_factory_new():
    """Initiate the Factory Reset Process
    New approach where reset to factory is trigerred when PIN and PUK is blocked (the card is basically unusable in this state)
    """ 
    print("WARNING: FACTORY RESET WITHOUT A WORKING BACKUP WILL LEAD TO UNRECOVERABLE LOSS OF FUNDS")
    logger.info("In common_reset_factory_new")

    pinRemaining = -1
    doReset = click.confirm("Are you sure that you want to perform a factory reset?", default=False)
    # Block PIN
    while(doReset):
        
        pin = getpass("Enter a wrong PIN to block the card, or the correct PIN to abort:")
        if len(pin)<4:
            print("PIN code too short, factory reset is aborted")
            doReset = False
            break

        try:
            (response, sw1, sw2)= cc.card_verify_PIN(pin)
            if sw1 == 0x90 and sw2 == 0x00:
                print("You have entered a correct PIN, factory reset is aborted")
                doReset = False
                pinRemaining = -1
                break
        except IdentityBlockedError as ex:
            # PIN blocked, PUK next
            #print(ex)
            print("PIN code is blocked!")
            pinRemaining = 0
            break
        except WrongPinError as ex:
            print(ex)
            print(f"pinRemaining: {ex.pin_left}")
        except Exception as ex:
            print(ex)

    # Block PUK
    pukRemaining = -1
    while(doReset):
        
        puk = getpass("Enter a wrong PUK to block the card, or the right PUK to abort:")
        puk_list = list(puk.encode('utf-8'))
        if len(puk_list)<4:
            print("PUK code too short, factory reset is aborted")
            doReset = False
            break

        try:
            (response, sw1, sw2)= cc.card_unblock_PIN(0, puk_list)
            if sw1 == 0x90 and sw2 == 0x00:
                print("You have entered a correct PUK, factory reset is aborted, PIN is unblocked")
                doReset = False
                pinRemaining = -1
                pukRemaining = -1
                break
            elif sw1==0x63 and (sw2 & 0xc0)==0xc0:
                #wrong puk
                pukRemaining= (sw2 & ~0xc0)
                msg = (f"Wrong PUK! {pukRemaining} tries remaining!")
                print(msg)
            elif sw1==0x9c and sw2==0x0c:
                # should not happen actually, since reset to factory is triggered before
                pukRemaining = 0
                print(f"PUK blocked!")
            elif sw1 == 0xFF and sw2 == 0x00:
                # Card reset to factory
                pinRemaining = -1
                pukRemaining = -1
                print(f"CARD RESET TO FACTORY!")
                return
            else:
                print(f"Unexpected error (error code {hex(256*sw1+sw2)})")

        except Exception as ex:
            print(ex)
            

    if doReset == False:
        print("Reset factory aborted")
        if pinRemaining != -1:
            print(f"WARNING: remaining PIN tries: {pinRemaining}")
        if pukRemaining != -1:
            print(f"WARNING: remaining PIN tries: {pinRemaining}")

    return

"""##############################
#           SEEDKEEPER          #        
##############################"""

@main.command()
def seedkeeper_get_card_status():
    """Return status info specific to SeedKeeper"""

    # get PIN from environment variable or interactively
    if 'PYSATOCHIP_PIN' in environ:
        pin= environ.get('PYSATOCHIP_PIN')
        print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
    else:
        pin = getpass("Enter your PIN:")
    cc.card_verify_PIN(pin)

    response, sw1, sw2, dic = cc.seedkeeper_get_status()
    print(f"nb_secrets: {dic['nb_secrets']}")
    print(f"total_memory: {dic['total_memory']}")
    print(f"free_memory: {dic['free_memory']}")
    print(f"nb_logs_total: {dic['nb_logs_total']}")
    print(f"nb_logs_avail: {dic['nb_logs_avail']}")
    print(f"last_log: {dic['last_log']}")

@main.command()
@click.option("--label", required=True, help="Label for the secret")
@click.option("--export-rights", required=True, help="Export Rights for the secret")
@click.option("--size", type=int, default=64, help="Size (In Bytes) of the Masterseed (BIP39 default is 64 Bytes)")
def seedkeeper_generate_masterseed(label, export_rights, size):
    """Generate a Masterseed On-Card"""
    if export_rights not in list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS):
        print("INVALID EXPORT RIGHTS, must be one of:", list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS))
        exit()

    export_rights = export_rights.replace("_", " ")
    export_rights = dict_swap_keys_values(SEEDKEEPER_DIC_EXPORT_RIGHTS)[export_rights]

    # get PIN from environment variable or interactively
    if 'PYSATOCHIP_PIN' in environ:
        pin= environ.get('PYSATOCHIP_PIN')
        print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
    else:
        pin = getpass("Enter your PIN:")
    cc.card_verify_PIN(pin)
    (response, sw1, sw2, sid, fingerprint) = cc.seedkeeper_generate_masterseed(size, export_rights, label)

    print("Imported - SID:", sid, " Fingerprint:", fingerprint)

@main.command()
@click.option("--label", required=True, help="Label for the secret")
@click.option("--export-rights", required=True, help="Export Rights for the secret")
def seedkeeper_generate_2fa_secret(label, export_rights):
    """Generate a 2fa Secret On-Card"""
    if export_rights not in list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS):
        print("INVALID EXPORT RIGHTS, must be one of:", list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS))
        exit()

    export_rights = export_rights.replace("_", " ")
    export_rights = dict_swap_keys_values(SEEDKEEPER_DIC_EXPORT_RIGHTS)[export_rights]

    # get PIN from environment variable or interactively
    if 'PYSATOCHIP_PIN' in environ:
        pin= environ.get('PYSATOCHIP_PIN')
        print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
    else:
        pin = getpass("Enter your PIN:")
    cc.card_verify_PIN(pin)
    (response, sw1, sw2, sid, fingerprint) = cc.seedkeeper_generate_2FA_secret(export_rights, label)

    print("Imported - SID:", sid, " Fingerprint:", fingerprint)


@main.command()
@click.option("--type", required=True, help="Type of secret to generate (Masterseed, Private_Key, Secret_Key, Master_Password)")
@click.option("--subtype", type=int, default=0, help="Further specify type of secret, default = 0 (unspecified). To be detailed!")
@click.option("--size", type=int, default=64, help="Size (in bytes) of the Secret")
@click.option("--label", required=True, help="Label for the secret")
@click.option("--export-rights", required=True, help="Export Rights for the secret")
@click.option("--save-entropy", is_flag=True, help="Save entropy used for secret generation")
@click.option("--entropy", required=True, help="External entropy used during secret generation")
def seedkeeper_generate_random_secret(type, subtype, size, label, export_rights, save_entropy, entropy):
    """Generate a random Secret on-card"""

    # print(f"type: {type}")
    # print(f"subtype: {subtype}")
    # print(f"size: {size}")
    # print(f"label: {label}")
    # print(f"export_rights: {export_rights}")
    # print(f"save_entropy: {save_entropy}")
    # print(f"entropy: {entropy}")

    # Check if secret type and export rights are valid options
    if type not in ["Private_Key", "Secret_Key", "Master_Password", "Masterseed"]:
        print(f"INVALID SECRET TYPE, must be one of: [Private_Key, Secret_Key, Master_Password, Masterseed]")
        exit()
    if export_rights not in list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS):
        print("INVALID EXPORT RIGHTS, must be one of:", list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS))
        exit()

    type = type.replace("_", " ")
    type = dict_swap_keys_values(SEEDKEEPER_DIC_TYPE)[type]

    export_rights = export_rights.replace("_", " ")
    export_rights = dict_swap_keys_values(SEEDKEEPER_DIC_EXPORT_RIGHTS)[export_rights]

    # get PIN from environment variable or interactively
    if 'PYSATOCHIP_PIN' in environ:
        pin= environ.get('PYSATOCHIP_PIN')
        print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
    else:
        pin = getpass("Enter your PIN:")
    cc.card_verify_PIN(pin)
    (response, sw1, sw2, dic) = cc.seedkeeper_generate_random_secret(type, subtype, size, export_rights, label, save_entropy, entropy)
    if sw1 == 0x90 and sw2 == 0x00:
        print(f"Random secret generated successfully: {dic}")
    else:
        print(f"Failed to generate random secret with error code {hex(256*sw1+sw2)}")


@main.command()
@click.option("--salt", required=True, help="Salt used to derive the master password (max 128 bytes)")
@click.option("--sid", type=int, required=True, help="SecretID (As per the list-secret-headers command)")
@click.option("--pubkey-id", type=int, default=None, help="Public Key ID used to encrypt the secret (Optional) Note: Must be the ID of a 'secret' of the type 'Public Key', visible when using the command 'seedkeeper-list-secret-headers'")
def seedkeeper_derive_master_password(salt, sid, pubkey_id):
    """Derive data from a master password with provided Salt"""

    # get PIN from environment variable or interactively
    if 'PYSATOCHIP_PIN' in environ:
        pin= environ.get('PYSATOCHIP_PIN')
        print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
    else:
        pin = getpass("Enter your PIN:")
    cc.card_verify_PIN(pin)

    # 
    (response, sw1, sw2, dic) = cc.seedkeeper_derive_master_password(salt, sid, pubkey_id)
    if sw1 == 0x90 and sw2 == 0x00:
        derived_data_hex= dic["derived_data"]
        print(f"derived_data: {derived_data_hex}")
    else:
        print(f"failed to derive data with error code {hex(256*sw1+sw2)}")


@main.command()
@click.option("--type", required=True, help="Plaintext file with secret to import (Raw secret-dict)")
@click.option("--subtype", type=int, default=0, help="Further specify type of secret, default = 0 (unspecified). To be detailed!")
@click.option("--label", required=True, help="Label for the secret")
@click.option("--export-rights", required=True, help="Export Rights for the secret")
@click.option("--use-passphrase", is_flag=True, help="Use a BIP39 Passphrase")
@click.option("--wordlist", default="english", help="Define which worldlist (language) to use for BIP39 v2")
def seedkeeper_import_secret(type, subtype, label, export_rights, use_passphrase, wordlist):
    """Import a Secret into the Seedkeeper"""

    # get PIN from environment variable or interactively
    if 'PYSATOCHIP_PIN' in environ:
        pin= environ.get('PYSATOCHIP_PIN')
        print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
    else:
        pin = getpass("Enter your PIN:")
    cc.card_verify_PIN(pin)

    # Check if secret type and export rights are valid options
    if type not in list_hyphenated_values(SEEDKEEPER_DIC_TYPE):
        print("INVALID SECRET TYPE, must be one of:",list_hyphenated_values(SEEDKEEPER_DIC_TYPE))
        exit()

    if export_rights not in list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS):
        print("INVALID EXPORT RIGHTS, must be one of:",list_hyphenated_values(SEEDKEEPER_DIC_EXPORT_RIGHTS))
        exit()

    # Swap underscores for spaces... Simplest solution to keep click happy and still use types directly from the dictionaries
    export_rights = export_rights.replace("_", " ")
    type = type.replace("_", " ")
    header = cc.make_header(type, export_rights, label, subtype= subtype)
    
    # get secret and optionnaly passphrase
    secret = input("Enter your secret:")
    bip39_passphrase = "" # default
    if use_passphrase:
        bip39_passphrase = input("Enter your BIP39 passphrase:")

    if type in ['Password', 'Master Password']:
        password_list = list(bytes(secret, 'utf-8'))
        secret_list = [len(password_list)] + password_list

    elif type in ['BIP39 mnemonic', 'Electrum mnemonic']:
        bip39_mnemonic_list = list(bytes(secret, 'utf-8'))
        bip39_passphrase_list = list(bytes(bip39_passphrase, 'utf-8'))

        print([len(bip39_mnemonic_list)])
        print(bip39_mnemonic_list)
        print([len(bip39_passphrase_list)])
        print(bip39_passphrase_list)

        secret_list = [len(bip39_mnemonic_list)] + bip39_mnemonic_list + [
            len(bip39_passphrase_list)] + bip39_passphrase_list

    #elif type == 'BIP39 mnemonic v2':
    elif type == 'Masterseed' and subtype == 0x01: # Masterseed with BIP39 info
        
        #todo check worldlist is supported
        wordlist_byte = dict_swap_keys_values(BIP39_WORDLIST_DIC).get(wordlist)
        if wordlist_byte == None:
            print(f"Error: wordlist {wordlist} unsupported!")
            exit()

        try:
            bip39_entropy_bytes = mnemonic_to_entropy(secret, wordlist)
            bip39_entropy_list = list(bip39_entropy_bytes)
        except Exception as ex:
            exit()
        bip39_passphrase_list = list(bytes(bip39_passphrase, 'utf-8'))
        try:
            masterseed_bytes= mnemonic_to_masterseed(secret, bip39_passphrase, 'BIP39 mnemonic')
            masterseed_list = list(masterseed_bytes)
        except Exception as e:
            exit(e)

        # this format is backward compatible with Masterseed, this facilitates encrypted export to satochip
        secret_list = ([len(masterseed_list)] + 
                        masterseed_list + 
                        [wordlist_byte] + 
                        [len(bip39_entropy_list)] + 
                        bip39_entropy_list + 
                        [len(bip39_passphrase_list)] + 
                        bip39_passphrase_list
                        )
    elif type == 'Public Key':
        secret_list = list(bytes.fromhex(secret))
        secret_list = [len(secret_list)] + secret_list
    else:
        secret_list = list(bytes.fromhex(secret))

    secret_dic = {'header': header, 'secret_list': secret_list}
    (sid, fingerprint) = cc.seedkeeper_import_secret(secret_dic)
    print("Imported - SID:", sid, " Fingerprint:", fingerprint)

    # convert to masterseed in case of mnemonic
    if type in ['BIP39 mnemonic', 'Electrum mnemonic']:
        print("Converting to Masterseed and storing in both formats... (To allow use directly in Satochip)")
        try:
            mnemonic_masterseed = mnemonic_to_masterseed(secret, bip39_passphrase, type)
        except Exception as e:
            exit(e)

        masterseed_secret_list = list(mnemonic_masterseed)
        masterseed_header = cc.make_header("Masterseed", export_rights, "Masterseed from mnemonic '" + label + "'")

        masterseed_secret_list = [len(masterseed_secret_list)] + masterseed_secret_list
        secret_dic = {'header': masterseed_header, 'secret_list': masterseed_secret_list}
        (sid, fingerprint) = cc.seedkeeper_import_secret(secret_dic)
        print("Imported - SID:", sid, " Fingerprint:", fingerprint)


@main.command()
@click.option("--json-file", help="A JSON file containing an encrypted secret")
@click.option("--pubkey-id", type=int, default=None, help="Public Key ID used to decrypt the encrypted secret Note: Must be the ID of a 'secret' of the type 'Public Key', visible when using the command 'seedkeeper-list-secret-headers'")
def seedkeeper_import_secret_from_json(json_file, pubkey_id):
    """Import a Secret into the Seedkeeper from a json file"""
    try:
        f = open(json_file)
        secret_json = json.load(f)

        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        if secret_json['authentikey_importer'] != cc.card_export_authentikey().get_public_key_hex(False):
            print("IMPORT FAILED: Device Authentikey doesn't match the Trusted Pubkey required to import this file...")
            print("Required Authentikey:", secret_json['authentikey_importer'])
            print("Device Authentikey:  ", cc.card_export_authentikey().get_public_key_hex(False))
            exit()
        for secret_dic in secret_json['secrets']:
            (sid, fingerprint) = cc.seedkeeper_import_secret(secret_dic, pubkey_id)
            print("Imported - SID:", sid, " Fingerprint:", fingerprint)
    except Exception as e:
        print(e)
        print("IMPORT FAILED: Incorrect pubkey selected for import, or import data is invalid/corrupt")

@main.command()
@click.option("--sid", type=int, required=True, help="SecretID (As per the list-secret-headers command)")
@click.option("--pubkey-id", type=int, default=None, help="Public Key ID used to encrypt the secret (Optional) Note: Must be the ID of a 'secret' of the type 'Public Key', visible when using the command 'seedkeeper-list-secret-headers'")
@click.option("--export-dict", is_flag=True, help="Export the data in a raw format (That can be directly imported)")
def seedkeeper_export_secret(sid, pubkey_id, export_dict):
    """Export a Secret from the Seedkeeper"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        secret_dict = cc.seedkeeper_export_secret(sid, pubkey_id)
        if export_dict:
            print(secret_dict)
        else:
            stype = SEEDKEEPER_DIC_TYPE.get(secret_dict['type'], hex(secret_dict['type']))  # hex(header['type'])
            subtype = secret_dict['subtype']
            origin = SEEDKEEPER_DIC_ORIGIN.get(secret_dict['origin'], hex(secret_dict['origin']))  # hex(header['origin'])
            export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(secret_dict['export_rights'],
                                                             hex(secret_dict['export_rights']))  # str(header['export_rights'])

            print("Secret Label: ", secret_dict['label'])
            print("Secret Type: ", stype)
            print("Secret Origin: ", origin)
            print("Export Rights: ", export_rights)
            print("Number of Exports (Plain):", secret_dict['export_nbplain'])
            print("Number of Exports (Secure):", secret_dict['export_nbsecure'])

            if pubkey_id is None: #If we are exporting in the clear
                #if 'mnemonic' in stype:
                if stype in ['BIP39 mnemonic', 'Electrum mnemonic']:
                    
                    offset = 0
                    secret_raw_hex = secret_dict['secret']
                    logger.info(f"secret_raw_hex: {secret_raw_hex}")
                    secret_raw_bytes = bytes.fromhex(secret_raw_hex)
                    
                    mnemonic_size = secret_raw_bytes[offset]
                    offset+=1

                    mnemonic_bytes = secret_raw_bytes[offset:(offset+mnemonic_size)]
                    offset+=mnemonic_size
                    try:
                        mnemonic = mnemonic_bytes.decode("utf-8")
                    except Exception as ex:
                        logger.warning(f"Error during mnemonic decoding: {ex}")
                        mnemonic = f"failed to decode mnemonic bytes: {mnemonic_bytes.hex()}"

                    passphrase_size= secret_raw_bytes[offset]
                    offset+=1

                    passphrase_bytes= secret_raw_bytes[offset: (offset+passphrase_size)]
                    offset+=passphrase_size
                    try:
                        passphrase = passphrase_bytes.decode("utf-8")
                    except Exception as ex:
                        logger.warning(f"Error during passphrase decoding: {ex}")
                        passphrase = f"failed to decode passphrase bytes: {passphrase_bytes.hex()}"

                    secret_string= f'\nMnemonic: "{mnemonic}" \nPassphrase: "{passphrase}"'  

                # elif stype == 'BIP39 mnemonic v2':
                #     # mnemonic in compressed format using entropy (16-32 bytes)
                #     offset = 0
                #     secret_raw_hex = secret_dict['secret']
                #     logger.info(f"secret_raw_hex: {secret_raw_hex}")
                #     secret_raw_bytes = bytes.fromhex(secret_raw_hex)
                    
                #     wordlist_byte = secret_raw_bytes[offset]
                #     offset+=1
                #     wordlist = BIP39_WORDLIST_DIC.get(wordlist_byte)
                #     if wordlist == None:
                #         logger.critical(f"Error: wordlist byte {wordlist_byte} unsupported!")
                #         exit()
                    
                #     entropy_size = secret_raw_bytes[offset]
                #     offset+=1

                #     entropy_bytes = secret_raw_bytes[offset:(offset+entropy_size)]
                #     offset+=entropy_size
                #     try:
                #         bip39_mnemonic = entropy_to_mnemonic(entropy_bytes, wordlist)
                #     except Exception as ex:
                #         logger.warning(f"Error during entropy conversion: {ex}")
                #         bip39_mnemonic = f"failed to convert entropy: {entropy_bytes.hex()}"

                #     passphrase_size= secret_raw_bytes[offset]
                #     offset+=1

                #     passphrase_bytes= secret_raw_bytes[offset: (offset+passphrase_size)]
                #     offset+=passphrase_size
                #     try:
                #         passphrase = passphrase_bytes.decode("utf-8")
                #     except Exception as ex:
                #         logger.warning(f"Error during passphrase decoding: {ex}")
                #         passphrase = f"failed to decode passphrase bytes: {passphrase_bytes.hex()}"

                #     masterseed_size = secret_raw_bytes[offset]
                #     offset+=1

                #     masterseed_bytes= secret_raw_bytes[offset: (offset+masterseed_size)]
                #     offset+=masterseed_size
                #     masterseed_hex= masterseed_bytes.hex()

                #     secret_string= f'\nWordlist: {wordlist} \nBIP39 mnemonic: "{bip39_mnemonic}" \nPassphrase: "{passphrase}" \nMasterseed: {masterseed_hex}'  

                #elif stype == 'BIP39 mnemonic v2':
                elif stype == 'Masterseed' and subtype==0x01:
                    # this format is backward compatible with Masterseed (BIP39 info appended after Masterseed)
                    # mnemonic in compressed format using entropy (16-32 bytes)
                    secret_raw_hex = secret_dict['secret']
                    logger.info(f"secret_raw_hex: {secret_raw_hex}")
                    secret_raw_bytes = bytes.fromhex(secret_raw_hex)
                    
                    offset = 0
                    masterseed_size = secret_raw_bytes[offset]
                    offset+=1

                    masterseed_bytes= secret_raw_bytes[offset: (offset+masterseed_size)]
                    offset+=masterseed_size
                    masterseed_hex= masterseed_bytes.hex()

                    wordlist_byte = secret_raw_bytes[offset]
                    offset+=1
                    wordlist = BIP39_WORDLIST_DIC.get(wordlist_byte)
                    if wordlist == None:
                        logger.critical(f"Error: wordlist byte {wordlist_byte} unsupported!")
                        exit()
                    
                    entropy_size = secret_raw_bytes[offset]
                    offset+=1

                    entropy_bytes = secret_raw_bytes[offset:(offset+entropy_size)]
                    offset+=entropy_size
                    try:
                        bip39_mnemonic = entropy_to_mnemonic(entropy_bytes, wordlist)
                    except Exception as ex:
                        logger.warning(f"Error during entropy conversion: {ex}")
                        bip39_mnemonic = f"failed to convert entropy: {entropy_bytes.hex()}"

                    passphrase_size= secret_raw_bytes[offset]
                    offset+=1

                    passphrase_bytes= secret_raw_bytes[offset: (offset+passphrase_size)]
                    offset+=passphrase_size
                    try:
                        passphrase = passphrase_bytes.decode("utf-8")
                    except Exception as ex:
                        logger.warning(f"Error during passphrase decoding: {ex}")
                        passphrase = f"failed to decode passphrase bytes: {passphrase_bytes.hex()}"

                    secret_string= f'\nWordlist: {wordlist} \nBIP39 mnemonic: "{bip39_mnemonic}" \nPassphrase: "{passphrase}" \nMasterseed: {masterseed_hex}'  

                elif stype == 'Password':
                    secret_string = "\"" + binascii.unhexlify(secret_dict['secret'])[1:].decode() + "\""

                else:
                    secret_string = "\"" + secret_dict['secret'][2:] + "\""

                print("Secret (Cleartext):", secret_string)
                exit()

            else:
                secret_dict_pubkey = cc.seedkeeper_export_secret(pubkey_id)
                authentikey_importer = secret_dict_pubkey['secret'][2:]  # [0:2] is the pubkey_size in hex
                secret_obj = {
                    'authentikey_exporter': cc.parser.authentikey.get_public_key_bytes(False).hex(),
                    'authentikey_importer': authentikey_importer,
                    'secrets': [{
                        'label': secret_dict['label'],
                        'type': secret_dict['type'],
                        'origin': secret_dict['origin'],
                        'export_rights': secret_dict['export_rights'],
                        'rfu1': secret_dict['rfu1'],
                        'rfu2': secret_dict['rfu2'],
                        'fingerprint': secret_dict['fingerprint'],
                        'header': secret_dict['header'],  # bytes(secret_dict['header']).hex(),
                        'iv': secret_dict['iv'],  # bytes(secret_dict['iv']).hex(),
                        'secret_encrypted': secret_dict['secret_encrypted'],
                        # bytes(secret_list).hex(),  #'secret_base64':base64.encodebytes( bytes(secret_list) ).decode('utf8')
                        'hmac': secret_dict['hmac'],  # bytes(secret_dict['hmac']).hex(),
                    }],
                }
                print("Secret Export (JSON to Import into another card/device)")
                print(json.dumps(secret_obj))
    except Exception as e:
        print(e)

@main.command()
@click.option("--sid", type=int, required=True, help="SecretID (As per the list-secret-headers command)")
@click.option("--pubkey-id", type=int, default=None, help="Public Key ID used to encrypt the secret (Optional) Note: Must be the ID of a 'secret' of the type 'Public Key', visible when using the command 'seedkeeper-list-secret-headers'")
def seedkeeper_export_secret_to_satochip(sid, pubkey_id):
    """Export a Secret from the Seedkeeper in format suitable to satochip"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)
        secret_dict = cc.seedkeeper_export_secret_to_satochip(sid, pubkey_id)
        
        secret_dict_pubkey = cc.seedkeeper_export_secret(pubkey_id)
        authentikey_importer = secret_dict_pubkey['secret'][2:]  # [0:2] is the pubkey_size in hex
        secret_obj = {
            'authentikey_exporter': cc.parser.authentikey.get_public_key_bytes(False).hex(),
            'authentikey_importer': authentikey_importer,
            'secrets': [{
                'label': secret_dict['label'],
                'type': secret_dict['type'],
                'origin': secret_dict['origin'],
                'export_rights': secret_dict['export_rights'],
                'rfu1': secret_dict['rfu1'],
                'rfu2': secret_dict['rfu2'],
                'fingerprint': secret_dict['fingerprint'],
                'header': secret_dict['header'],  # bytes(secret_dict['header']).hex(),
                'iv': secret_dict['iv'],  # bytes(secret_dict['iv']).hex(),
                'secret_encrypted': secret_dict['secret_encrypted'],
                # bytes(secret_list).hex(),  #'secret_base64':base64.encodebytes( bytes(secret_list) ).decode('utf8')
                'hmac': secret_dict['hmac'],  # bytes(secret_dict['hmac']).hex(),
            }],
        }
        print("Secret Export (JSON to Import into another card/device)")
        print(json.dumps(secret_obj))
    except Exception as e:
        print(e)

@main.command()
def seedkeeper_list_secret_headers():
    """Display a summary of the secrets stored on the SeedKeeper"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        
        cc.card_verify_PIN(pin)
        headers = cc.seedkeeper_list_secret_headers()

        #Present the data in a human readable way (Copied from seedkeeper-tool)
        # nice presentation instead of raw data
        txt = f'Number of secrets stored: {len(headers)}'
        headings = ['Id', 'Label', 'Type', 'Origin', 'Export rights', 'Nb plain exports', 'Nb encrypted exports',
                    'Nb secret exported', 'Fingerprint']

        print(headings)
        for header in headers:
            sid = str(header['id'])
            label = header['label']
            stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
            origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
            export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                  hex(header['export_rights']))  # str(header['export_rights'])
            export_nbplain = str(header['export_nbplain'])
            export_nbsecure = str(header['export_nbsecure'])
            export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
            fingerprint = header['fingerprint']

            print([sid, label, stype, origin, export_rights, export_nbplain, export_nbsecure, export_nbcounter,
                 fingerprint])

        print(txt)

    except Exception as e:
        print(e)

@main.command()
@click.option("--sid", type=int, required=True, help="SecretID (As per the list-secret-headers command)")
def seedkeeper_reset_secret(sid):
    """Reset a secret object in memory. 
        WARNING: this action cannot be undone!"""
    try:
        logger.info("In seedkeeper_reset_secret")
        print("WARNING: RESETTING A SECRET WITHOUT A WORKING BACKUP CAN LEAD TO UNRECOVERABLE LOSS OF FUNDS!")
        
        if click.confirm("Are you sure that you want to reset a secret?", default=False):
            # we don't try to recover PIN from environment variables for particularly sensitive operations
            pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)
        
            response, sw1, sw2, dic = cc.seedkeeper_reset_secret(sid)
            if dic["is_reset"]:
                print("Secret reset successfully!")
            else:
                print("Failed to reset secret (secret not found?).")
        else:
            print("Secret reset cancelled!")

    except Exception as e:
        print(e)  

@main.command()
def seedkeeper_print_logs():
    """Prints Log of operations on device"""
    try:
        # get PIN from environment variable or interactively
        if 'PYSATOCHIP_PIN' in environ:
            pin= environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")

        cc.card_verify_PIN(pin)
        (logs, nbtotal_logs, nbavail_logs) = cc.seedkeeper_print_logs()

        logs = logs[0:nbtotal_logs]
        strlogs = []
        strlogs.append(['Operation', 'ID1', 'ID2', 'Result'])
        # convert raw logs to readable data
        for log in logs:
            ins = log[0]
            id1 = log[1]
            id2 = log[2]
            result = log[3]
            if ins == 0xA1:  # encrypted or plain import? depends on value of id2
                ins = 0xA1A if (id2 == 0xFFFF) else 0xA1B
            elif ins == 0xA2:
                ins = 0xA2A if (id2 == 0xFFFF) else 0xA2B
            ins = SEEDKEEPER_LOG_INS_DIC.get(ins, hex(log[0]))

            id1 = 'N/A' if id1 == 0xFFFF else str(id1)
            id2 = 'N/A' if id2 == 0xFFFF else str(id2)

            if (result & 0x63C0) == 0x63C0:  # last nible contains number of pin remaining
                remaining_tries = (result & 0x000F)
                result = 'PIN failed - ' + str(remaining_tries) + ' tries remaining'
            else:
                result = SEEDKEEPER_LOG_RES_DIC.get(log[3], hex(log[3]))

            strlogs.append([ins, id1, id2, result])

        if len(strlogs) == 0:
            strlogs.append(['', '', '', ''])

        for logline in strlogs:
            print(logline)

    except Exception as e:
        print(e)

"""##############################
#            SATODIME           #        
##############################"""

@main.command()
def satodime_get_card_status():
    """Return status info specific to Satodime"""
    response, sw1, sw2, satodime_status = cc.satodime_get_status()
    unlock_counter = bytes(satodime_status['unlock_counter']).hex()
    max_keys = satodime_status['max_num_keys']
    print("Key Slot States")
    for key_index in range(0,max_keys):
        print("Slot:", key_index, " State:", DIC_STATE[satodime_status['satodime_keys_status'][key_index]])

    print()
    print("Unlock Counter:", unlock_counter)

@main.command()
@click.option("--slot", default=0, help="Get the status of a specific keyslot")
def satodime_get_key_status(slot):
    """Return the status of a specific keyslot"""
    response, sw1, sw2, keyslot_status = cc.satodime_get_keyslot_status(slot)
    print("Slot State:", keyslot_status['key_status_txt'])
    print("Slot Type:", keyslot_status['key_slip44_txt'], keyslot_status['key_asset_txt'])
    if keyslot_status['is_token'] or keyslot_status['is_nft']:
        print("Slot Contract:", keyslot_status['key_contract_hex'])

@main.command()
@click.option("--unlock-secret", default="", help="Unlock Secret (Not required if connecting over USB)")
@click.option("--unlock-counter", default="", help="Unlock Counter (Not required if connecting over USB)")
def satodime_ownership_transfer(unlock_secret, unlock_counter):
    """Initiate Ownership Transfer"""
    unlock_secret = list(bytes.fromhex(unlock_secret))
    unlock_counter = list(bytes.fromhex(unlock_counter))
    cc.satodime_set_unlock_counter(unlock_counter)
    cc.satodime_set_unlock_secret(unlock_secret)

    try:
        (response, sw1, sw2) = cc.satodime_initiate_ownership_transfer()

        if (sw1 == 0x90) and (sw2 == 0x00):
            print("Success: Ownership Transfer Initiated, the Satodime can now be claimed by another device.")
        elif (sw1 == 0x9C) and (sw2 == 0x04):
            print("Notice: Card already in Ownership Transfer Mode")
        elif (sw1 == 0x9C) and (sw2 == 0x50):
            print("Failed: Incorrect Unlock Counter")
        elif (sw1 == 0x9C) and (sw2 == 0x51):
            print("Failed: Incorrect Unlock Secret")
        else:
            print("Unknown Error: ", response, sw1, sw2)
    except Exception as e:
        print("Failed:", e)

@main.command()
def satodime_ownership_claim():
    """Claim Ownership"""
    common_initial_setup(["--satodime"])

@main.command()
@click.option("--slot", default=0, help="Get the status of a specific keyslot")
def satodime_get_pubkey(slot):
    """Get Pubkey(Hex) for a given keyslot"""
    response, sw1, sw2, pubkey_list, pubkey_comp_list = cc.satodime_get_pubkey(slot)
    print("Pubkey (Uncompressed):", bytes(pubkey_list).hex())
    print("Pubkey (Compressed):", bytes(pubkey_comp_list).hex())

@main.command()
@click.option("--slot", default=0, help="Get the status of a specific keyslot")
@click.option("--unlock-secret", default="", help="Unlock Secret (Not required if connecting over USB)")
@click.option("--unlock-counter", default="", help="Unlock Counter (Not required if connecting over USB)")
def satodime_get_privkey(slot, unlock_secret, unlock_counter):
    """Get Private Key (Hex) for an unsealed Keyslot"""
    unlock_secret = list(bytes.fromhex(unlock_secret))
    unlock_counter = list(bytes.fromhex(unlock_counter))
    cc.satodime_set_unlock_counter(unlock_counter)
    cc.satodime_set_unlock_secret(unlock_secret)

    try:
        (response, sw1, sw2, entropy_list, privkey_list) = cc.satodime_get_privkey(slot)
        print("Privkey (Hex):", bytes(privkey_list).hex())
        print("Privkey Entropy:", bytes(entropy_list).hex())
        print("Custom Entropy (Set when key Sealed):", bytes(entropy_list)[:32].decode())

        print()
        print("Updated Unlock Counter:", bytes(cc.unlock_counter).hex())
    except IncorrectUnlockCounterError:
        print("Failed: Incorrect Unlock Counter, you can get the expected unlock code with satodime-get-status")
    except IncorrectUnlockCodeError:
        print("Failed: Incorrect Unlock Secret. You either need to transfer ownership and note down the unlock-secret, or connect via a USB to proceed without it")
    except Exception as e:
        print(e)

@main.command()
@click.option("--slot", default=0, help="Get the status of a specific keyslot (Slots start counting from 0)")
@click.option("--custom-entropy", default="", help="Some custom entropy to add to the private key generated for this slot")
@click.option("--unlock-secret", default="", help="Unlock Secret (Not required if connecting over USB)")
@click.option("--unlock-counter", default="", help="Unlock Counter (Not required if connecting over USB)")
def satodime_key_seal(slot, custom_entropy, unlock_secret, unlock_counter):
    """Generate a Private Key and Seal in a Keyslot"""
    unlock_secret = list(bytes.fromhex(unlock_secret))
    unlock_counter = list(bytes.fromhex(unlock_counter))
    cc.satodime_set_unlock_counter(unlock_counter)
    cc.satodime_set_unlock_secret(unlock_secret)

    try:
        custom_entropy_list = list(custom_entropy.encode().ljust(32, b'\0'))
        response, sw1, sw2, pubkey_list, pubkey_comp_list = cc.satodime_seal_key(slot, custom_entropy_list)
        print("Success: Slot Sealed")
        print("Pubkey (Uncompressed):", bytes(pubkey_list).hex())
        print("Pubkey (Compressed):", bytes(pubkey_comp_list).hex())
    except Exception as e:
        print(e)

    print()
    print("Updated Unlock Counter:", bytes(cc.unlock_counter).hex())

@main.command()
@click.option("--slot", default=0, help="Get the status of a specific keyslot (Slots start counting from 0)")
@click.option("--unlock-secret", default="", help="Unlock Secret (Not required if connecting over USB)")
@click.option("--unlock-counter", default="", help="Unlock Counter (Not required if connecting over USB)")
def satodime_key_unseal(slot, unlock_secret, unlock_counter):
    """Unseal a Keyslot (Reveal its Private Key)"""
    unlock_secret = list(bytes.fromhex(unlock_secret))
    unlock_counter = list(bytes.fromhex(unlock_counter))
    cc.satodime_set_unlock_counter(unlock_counter)
    cc.satodime_set_unlock_secret(unlock_secret)

    print()
    if click.confirm("WARNING: This will unseal slot " + str(slot) + "and output corresponding private key in this terminal.\nThe Private Key will remain accessible until this slot is reset...\nAre you sure you want to unseal this keyslot?", default=False):

        try:
            response, sw1, sw2, entropy_list, privkey_list = cc.satodime_unseal_key(slot)
            print("Privkey (Hex):", bytes(privkey_list).hex())
            print("Privkey Entropy:", bytes(entropy_list).hex())
            print("Custom Entropy (Set when key Sealed):", bytes(entropy_list)[:32].decode())

            print()
            print("Updated Unlock Counter:", bytes(cc.unlock_counter).hex())
        except Exception as e:
            print(e)


@main.command()
@click.option("--slot", default=0, help="Get the status of a specific keyslot (Slots start counting from 0)")
@click.option("--unlock-secret", default="", help="Unlock Secret (Not required if connecting over USB)")
@click.option("--unlock-counter", default="", help="Unlock Counter (Not required if connecting over USB)")
def satodime_key_reset(slot, unlock_secret, unlock_counter):
    """Reset a keyslot"""
    unlock_secret = list(bytes.fromhex(unlock_secret))
    unlock_counter = list(bytes.fromhex(unlock_counter))
    cc.satodime_set_unlock_counter(unlock_counter)
    cc.satodime_set_unlock_secret(unlock_secret)

    print()
    if click.confirm("WARNING: This will reset slot " + str(slot) + ", wiping its Private Key. Any funds at the corresponding address will be unrecoverablly lost unless you have another backup of this private key...\nAre you sure you want to reset this keyslot?", default=False):
        try:
            response, sw1, sw2 = cc.satodime_reset_key(slot)
            print("Success, key reset...")
        except Exception as e:
            print(e)

        print()
        print("Updated Unlock Counter:", bytes(cc.unlock_counter).hex())

"""##############################
#            SATOCASH           #        
##############################"""

@main.command()
def satocash_get_status():
    """Get a Satocash card status"""
    try:
        response, sw1, sw2, dic_status = cc.satocash_get_status()
        print(f"Status: {dic_status}")
    except Exception as ex:
        print(f"Error in satocash_get_status: {ex}")

@main.command()
@click.option("--url", help="mint url")
def satocash_import_mint(url: str):
    """Import a mint (url) into a Satocash. This is required to import keyset(s), then proof(s)"""
    try:
        # no pin required for status
        response, sw1, sw2, index = cc.satocash_import_mint(url)
        print(f"Mint {url} imported into card at index {index}")
    except Exception as ex:
        print(f"Error during import: {ex}")

@main.command()
@click.option("--index", help="Index of mint to export")
def satocash_export_mint(index: str):
    """Export a mint (url) from a Satocash at a given index"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        index = int(index)
        response, sw1, sw2, url = cc.satocash_export_mint(index)
        print(f"Mint url: {url}")
    except Exception as ex:
        print(f"Error during mint export: {ex}")

@main.command()
@click.option("--index", help="Index of mint to remove")
def satocash_remove_mint(index: str):
    """Remove a mint (url) from a Satocash at a given index"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        index = int(index)
        response, sw1, sw2 = cc.satocash_remove_mint(index)
        print(f"Mint removed from card")
    except Exception as ex:
        print(f"Error during mint removal: {ex}")

@main.command()
@click.option("--keyset-id", help="Keyset_id as 8-byte hex value")
@click.option("--mint-index", help="Mint index in satocard")
@click.option("--unit", default= "sat", help="Unit representation: sat, msat, USD, EUR")
def satocash_import_keyset(keyset_id: str, mint_index: str, unit: str):
    """Import a keyset into a Satocash. This is required to import proof(s)"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        dic_unit = {"sat":1, "msat":2, "USD":3, "EUR":4}
        keyset_id_bytes = bytes.fromhex(keyset_id)
        mint_index = int(mint_index)
        unit = dic_unit[unit]

        response, sw1, sw2, index = cc.satocash_import_keyset(keyset_id_bytes, mint_index, unit)
        print(f"Keyset {keyset_id} imported into card at index {index}")

    except Exception as ex:
        print(f"Error during keyset import: {ex}")

@main.command()
@click.option("--index-list", help="list of keyset to fetch by index, in the form '1,2,4,6'.")
def satocash_export_keysets(index_list_str: str):
    """Export keysets info from a Satocash. Info includes keyset_id, mint_index and unit"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        # parse list from string
        # Split the string by commas
        string_values = index_list_str.split(',')
        # Convert each string value to integer, stripping whitespace
        index_list = [int(value.strip()) for value in string_values]

        response, sw1, sw2, keysets = cc.satocash_export_keysets(index_list)
        print(f"Keysets: {keysets}")

    except Exception as ex:
        print(f"Error during keyset export: {ex}")


@main.command()
@click.option("--index", help="Index of keyset to remove")
def satocash_remove_keyset(index: str):
    """Remove a keyset from a Satocash at a given index"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        index = int(index)

        response, sw1, sw2 = cc.satocash_remove_keyset(index)
        print(f"Keyset removed from card")

    except Exception as ex:
        print(f"Error during keyset removal: {ex}")

@main.command()
@click.option("--keyset-index", help="Keyset-index in satocard")
@click.option("--amount", help="amount")
@click.option("--secret", help="ecash secret x as 32-byte hex representation")
@click.option("--unblinded-key", help="ecash unblinded key as 32-byte hex representation")
def satocash_import_proof(keyset_index: str, amount: str, secret: str, unblinded_key: str):
    """Import a proof into a Satocash. Info includes keyset_index, amount, secret and unblinded-key"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        # parse data from string
        keyset_index = int(keyset_index)
        amount_exponent = math.log(int(amount),2) # the amount is actually stored as the power 2 exponent in [0...63]
        secret_bytes = bytes.fromhex(secret)
        unblinded_key_bytes = bytes.fromhex(unblinded_key)

        response, sw1, sw2, index = cc.satocash_import_proof(keyset_index, amount_exponent, secret_bytes, unblinded_key_bytes)
        print(f"Token imported into card at index {index}")
    except Exception as ex:
        print(f"Error during import: {ex}")

@main.command()
@click.option("--index-list", help="list of proofs to fetch by index, in the form '1,2,4,6'.")
def satocash_export_proofs(index_list: str):
    """Export proofs from a Satocash. Info includes keyset_index, amount_exponent, secret, unblinded_key"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        # parse list from string
        # Split the string by commas
        string_values = index_list.split(',')
        # Convert each string value to integer, stripping whitespace
        index_list = [int(value.strip()) for value in string_values]
        print(f"index_list: {index_list}")

        proofs = cc.satocash_export_proofs(index_list)
        print(f"Proofs: {proofs}")

        # convert to tokenv4
        # keep it simple: generate on token per proof
        for proof in proofs:
            try:
                keyset_index = proof["keyset_index"]

                # recover keyset id, unit & mint info
                response, sw1, sw2, keysets, keysets_dic = cc.satocash_export_keysets([keyset_index])
                keyset_id = keysets[0].get("id")
                mint_index = keysets[0].get("mint_index")
                unitByte = keysets[0].get("unit")
                dic_unit = {1:"sat", 2:"msat", 3:"USD", 4:"EUR"}
                unit = dic_unit[unitByte]

                # recover mint_url
                response, sw1, sw2, mint_url = cc.satocash_export_mint(index= mint_index)
                print(f"mint_url: {mint_url}")

                # generate tokenv4 dict
                tokenv4_dic = {'m': mint_url, 'u': unit, 'd': 'Satocash token'}
                token_dic = {}
                token_dic['i'] = keyset_id
                proof_dic = {
                    'a': proof['amount'],
                    's': proof['secret_hex'],
                    'c': bytes.fromhex(proof['unblinded_key_hex'])
                }
                token_dic['p'] = [proof_dic]
                tokenv4_dic['t'] = [token_dic]

                # serialize token dic to string
                tokenv4_str = satocash_serialize_tokenv4(tokenv4_dic)
                print(f"tokenv4_str: {tokenv4_str}")

            except Exception as ex:
                print(f"Error while serializing proofs to tokens: {ex}")
                print(traceback.format_exc())

    except Exception as ex:
        print(f"Error during proof export: {ex}")
        print(traceback.format_exc())

@main.command()
@click.option("--unit", default="sat", help="Monetary unit for which we want info: sat, msat, USD or EUR")
@click.option("--info-type", help="The info that we want for each proof: STATE, KEYSET_INDEX, AMOUNT, MINT_INDEX, UNIT")
@click.option("--index-start", default=0, help="Starting index for proofs")
@click.option("--index-size", default= 0, help="Number of index for which info is requested, starting from index-start")
def satocash_get_proof_info(unit: str, info_type: str, index_start: str, index_size: str):
    """Get proof info for a given subset of proofs"""
    try:
        # get PIN from environment variable or interactively
        # todo: check pin policy?
        if 'PYSATOCHIP_PIN' in environ:
            pin = environ.get('PYSATOCHIP_PIN')
            print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
        else:
            pin = getpass("Enter your PIN:")
        cc.card_verify_PIN(pin)

        dic_unit = {"sat": 1, "msat": 2, "USD": 3, "EUR": 4}
        dic_info = {"STATE":0, "KEYSET_INDEX":1, "AMOUNT":2, "MINT_INDEX":3, "UNIT":4}
        unit = dic_unit[unit]
        info_type = dic_info[info_type]
        index_start = int(index_start)
        index_size = int(index_size)
        if index_size == 0:
            # get all indexes
            try:
                response, sw1, sw2, dic_status = cc.satocash_get_status()
                print(f"Status: {dic_status}")
                index_size = dic_status.get('max_nb_proofs', 128)
            except Exception as ex:
                print(f"Error in satocash_get_status: {ex}")

        response, sw1, sw2 = cc.satocash_get_proof_info(unit, info_type, index_start, index_size)
        print(f"Token info (raw): {response}")
        dic_unit_by_code = {1:"sat", 2:"msat", 3:"USD", 4:"EUR"}
        dic_info_by_code = {0:"STATE", 1:"KEYSET_INDEX", 2:"AMOUNT", 3:"MINT_INDEX", 4:"UNIT"}
        dic_state_by_code = {0:"STATE_EMPTY", 1:"STATE_UNSPENT", 2:"STATE_SPENT"}

        print(f"Token info:")
        for index, value in enumerate(response):
            proof_info_str = value
            if info_type == 0:
                proof_info_str = dic_state_by_code.get(value, "UNKNOWN")
            elif info_type == 2:
                if value == 0xFF:
                    # proof is empty or in another denomination unit
                    proof_info_str = 0
                else:
                    if (value & 0x80)==0x80:
                        # this is a spent proof, shown as negative
                        proof_info_str = -(2**(value & 0x7f)) # value is actually the power 2 exponent (without the 'spent' flag)
                    else:
                        # this is an unspent proof
                        proof_info_str = 2 ** value  # value is actually the power 2 exponent
            elif info_type == 4:
                proof_info_str = dic_unit_by_code.get(value, "UNKNOWN")

            print(f"index: {index_start + index} - info: {proof_info_str} - type: {dic_info_by_code.get(info_type, "UNKNOWN")}")
            # print(f"index: {index_start + index}")
            # print(f"info_raw: {value}")
            # print(f"info_str: {proof_info_str}")
            # print(f"type_raw: {info_type}")
            # print(f"type_str: {dic_info_by_code.get(info_type, "UNKNOWN")}")
            # print("")

    except Exception as ex:
        print(f"Error while fetching proof info: {ex}")


@main.command()
@click.option("--unit", default="sat", help="Monetary unit for which we want info: sat, msat, USD or EUR")
def satocash_get_balances(unit: str):
    """Get balances for tokens stored in the card for a given currency unit, sorted by mints"""
    try:
        dic_info = {"STATE": 0, "KEYSET_INDEX": 1, "AMOUNT": 2, "MINT_INDEX": 3, "UNIT": 4}
        dic_unit = {"sat": 1, "msat": 2, "USD": 3, "EUR": 4}
        unit = dic_unit[unit]

        # get status
        response, sw1, sw2, status_dic = cc.satocash_get_status()
        max_nb_mints = status_dic.get('max_nb_mints', 0)
        nb_mints = status_dic.get('nb_mints', 0)
        max_nb_proofs = status_dic.get('max_nb_proofs', 0)
        nb_proofs = status_dic.get('nb_proofs', 0)
        nb_unspent_proofs = status_dic.get('nb_unspent_proofs', 0)
        print(f"max_nb_mints: {max_nb_mints}")
        print(f"max_nb_proofs: {max_nb_proofs}")
        print(f"nb_proofs: {nb_proofs}")
        print(f"nb_unspent_proofs: {nb_unspent_proofs}")

        # get PIN from environment variable or interactively
        pin_policy = status_dic.get('pin_policy', 0x01)
        if pin_policy>0x00:
            if 'PYSATOCHIP_PIN' in environ:
                pin = environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)

        # get proof info in raw format
        index_size=128
        info_type_amount_exponent = dic_info['AMOUNT']
        info_type_mint = dic_info['MINT_INDEX']
        amount_exponents = []
        mint_indexes = []
        for index_start in range(0, max_nb_proofs, 128):
            response, sw1, sw2 = cc.satocash_get_proof_info(unit, info_type_amount_exponent, index_start, index_size)
            amount_exponents += response
            response, sw1, sw2 = cc.satocash_get_proof_info(unit, info_type_mint, index_start, index_size)
            mint_indexes += response
        print(f"amount_exponents: {amount_exponents}")
        print(f"mint_indexes: {mint_indexes}")


        # compute balance for each mint
        amount_unspent_by_mints = max_nb_mints * [0]
        amount_spent_by_mints = max_nb_mints * [0]
        mint_urls = max_nb_mints * ['']
        for index in range(max_nb_proofs):
            mint_index = mint_indexes[index]
            amount_exponent = amount_exponents[index]
            if amount_exponent == 0xFF:
                amount = 0
            else:
                if amount_exponent & 0x80 == 0x80:
                    # spent amount
                    amount = 2**(amount_exponent & 0x7f)
                    amount_spent_by_mints[mint_index] += amount
                else:
                    # unspent amount
                    amount = 2 ** amount_exponent
                    amount_unspent_by_mints[mint_index] += amount

        print(f"UNSPENT AMOUNTS:")
        for index in range(max_nb_mints):
            if amount_unspent_by_mints[index]!=0:
                # get mint info
                response, sw1, sw2, url = cc.satocash_export_mint(index)
                mint_urls[index] = url
                print(f"balance: {amount_unspent_by_mints[index]} - mint: {url} - index: {index}")

        print(f"SPENT AMOUNTS:")
        for index in range(max_nb_mints):
            if amount_spent_by_mints[index] != 0:
                # get mint info
                response, sw1, sw2, url = cc.satocash_export_mint(index)
                mint_urls[index] = url
                print(f"balance: {amount_spent_by_mints[index]} - mint: {url} - index: {index}")

        return status_dic, mint_urls, amount_unspent_by_mints, amount_spent_by_mints

    except Exception as ex:
        print(f"Error while fetching balances: {ex}")

@main.command()
@click.option("--tokenv4", help="Cash tokenv4 serialized format (base64)")
def satocash_import_tokenv4(tokenv4: str):
    """Import a base64 serialized token into satocash"""

    # get PIN from environment variable or interactively
    # todo: check pin policy?
    if 'PYSATOCHIP_PIN' in environ:
        pin = environ.get('PYSATOCHIP_PIN')
        print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
    else:
        pin = getpass("Enter your PIN:")
    cc.card_verify_PIN(pin)

    json = satocash_deserialize_tokenv4(tokenv4)
    print(f"token_json: {json}")

    unit_str = json['u']
    mint_url = json['m']
    mint_index = -1
    # import mint
    try:
        response, sw1, sw2, mint_index = cc.satocash_import_mint(mint_url)
        print(f"Mint {mint_url} imported into card at index {mint_index}")
    except Exception as ex:
        print(f"Error during import: {ex}")
        return

    tokens = json['t']
    # for each token
    for token_dic in tokens:
        keyset_id_bytes = token_dic['i']
        keyset_index = 0
        # import keyset_id
        try:
            dic_unit = {"sat": 1, "msat": 2, "USD": 3, "EUR": 4}
            unit = dic_unit[unit_str]
            print(f"unit: {unit}")
            print(f"keyset_id_bytes: {keyset_id_bytes}")
            print(f"mint_index: {mint_index}")

            response, sw1, sw2, keyset_index = cc.satocash_import_keyset(keyset_id_bytes, mint_index, unit)
            print(f"Keyset {keyset_id_bytes.hex()} imported into card at index {keyset_index}")
        except Exception as ex:
            print(f"Error during tokenv4 import: {ex}")
            print(traceback.format_exc())
            return

        proofs = token_dic['p']
        # for each proof
        for proof_dic in proofs:
            amount = proof_dic['a']
            secret_hex = proof_dic['s']
            unblinded_key_bytes = proof_dic['c']
            if len(unblinded_key_bytes) != 33:
                print(f"Wrong unblinded_key size: {len(unblinded_key_bytes)} (should be 33)")
                return

            # import proof
            try:
                # parse data from string
                amount_exponent = int(math.log(int(amount),2)) # the amount is actually stored as the power 2 exponent in [0...63]
                print(f"amount_exponent: {amount_exponent}")
                secret_bytes = bytes.fromhex(secret_hex)
                response, sw1, sw2, proof_index = cc.satocash_import_proof(keyset_index, amount_exponent, secret_bytes, unblinded_key_bytes)
                print(f"Token imported into card at index {proof_index}")
            except Exception as ex:
                print(f"Error during tokenv4 import: {ex}")
                print(traceback.format_exc())

@main.command()
@click.option("--unit", default="sat", help="Monetary unit for which we want info: sat, msat, USD or EUR")
@click.option("--amount", help="minimum amount in token to export")
def satocash_export_tokenv4(unit, amount):
    """Export a base64 serialized token from satocash for at least a given amount"""
    try:
        amount = int(amount)

        # get status
        response, sw1, sw2, status_dic = cc.satocash_get_status()
        max_nb_mints = status_dic.get('max_nb_mints', 0)
        max_nb_keysets = status_dic.get('max_nb_keysets', 0)
        nb_mints = status_dic.get('nb_mints', 0)
        max_nb_proofs = status_dic.get('max_nb_proofs', 0)
        nb_proofs = status_dic.get('nb_proofs', 0)
        nb_unspent_proofs = status_dic.get('nb_unspent_proofs', 0)
        print(f"max_nb_mints: {max_nb_mints}")
        print(f"max_nb_keysets: {max_nb_keysets}")
        print(f"max_nb_proofs: {max_nb_proofs}")
        print(f"nb_proofs: {nb_proofs}")
        print(f"nb_unspent_proofs: {nb_unspent_proofs}")

        # get PIN from environment variable or interactively
        pin_policy = status_dic.get('pin_policy', 0x01)
        if pin_policy > 0x00:
            if 'PYSATOCHIP_PIN' in environ:
                pin = environ.get('PYSATOCHIP_PIN')
                print("INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'")
            else:
                pin = getpass("Enter your PIN:")
            cc.card_verify_PIN(pin)

        # get proof info in raw format
        dic_info = {"STATE": 0, "KEYSET_INDEX": 1, "AMOUNT_EXPONENT": 2, "MINT_INDEX": 3, "UNIT": 4}
        dic_unit = {"sat": 1, "msat": 2, "USD": 3, "EUR": 4}
        index_size = 128
        unit_byte = dic_unit[unit]
        info_type_amount_exponent = dic_info['AMOUNT_EXPONENT']
        info_type_mint = dic_info['MINT_INDEX']
        info_type_keyset_index = dic_info['KEYSET_INDEX']
        amount_exponents = []
        mint_indexes = []
        keyset_indexes = []
        for index_start in range(0, max_nb_proofs, 128):
            response, sw1, sw2 = cc.satocash_get_proof_info(unit_byte, info_type_amount_exponent, index_start, index_size)
            amount_exponents += response
            response, sw1, sw2 = cc.satocash_get_proof_info(unit_byte, info_type_mint, index_start, index_size)
            mint_indexes += response
            response, sw1, sw2 = cc.satocash_get_proof_info(unit_byte, info_type_keyset_index, index_start, index_size)
            keyset_indexes += response
        print(f"amount_exponents: {amount_exponents}")
        print(f"mint_indexes: {mint_indexes}")
        print(f"keyset_indexes: {keyset_indexes}")

        # compute balance for each mint
        # also list keysets by mint and proofs by keyset
        amount_unspent_by_mints = max_nb_mints * [0]
        keyset_indexes_by_mint = max_nb_mints * [set()]
        proof_indexes_by_keyset = max_nb_keysets * [set()]
        amount_available = 0
        mint_index = None
        for proof_index in range(max_nb_proofs):
            mint_index = mint_indexes[proof_index]
            amount_exponent = amount_exponents[proof_index]
            keyset_index = keyset_indexes[proof_index]

            # get proof amount
            if (amount_exponent != 0xFF) and (amount_exponent & 0x80 == 0x00):
                # unspent amount
                proof_amount = 2 ** amount_exponent
                amount_unspent_by_mints[mint_index] += proof_amount
                keyset_indexes_by_mint[mint_index].add(keyset_index)
                proof_indexes_by_keyset[keyset_index].add(proof_index)
                if amount_unspent_by_mints[mint_index] >= amount:
                    # we have reached a sufficient set of proofs
                    amount_available = amount_unspent_by_mints[mint_index]
                    break

        # check that we have sufficient funds
        if amount_available < amount:
            print("Not enough funds available in one mint!")
            print(f"Amount per mint: {amount_unspent_by_mints}")
            return

        # at this point, we have enough funds in the mint at mint_index
        response, sw1, sw2, mint_url = cc.satocash_export_mint(mint_index)
        print(f"mint_index: {mint_index}")
        print(f"mint_url: {mint_url}")
        print(f"amount_available: {amount_available}")

        # select proofs by keysets and get ids from card
        keyset_indexes_subset = keyset_indexes_by_mint[mint_index]
        print(f"keyset_indexes_subset: {keyset_indexes_subset}")
        response, sw1, sw2, keysets, keysets_dic = cc.satocash_export_keysets(list(keyset_indexes_subset))

        # generate tokenv4 dict
        tokenv4_dic = {'m': mint_url, 'u': unit, 'd': 'Satocash token'}
        tokenv4_dic['t'] = []
        for keyset_dic in keysets:
            token_dic = {}

            # get id from card
            keyset_id = keyset_dic['id']
            keyset_index = keyset_dic['index']
            token_dic['i'] = keyset_id

            # get proofs by keyset_index
            token_dic['p'] = []
            proof_indexes_subset = proof_indexes_by_keyset[keyset_index]
            print(f"proof_indexes_subset: {proof_indexes_subset}")
            # export proofs
            proof_list = cc.satocash_export_proofs(list(proof_indexes_subset))
            for proof in proof_list:
                proof_dic = {
                    'a':proof['amount'],
                    's':proof['secret_hex'],
                    'c':bytes.fromhex(proof['unblinded_key_hex'])
                }
                token_dic['p'] += [proof_dic]
                print(f"proof_dic: {proof_dic}")

            print(f"token_dic: {token_dic}")
            tokenv4_dic['t'] += [token_dic]

        print(f"tokenv4_dic: {tokenv4_dic}")

        # serialize token dic to string
        tokenv4_str = satocash_serialize_tokenv4(tokenv4_dic)
        print(f"tokenv4_str: {tokenv4_str}")

    except Exception as ex:
        print(f"Error while exporting tokens: {ex}")
        print(traceback.format_exc())

def satocash_deserialize_tokenv4(tokenv4_serialized: str):
    """
    Ingesta a serialized "cashuB<cbor_urlsafe_base64>" token and returns a TokenV4 as json.
    based on Nutshell
    """
    prefix = "cashuB"
    assert tokenv4_serialized.startswith(prefix), Exception(
        f"Token prefix not valid. Expected {prefix}."
    )
    token_base64 = tokenv4_serialized[len(prefix) :]
    # if base64 string is not a multiple of 4, pad it with "="
    token_base64 += "=" * (4 - len(token_base64) % 4)

    token = cbor2.loads(base64.urlsafe_b64decode(token_base64))
    return token


def satocash_serialize_tokenv4(tokenv4_dic) -> str:
    """
    Takes a TokenV4 and serializes it as "cashuB<cbor_urlsafe_base64>.
    """
    prefix = "cashuB"
    tokenv4_serialized = prefix
    # encode the token as a base64 string
    tokenv4_serialized += base64.urlsafe_b64encode(
        cbor2.dumps(tokenv4_dic)
    ).decode()
    # remove padding
    tokenv4_serialized = tokenv4_serialized.rstrip("=")
    return tokenv4_serialized



"""##############################
#       SEEDKEEPER UTIL         #        
##############################"""

@main.command()
@click.option("--json-file", required=True, help="File containing the encrypted secret")
def util_decrypt_secret_export(json_file):
    """Tool to Decrypt Encrypted Seedkeeper Exports"""
    try:
        # Opening JSON and loading file
        f = open(json_file)
        export_data = json.load(f)

        privkey = input("Enter your private key:")
        secrets = Decrypt_Secret(privkey, export_data)
        for secret in secrets:
            print(secret)
    except Exception as e:
        print("FAILED:", e)

@main.command()
def util_generate_local_keypair():
    """Generate a local Pubkey/Privkey pair"""
    privkey = binascii.hexlify(urandom(32))
    ecdh = ECDH(curve=SECP256k1)
    pubkey = ecdh.load_private_key_bytes(binascii.unhexlify(privkey)).to_string().hex()
    print("Privkey:", privkey.decode())
    print("Pubkey:", '04' + pubkey)


@main.command()
def util_find_card_reader():
    available_readers = readers()
    print("Available readers:", available_readers)

    if available_readers:
        connection = available_readers[0].createConnection()
        connection.connect()
        print("ATR:", connection.getATR())
    else:
        print("No readers available.")

if __name__ == '__main__':
    main()
