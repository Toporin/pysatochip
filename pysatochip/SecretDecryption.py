#!/usr/bin/env python3
#
# Copyright (c) 2023 Stephen Rothery - https://github.com/3rdIteration
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

from ecdsa import SigningKey, SECP256k1, ECDH
import binascii, json, hmac, hashlib, argparse, logging

import cryptography
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import Cipher as CG_Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as CG_algorithms
from cryptography.hazmat.primitives.ciphers import modes as CG_modes
from cryptography.hazmat.backends import default_backend as CG_default_backend

from pysatochip.JCconstants import *

logging.basicConfig(level=logging.ERROR, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )

SECRET_CST_SC = b"seckeysecmac"

parser = argparse.ArgumentParser(description='Decrypt Encrypted JSON Exports from Seedkeeper')
parser.add_argument('--privkey', required = True,
					help="Private key to attempt decryption of the encrypted secret. (In raw hex format)")
parser.add_argument('--secret-json-file', required = True,
					help="Path to file containing encrypted secret(s) in JSON format")

def unpad(s): return s[0:-ord(s[-1:])]

# This takes two arguments, one being the hex encoded pubkey and the second being the JSON for encrypted secrets
def Decrypt_Secret(privateKey, export_data):
	decrypted_secrets = []

	# Load Key & Generate Shared Secret
	ecdh = ECDH(curve=SECP256k1)
	generated_pubkey = ecdh.load_private_key_bytes(binascii.unhexlify(privateKey)).to_string().hex()
	if generated_pubkey != export_data['authentikey_importer'][2:]:
		raise Exception("Derived Public Key doesn't match Required Public Key...")

	ecdh.load_received_public_key_bytes(binascii.unhexlify(export_data['authentikey_exporter']))
	shared_secret = ecdh.generate_sharedsecret_bytes()

	#Generate keys for decryption and mac
	decryption_key = hmac.new(shared_secret, msg = SECRET_CST_SC[:6], digestmod = hashlib.sha1).digest()[:-4]
	hmac_key = hmac.new(shared_secret, msg = SECRET_CST_SC[6:], digestmod = hashlib.sha1).digest()

	for secret in export_data['secrets']:
		exported_iv = bytearray.fromhex(secret['iv'])
		exported_hmac = secret['hmac']
		exported_secret_data = bytearray.fromhex(secret['secret_encrypted'])
		export_header = bytearray.fromhex(secret['header'])[2:(2+12)] # sid (first two bytes), label and labelsize aren't part of the HMAC'

		# Compute and check MAC
		hashed_secret_data = hashlib.sha256()
		hashed_secret_data.update(export_header)
		hashed_secret_data.update(bytearray.fromhex(secret['secret_encrypted']))
		computed_mac = hmac.new(hmac_key, hashed_secret_data.digest(), digestmod = hashlib.sha1).digest().hex()

		if computed_mac != exported_hmac:
			raise Exception("WARNING: MAC Mismatch (Encrypted Data is invalid, tampered or corrupt)")

		# Decrypt Secret
		cipher = CG_Cipher(CG_algorithms.AES(decryption_key), CG_modes.CBC(exported_iv), backend=CG_default_backend())
		decryptor = cipher.decryptor()
		raw_secret = decryptor.update(exported_secret_data) + decryptor.finalize()

		try: # First just try for text based secrets like mnemonics or general password
			decrypted_secret = raw_secret.split(b'\x00')[0][1:].decode()
		except Exception as e: # Then try to treat as hex encoded secrets
			decrypted_secret = unpad(raw_secret).hex()[2:]

		label = secret['label']
		type = SEEDKEEPER_DIC_TYPE.get(secret['type'], hex(secret['type']))

		decrypted_secrets.append({"label" : label, "type" : type, "decryped_secret" : decrypted_secret})

	return decrypted_secrets

if __name__ == '__main__':
	args = parser.parse_args()
	# Opening JSON and loading file
	f = open(args.secret_json_file)
	export_data = json.load(f)

	try:
		secrets = Decrypt_Secret(args.privkey, export_data)
		for secret in secrets:
			print(secret)
	except Exception as e:
		print("FAILED:", e)