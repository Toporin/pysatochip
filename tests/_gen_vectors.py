"""Provenance record: how tests/vectors.py was generated.

This script captured the golden vectors from the OLD `ecdsa`-based
implementation, before it was removed in 0.18.0 (issue #8). It therefore does
NOT run against the current tree: `ecdsa` is no longer a dependency, and
ECPrivkey.sign() is no longer deterministic. It is kept so that the origin of
every value in vectors.py stays auditable:

    git checkout v0.17.4 && pip install ecdsa && python tests/_gen_vectors.py

Do not add new vectors here. Add them to vectors.py with a comment explaining
how they were derived.
"""
import os
import sys

# Guard: on the current tree this script still *runs* (as long as ecdsa happens
# to be installed) but ECPrivkey.sign() is no longer deterministic, so it would
# emit different signature values and silently weaken the regression vectors it
# is supposed to justify. Refuse unless the caller really means it.
try:
    import pysatochip.ec_backend  # noqa: F401
    _NEW_TREE = True
except ImportError:
    _NEW_TREE = False

if _NEW_TREE and not os.environ.get("PYSATOCHIP_REGEN_VECTORS"):
    sys.exit(
        "refusing to run: this is the post-0.18.0 tree, where ECPrivkey.sign()\n"
        "is not deterministic, so the signature vectors would not reproduce.\n"
        "Check out v0.17.4 to regenerate, or set PYSATOCHIP_REGEN_VECTORS=1 to\n"
        "override (the output will NOT match tests/vectors.py).")

import hashlib
from ecdsa import ECDH, SigningKey
from ecdsa.curves import SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der, sigencode_string
from pysatochip.ecc import ECPrivkey, ECPubkey

N = SECP256k1.order

# ---- fixed secrets (test-only, never used on a real device) -----------------
PRIV_A = bytes.fromhex("c0ffee00112233445566778899aabbccddeeff0102030405060708090a0b0c0d")
PRIV_B = bytes.fromhex("1234567890abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978")

out = {}

sk_a = SigningKey.from_string(PRIV_A, curve=SECP256k1)
sk_b = SigningKey.from_string(PRIV_B, curve=SECP256k1)
pub_a_unc = b"\x04" + sk_a.get_verifying_key().to_string()
pub_b_unc = b"\x04" + sk_b.get_verifying_key().to_string()

out["priv_a"] = PRIV_A.hex()
out["priv_b"] = PRIV_B.hex()
out["pub_a_uncompressed"] = pub_a_unc.hex()
out["pub_b_uncompressed"] = pub_b_unc.hex()
out["pub_a_compressed"] = ECPrivkey(PRIV_A).get_public_key_bytes(True).hex()
out["pub_b_compressed"] = ECPrivkey(PRIV_B).get_public_key_bytes(True).hex()

# ---- ECDH: THE wire-compatibility gate for SecureChannel -------------------
e = ECDH(curve=SECP256k1, private_key=sk_a)
e.load_received_public_key_bytes(pub_b_unc[1:])
shared_ab = e.generate_sharedsecret_bytes()
e2 = ECDH(curve=SECP256k1, private_key=sk_b)
e2.load_received_public_key_bytes(pub_a_unc[1:])
shared_ba = e2.generate_sharedsecret_bytes()
assert shared_ab == shared_ba, "ECDH not symmetric?!"
out["ecdh_shared_x"] = shared_ab.hex()

# ---- deterministic (RFC6979) signature over a fixed digest -----------------
DIGEST = hashlib.sha256(b"pysatochip issue #8 golden vector").digest()
out["digest"] = DIGEST.hex()
sig_der_low = ECPrivkey(PRIV_A).sign_transaction(DIGEST)   # low-S DER, RFC6979
out["sig_der_lows_rfc6979"] = sig_der_low.hex()
r, s = sigdecode_der(sig_der_low, N)
assert s <= N // 2, "expected low-S from ECPrivkey.sign"
out["sig_r"] = hex(r)
out["sig_s"] = hex(s)

# ---- the same signature re-encoded with HIGH s (must still verify) ---------
out["sig_der_highs"] = sigencode_der(r, N - s, N).hex()

# ---- 64-byte compact form --------------------------------------------------
sig_string = sigencode_string(r, s, N)
out["sig_string"] = sig_string.hex()

# ---- pubkey recovery: (sig_string, recid) -> pubkey ------------------------
recovered = []
for recid in range(4):
    try:
        pk = ECPubkey.from_sig_string(sig_string, recid, DIGEST)
        recovered.append([recid, pk.get_public_key_bytes(False).hex()])
    except Exception:
        recovered.append([recid, None])
out["recovery"] = recovered
# which recid yields pub_a
out["recid_for_pub_a"] = [r_ for r_, p in recovered if p == pub_a_unc.hex()]

# ---- SHA-512 signature over secp256k1 (cert-chain subCA->device shape) -----
MSG = b"tbs-certificate-bytes-stand-in"
sig512 = sk_a.sign(MSG, hashfunc=hashlib.sha512, sigencode=sigencode_der)
assert sk_a.get_verifying_key().verify(sig512, MSG, hashfunc=hashlib.sha512, sigdecode=sigdecode_der)
out["sha512_msg"] = MSG.hex()
out["sha512_sig_der"] = sig512.hex()

# ---- signed message (sign_message / verify_message_for_address) -----------
MESSAGE = b"Satochip test message"
sig65 = ECPrivkey(PRIV_A).sign_message(MESSAGE, True)
out["message"] = MESSAGE.hex()
out["sig65_compressed"] = sig65.hex()

import json
print(json.dumps(out, indent=2))
