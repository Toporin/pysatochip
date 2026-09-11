# -*- coding: utf-8 -*-
"""
Hardened elliptic-curve primitives for pysatochip.

pysatochip used to rely on the pure-python `ecdsa` package for every EC
operation. That package is affected by CVE-2024-23342 (the "Minerva" timing
attack): its scalar multiplication is not constant time, so signing and ECDH --
the operations that touch a private key -- leak information about the secret
through timing. Upstream closed the report as "not planned" and describes the
library as a teaching/testing tool rather than a production implementation, so
pysatochip no longer depends on it at all. See issue #8.

Every secret-dependent operation is therefore delegated to a hardened backend:

  1. pyca/cryptography (OpenSSL) -- already a pysatochip dependency, available
     as a wheel on every desktop platform. This is the default.
  2. embit's ctypes binding to libsecp256k1 -- Bitcoin Core's constant-time,
     blinded implementation. Used when cryptography is unavailable, which is the
     case on the shipped seedsigner-os Raspberry Pi images: those enable
     BR2_PACKAGE_PYTHON_EMBIT (with a prebuilt libsecp256k1 for armv6l/armv7l/
     aarch64) but not BR2_PACKAGE_PYTHON_CRYPTOGRAPHY.

If neither is importable, secret-dependent calls raise NoECBackendError rather
than silently falling back to a vulnerable implementation. Verification and
public-key handling keep working in that case, via ec_math and pycryptodomex.

Public keys and signatures cross this API as bytes; no backend object leaks to
callers.
"""

import hashlib
import logging
from os import urandom
from typing import Optional, Tuple

from . import ec_math
from .ec_math import CURVE_ORDER, InvalidECPointException

logger = logging.getLogger(__name__)

BACKEND_CRYPTOGRAPHY = "cryptography"
BACKEND_EMBIT = "embit"

_HASHLIB = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


class NoECBackendError(Exception):
    """Raised when no side-channel-hardened EC backend is available."""


class UnsupportedCurveError(Exception):
    """Raised when the available backend cannot handle the requested curve."""


#
# backend detection
#

_ec = None       # cryptography.hazmat.primitives.asymmetric.ec
_asym_utils = None
_hashes = None
_serialization = None
_secp = None     # embit.util.ctypes_secp256k1

try:
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import utils as _asym_utils
    # secp256k1 is optional in OpenSSL builds, so prove it actually works
    _ec.derive_private_key(1, _ec.SECP256K1())
    HAS_CRYPTOGRAPHY = True
except Exception as _ex:  # pragma: no cover - depends on the environment
    logger.debug("cryptography EC backend unavailable: %r", _ex)
    _ec = _asym_utils = _hashes = _serialization = None
    HAS_CRYPTOGRAPHY = False

try:
    # Import ctypes_secp256k1 DIRECTLY. embit.util.secp256k1 wraps this import
    # in a bare except and falls back to embit.util.py_secp256k1, a pure-python
    # implementation that is NOT constant time -- accepting that would silently
    # reintroduce exactly the vulnerability we are removing here.
    from embit.util import ctypes_secp256k1 as _secp
    # ECDH and recovery are optional libsecp256k1 modules; embit hides the
    # wrapper when the symbol is missing, so require them explicitly.
    for _sym in ("ecdh", "ecdsa_recover", "ec_pubkey_tweak_mul", "ecdsa_sign"):
        if not hasattr(_secp, _sym):
            raise ImportError(
                "libsecp256k1 loaded by embit lacks {}".format(_sym))
    HAS_EMBIT = True
except Exception as _ex:  # pragma: no cover - depends on the environment
    logger.debug("embit/libsecp256k1 EC backend unavailable: %r", _ex)
    _secp = None
    HAS_EMBIT = False

try:
    from Cryptodome.Hash import SHA256 as _CD_SHA256
    from Cryptodome.Hash import SHA384 as _CD_SHA384
    from Cryptodome.Hash import SHA512 as _CD_SHA512
    from Cryptodome.PublicKey import ECC as _CD_ECC
    from Cryptodome.Signature import DSS as _CD_DSS
    HAS_PYCRYPTODOMEX = True
    _CD_HASHES = {"sha256": _CD_SHA256, "sha384": _CD_SHA384, "sha512": _CD_SHA512}
except Exception as _ex:  # pragma: no cover - depends on the environment
    logger.debug("pycryptodomex unavailable: %r", _ex)
    HAS_PYCRYPTODOMEX = False
    _CD_HASHES = {}


def _auto_backend() -> Optional[str]:
    if HAS_CRYPTOGRAPHY:
        return BACKEND_CRYPTOGRAPHY
    if HAS_EMBIT:
        return BACKEND_EMBIT
    return None


# Resolved once at import. Override with set_backend() for testing.
BACKEND = _auto_backend()

if BACKEND is None:  # pragma: no cover - depends on the environment
    logger.warning(
        "No hardened EC backend found (need 'cryptography' or 'embit'). "
        "Signature verification still works, but any operation involving a "
        "private key will fail.")


def available_backends() -> Tuple[str, ...]:
    backends = []
    if HAS_CRYPTOGRAPHY:
        backends.append(BACKEND_CRYPTOGRAPHY)
    if HAS_EMBIT:
        backends.append(BACKEND_EMBIT)
    return tuple(backends)


def set_backend(backend: Optional[str]) -> Optional[str]:
    """Force a backend ("auto", "cryptography", "embit"). Returns the resolved
    backend. Intended for tests and for callers that want to pin behaviour."""
    global BACKEND
    if backend in (None, "auto"):
        BACKEND = _auto_backend()
    elif backend == BACKEND_CRYPTOGRAPHY:
        if not HAS_CRYPTOGRAPHY:
            raise NoECBackendError("cryptography backend requested but unavailable")
        BACKEND = BACKEND_CRYPTOGRAPHY
    elif backend == BACKEND_EMBIT:
        if not HAS_EMBIT:
            raise NoECBackendError("embit backend requested but unavailable")
        BACKEND = BACKEND_EMBIT
    else:
        raise ValueError("unknown EC backend: {}".format(backend))
    return BACKEND


def _require_backend() -> str:
    if BACKEND is None:
        raise NoECBackendError(
            "No side-channel-hardened EC backend available. Install "
            "'cryptography' (recommended) or 'embit' (bundles libsecp256k1). "
            "pysatochip refuses to perform private key operations with a "
            "known-vulnerable implementation (CVE-2024-23342).")
    return BACKEND


def _hashfunc(hashalg: str):
    try:
        return _HASHLIB[hashalg]
    except KeyError:
        raise ValueError("unsupported hash algorithm: {}".format(hashalg))


#
# helpers
#

def _check_privkey(privkey_bytes: bytes) -> bytes:
    privkey_bytes = bytes(privkey_bytes)
    if len(privkey_bytes) != 32:
        raise ValueError(
            "private key must be 32 bytes, not {}".format(len(privkey_bytes)))
    if not ec_math.is_secret_within_curve_range(privkey_bytes):
        raise InvalidECPointException(
            "invalid private key scalar (not within curve order)")
    return privkey_bytes


def _normalize_pubkey(pubkey_bytes: bytes) -> bytes:
    """Validate a serialized public key and return it uncompressed (65 bytes).

    Rejects points that are not on the curve, which `ecdsa` used to do via
    VerifyingKey.from_string(validate_point=True).
    """
    x, y = ec_math.ser_to_point(pubkey_bytes)
    if not ec_math.contains_point(x, y):
        raise InvalidECPointException("public key is not on the secp256k1 curve")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _cg_load_pubkey(pubkey_bytes: bytes):
    return _ec.EllipticCurvePublicKey.from_encoded_point(
        _ec.SECP256K1(), _normalize_pubkey(pubkey_bytes))


def _truncate_digest(digest: bytes) -> bytes:
    """libsecp256k1 takes exactly a 32-byte hash.

    ECDSA uses the leftmost n bits of the digest, so a SHA-384/512 digest is
    truncated to its leftmost 32 bytes. Shorter digests are not padded --
    pysatochip never uses a hash below 256 bits.
    """
    digest = bytes(digest)
    if len(digest) < 32:
        raise ValueError(
            "digest must be at least 32 bytes, got {}".format(len(digest)))
    return digest[:32]


#
# key generation and derivation  (SECRET-DEPENDENT)
#

def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (privkey_bytes, uncompressed pubkey bytes) for a fresh keypair."""
    backend = _require_backend()
    if backend == BACKEND_CRYPTOGRAPHY:
        key = _ec.generate_private_key(_ec.SECP256K1())
        privkey_bytes = key.private_numbers().private_value.to_bytes(32, "big")
        pubkey_bytes = key.public_key().public_bytes(
            _serialization.Encoding.X962,
            _serialization.PublicFormat.UncompressedPoint)
        return privkey_bytes, bytes(pubkey_bytes)
    # embit: rejection-sample a scalar, then derive the point in libsecp256k1
    while True:
        candidate = urandom(32)
        if ec_math.is_secret_within_curve_range(candidate):
            return candidate, privkey_to_pubkey(candidate, compressed=False)


def privkey_to_pubkey(privkey_bytes: bytes, compressed: bool = False) -> bytes:
    """Derive a public key from a private key (secret scalar multiplication)."""
    backend = _require_backend()
    privkey_bytes = _check_privkey(privkey_bytes)
    if backend == BACKEND_CRYPTOGRAPHY:
        key = _ec.derive_private_key(
            ec_math.string_to_number(privkey_bytes), _ec.SECP256K1())
        fmt = (_serialization.PublicFormat.CompressedPoint if compressed
               else _serialization.PublicFormat.UncompressedPoint)
        return bytes(key.public_key().public_bytes(
            _serialization.Encoding.X962, fmt))
    pubkey = _secp.ec_pubkey_create(privkey_bytes)
    flag = _secp.EC_COMPRESSED if compressed else _secp.EC_UNCOMPRESSED
    return bytes(_secp.ec_pubkey_serialize(pubkey, flag))


#
# ECDH  (SECRET-DEPENDENT)
#

def ecdh_shared_x(privkey_bytes: bytes, peer_pubkey_bytes: bytes) -> bytes:
    """ECDH shared secret as the raw 32-byte x-coordinate of privkey * peer.

    This is what the Satochip/SeedKeeper secure channel and the SeedKeeper
    encrypted-export format expect, and it is what ecdsa's
    ECDH.generate_sharedsecret_bytes() returned. Note that libsecp256k1's
    built-in secp256k1_ecdh() instead returns SHA-256 of the compressed point,
    so the embit path multiplies the point and takes x directly.
    """
    backend = _require_backend()
    privkey_bytes = _check_privkey(privkey_bytes)
    peer_pubkey_bytes = _normalize_pubkey(peer_pubkey_bytes)
    if backend == BACKEND_CRYPTOGRAPHY:
        key = _ec.derive_private_key(
            ec_math.string_to_number(privkey_bytes), _ec.SECP256K1())
        shared = key.exchange(_ec.ECDH(), _cg_load_pubkey(peer_pubkey_bytes))
        return bytes(shared)
    # libsecp256k1's default ECDH hash function returns SHA-256 of the
    # compressed shared point; pass a hash function that hands back the raw
    # x-coordinate instead, which is what the applet derives.
    pubkey = _secp.ec_pubkey_parse(peer_pubkey_bytes)
    return bytes(_secp.ecdh(pubkey, privkey_bytes,
                            hashfn=lambda x, y, data: x))


#
# signing  (SECRET-DEPENDENT)
#

def sign_digest(privkey_bytes: bytes, digest: bytes) -> Tuple[int, int]:
    """Sign a 32-byte digest. Returns (r, s) with s canonicalized to low-S.

    The nonce is backend-dependent: libsecp256k1 uses RFC-6979 (deterministic),
    while cryptography/OpenSSL uses a random nonce. Both produce valid,
    Bitcoin-compliant signatures; RFC-6979 is not required for validity, so
    signatures are no longer byte-identical across backends.
    """
    backend = _require_backend()
    privkey_bytes = _check_privkey(privkey_bytes)
    digest = _truncate_digest(digest)
    if backend == BACKEND_CRYPTOGRAPHY:
        key = _ec.derive_private_key(
            ec_math.string_to_number(privkey_bytes), _ec.SECP256K1())
        der = key.sign(digest, _ec.ECDSA(_asym_utils.Prehashed(_hashes.SHA256())))
        r, s = _asym_utils.decode_dss_signature(der)
    else:
        sig = _secp.ecdsa_sign(digest, privkey_bytes)
        der = bytes(_secp.ecdsa_signature_serialize_der(sig))
        r, s = ec_math.decode_der(der)
    return r, ec_math.canonicalize_s(s)


#
# verification  (PUBLIC -- no secrets involved)
#

def verify_digest(pubkey_bytes: bytes, der_sig: bytes, digest: bytes) -> bool:
    """Verify a DER signature over a pre-hashed message.

    High-S signatures are accepted: they are valid ECDSA and pysatochip has to
    handle whatever the card or a certificate authority produced.
    """
    pubkey_bytes = _normalize_pubkey(pubkey_bytes)
    digest = _truncate_digest(digest)
    if BACKEND == BACKEND_CRYPTOGRAPHY:
        from cryptography.exceptions import InvalidSignature
        try:
            _cg_load_pubkey(pubkey_bytes).verify(
                bytes(der_sig), digest,
                _ec.ECDSA(_asym_utils.Prehashed(_hashes.SHA256())))
            return True
        except InvalidSignature:
            return False
    if BACKEND == BACKEND_EMBIT:
        try:
            sig = _secp.ecdsa_signature_parse_der(bytes(der_sig))
        except Exception:
            return False
        # libsecp256k1 rejects high-S signatures by policy, but a card or a
        # certificate authority is not bound by the low-S rule, so normalize
        # before verifying
        sig = _secp.ecdsa_signature_normalize(sig)
        pubkey = _secp.ec_pubkey_parse(pubkey_bytes)
        try:
            return bool(_secp.ecdsa_verify(sig, digest, pubkey))
        except Exception:
            return False
    # No hardened backend: verification involves no secret, so fall back to
    # pure python rather than refusing to check signatures at all.
    return _verify_digest_pure(pubkey_bytes, der_sig, digest)


def _verify_digest_pure(pubkey_bytes: bytes, der_sig: bytes, digest: bytes) -> bool:
    try:
        r, s = ec_math.decode_der(der_sig)
    except Exception:
        return False
    n = CURVE_ORDER
    if not (0 < r < n and 0 < s < n):
        return False
    try:
        point = ec_math.ser_to_point_obj(pubkey_bytes)
    except Exception:
        return False
    e = ec_math.string_to_number(_truncate_digest(digest))
    w = ec_math.inverse_mod(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    xy = ec_math.GENERATOR * u1 + point * u2
    if xy.is_at_infinity():
        return False
    return xy.x % n == r % n


def verify_message(pubkey_bytes: bytes, message: bytes, der_sig: bytes,
                   hashalg: str = "sha256") -> bool:
    """Verify a DER signature over an unhashed message (secp256k1)."""
    digest = _hashfunc(hashalg)(bytes(message)).digest()
    return verify_digest(pubkey_bytes, der_sig, digest)


def verify_p384(pubkey_bytes: bytes, message: bytes, der_sig: bytes,
                hashalg: str = "sha384") -> bool:
    """Verify a DER signature over an unhashed message on NIST P-384.

    Needed for the root-CA -> subCA link of the Satochip certificate chain.
    libsecp256k1 cannot do P-384 at all, so the fallback here is pycryptodomex
    rather than embit.
    """
    pubkey_bytes = bytes(pubkey_bytes)
    if len(pubkey_bytes) != 97 or pubkey_bytes[0] != 0x04:
        raise InvalidECPointException(
            "expected a 97-byte uncompressed P-384 public key")
    if HAS_CRYPTOGRAPHY:
        from cryptography.exceptions import InvalidSignature
        hash_cls = {"sha256": _hashes.SHA256, "sha384": _hashes.SHA384,
                    "sha512": _hashes.SHA512}.get(hashalg)
        if hash_cls is None:
            raise ValueError("unsupported hash algorithm: {}".format(hashalg))
        pub = _ec.EllipticCurvePublicKey.from_encoded_point(
            _ec.SECP384R1(), pubkey_bytes)
        try:
            pub.verify(bytes(der_sig), bytes(message), _ec.ECDSA(hash_cls()))
            return True
        except InvalidSignature:
            return False
    if HAS_PYCRYPTODOMEX:
        hash_mod = _CD_HASHES.get(hashalg)
        if hash_mod is None:
            raise ValueError("unsupported hash algorithm: {}".format(hashalg))
        key = _CD_ECC.construct(
            curve="NIST P-384",
            point_x=ec_math.string_to_number(pubkey_bytes[1:49]),
            point_y=ec_math.string_to_number(pubkey_bytes[49:97]))
        verifier = _CD_DSS.new(key, "fips-186-3", encoding="der")
        try:
            verifier.verify(hash_mod.new(bytes(message)), bytes(der_sig))
            return True
        except ValueError:
            return False
    raise UnsupportedCurveError(
        "NIST P-384 verification needs 'cryptography' or 'pycryptodomex'")


#
# public key recovery  (PUBLIC -- no secrets involved)
#

def recover_pubkey(sig_string: bytes, recid: int, msg_hash: bytes) -> bytes:
    """Recover the uncompressed pubkey from a 64-byte compact signature.

    pyca/cryptography exposes no recovery API, so ec_math's pure-python
    implementation is used there. libsecp256k1 has secp256k1_ecdsa_recover and
    is preferred when present.
    """
    if BACKEND == BACKEND_EMBIT:
        if recid < 0 or recid > 3:
            raise ValueError(
                "recid is {}, but should be 0 <= recid <= 3".format(recid))
        try:
            sig = _secp.ecdsa_recoverable_signature_parse_compact(
                bytes(sig_string), recid)
            pubkey = _secp.ecdsa_recover(sig, _truncate_digest(msg_hash))
            return bytes(_secp.ec_pubkey_serialize(pubkey, _secp.EC_UNCOMPRESSED))
        except InvalidECPointException:
            raise
        except Exception as ex:
            raise InvalidECPointException(
                "could not recover public key: {!r}".format(ex))
    return ec_math.recover_pubkey(sig_string, recid, msg_hash)
