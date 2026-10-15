# -*- coding: utf-8 -*-
"""
Hardened AES-CBC primitives for the card secure channel.

`pyaes`, the pure-python AES this module can still fall back to, is table-driven
and unmaintained since 2017. Its lookup tables make the cipher's memory access
pattern depend on the key, which is observable through the CPU cache -- the same
class of side channel that got the pure-python `ecdsa` package removed in
v0.18.0 (CVE-2024-23342, issue #8), here applied to the secure-channel session
key rather than to a long-term key.

The backend is therefore selected in the same spirit as ec_backend.py:

  1. pyca/cryptography (OpenSSL) -- already a hard dependency and the default EC
     backend. Uses AES-NI where the CPU provides it, constant time otherwise.
  2. pycryptodomex -- also already a hard dependency, and likewise a native
     implementation. Covers hosts where cryptography is unavailable.
  3. pyaes -- last resort, for embedded builds (seedsigner-os) that ship
     neither. Kept so those builds keep working, not because it is good.

Unlike ec_backend, this module does NOT fail closed when only the weak backend
is present: refusing to talk to the card at all would be a worse outcome than a
cache-timing exposure on an ephemeral session key, and the secure channel is
mandatory from applet v0.11 onwards. It logs a warning instead.

The wire format is fixed by the applet: AES-128-CBC with PKCS#7 padding. The
padding is implemented here, once, so that all three backends behave
identically -- in particular, all three reject malformed padding, which pyaes's
own PADDING_DEFAULT does not.
"""

import logging

logger = logging.getLogger(__name__)
# NB: no logger.setLevel() here on purpose. Module loggers must stay at NOTSET
# so that a level set on the `pysatochip` package logger cascades to all of
# them -- see pysatochip.set_log_level().

BACKEND_CRYPTOGRAPHY = "cryptography"
BACKEND_PYCRYPTODOMEX = "pycryptodomex"
BACKEND_PYAES = "pyaes"

AES_BLOCK_SIZE = 16


class NoAESBackendError(Exception):
    """Raised when no AES implementation is available at all."""


class InvalidPaddingError(ValueError):
    """Raised when PKCS#7 padding is malformed."""


#
# backend detection
#

_cg_Cipher = _cg_algorithms = _cg_modes = None
_CD_AES = None
_pyaes = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _cg_Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _cg_algorithms
    from cryptography.hazmat.primitives.ciphers import modes as _cg_modes
    HAS_CRYPTOGRAPHY = True
except Exception as _ex:  # pragma: no cover - depends on the environment
    logger.debug("cryptography AES backend unavailable: %r", _ex)
    _cg_Cipher = _cg_algorithms = _cg_modes = None
    HAS_CRYPTOGRAPHY = False

try:
    from Cryptodome.Cipher import AES as _CD_AES
    HAS_PYCRYPTODOMEX = True
except Exception as _ex:  # pragma: no cover - depends on the environment
    logger.debug("pycryptodomex AES backend unavailable: %r", _ex)
    _CD_AES = None
    HAS_PYCRYPTODOMEX = False

try:
    import pyaes as _pyaes
    HAS_PYAES = True
except Exception as _ex:  # pragma: no cover - depends on the environment
    logger.debug("pyaes backend unavailable: %r", _ex)
    _pyaes = None
    HAS_PYAES = False


def _auto_backend():
    if HAS_CRYPTOGRAPHY:
        return BACKEND_CRYPTOGRAPHY
    if HAS_PYCRYPTODOMEX:
        return BACKEND_PYCRYPTODOMEX
    if HAS_PYAES:
        return BACKEND_PYAES
    return None


# Resolved once at import. Override with set_backend() for testing.
BACKEND = _auto_backend()

if BACKEND is None:  # pragma: no cover - depends on the environment
    logger.warning(
        "No AES backend found (need 'cryptography', 'pycryptodomex' or "
        "'pyaes'). The card secure channel will not work.")
elif BACKEND == BACKEND_PYAES:  # pragma: no cover - depends on the environment
    logger.warning(
        "Falling back to the pure-python 'pyaes' for the card secure channel. "
        "Its table-driven AES is cache-timing observable; install "
        "'cryptography' or 'pycryptodomex' for a hardened implementation.")


def available_backends():
    backends = []
    if HAS_CRYPTOGRAPHY:
        backends.append(BACKEND_CRYPTOGRAPHY)
    if HAS_PYCRYPTODOMEX:
        backends.append(BACKEND_PYCRYPTODOMEX)
    if HAS_PYAES:
        backends.append(BACKEND_PYAES)
    return tuple(backends)


def set_backend(backend):
    """Force a backend ("auto", "cryptography", "pycryptodomex", "pyaes").
    Returns the resolved backend. Intended for tests and for callers that want
    to pin behaviour."""
    global BACKEND
    _available = {
        BACKEND_CRYPTOGRAPHY: HAS_CRYPTOGRAPHY,
        BACKEND_PYCRYPTODOMEX: HAS_PYCRYPTODOMEX,
        BACKEND_PYAES: HAS_PYAES,
    }
    if backend in (None, "auto"):
        BACKEND = _auto_backend()
    elif backend in _available:
        if not _available[backend]:
            raise NoAESBackendError(
                "{} backend requested but unavailable".format(backend))
        BACKEND = backend
    else:
        raise ValueError("unknown AES backend: {}".format(backend))
    return BACKEND


def _require_backend():
    if BACKEND is None:
        raise NoAESBackendError(
            "No AES backend available. Install 'cryptography' (recommended), "
            "'pycryptodomex' or 'pyaes'.")
    return BACKEND


#
# PKCS#7 padding (shared by every backend, so they behave identically)
#

def pkcs7_pad(data: bytes) -> bytes:
    padsize = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return bytes(data) + bytes([padsize]) * padsize


def pkcs7_unpad(data: bytes) -> bytes:
    """Strict PKCS#7 unpadding.

    pyaes's PADDING_DEFAULT only checks that the final byte is <= 16 and never
    compares the padding bytes, so b'A'*15 + b'\\x00' decodes to b''. pyaes is
    still the last-resort backend, so validate here instead: on a channel whose
    responses carry no MAC, silently truncating a response to nothing is a far
    worse failure mode than raising.
    """
    if not data or len(data) % AES_BLOCK_SIZE != 0:
        raise InvalidPaddingError(
            "padded plaintext has invalid length {}".format(len(data)))
    padsize = data[-1]
    if padsize < 1 or padsize > AES_BLOCK_SIZE or padsize > len(data):
        raise InvalidPaddingError("invalid PKCS#7 pad byte {}".format(padsize))
    if data[-padsize:] != bytes([padsize]) * padsize:
        raise InvalidPaddingError("inconsistent PKCS#7 padding")
    return bytes(data[:-padsize])


#
# raw AES-CBC
#

def _check_args(key: bytes, iv: bytes):
    if len(key) not in (16, 24, 32):
        raise ValueError("invalid AES key length: {}".format(len(key)))
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("invalid AES-CBC IV length: {}".format(len(iv)))


def _cbc_raw(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    backend = _require_backend()
    if backend == BACKEND_CRYPTOGRAPHY:
        cipher = _cg_Cipher(_cg_algorithms.AES(bytes(key)), _cg_modes.CBC(bytes(iv)))
        op = cipher.encryptor() if encrypt else cipher.decryptor()
        return op.update(bytes(data)) + op.finalize()
    if backend == BACKEND_PYCRYPTODOMEX:
        cipher = _CD_AES.new(bytes(key), _CD_AES.MODE_CBC, bytes(iv))
        return cipher.encrypt(bytes(data)) if encrypt else cipher.decrypt(bytes(data))
    # pyaes has no streaming raw-CBC API; drive it a block at a time. Padding is
    # handled by this module, so PADDING_NONE semantics are what we want.
    mode = _pyaes.AESModeOfOperationCBC(bytes(key), iv=bytes(iv))
    step = mode.encrypt if encrypt else mode.decrypt
    return b''.join(step(bytes(data[i:i + AES_BLOCK_SIZE]))
                    for i in range(0, len(data), AES_BLOCK_SIZE))


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-CBC encrypt with PKCS#7 padding."""
    _check_args(key, iv)
    return _cbc_raw(key, iv, pkcs7_pad(plaintext), encrypt=True)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC decrypt and strip PKCS#7 padding.

    Raises InvalidPaddingError if the ciphertext length or the padding is
    malformed."""
    _check_args(key, iv)
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise InvalidPaddingError(
            "ciphertext length {} is not a non-zero multiple of the AES block "
            "size".format(len(ciphertext)))
    return pkcs7_unpad(_cbc_raw(key, iv, ciphertext, encrypt=False))
