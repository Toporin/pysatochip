# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from typing import Optional, Tuple, Union

from . import ec_backend, ec_math
# Re-exported unchanged so that existing importers of ecc.py keep working;
# several of these are unused here but are part of this module's public surface.
from .ec_math import (  # noqa: F401
    CURVE_ORDER,
    InvalidECPointException,
    get_y_coord_from_x,
    legendre_symbol,
    modular_sqrt,
    point_to_ser,
    ser_to_point,
)
from .util import assert_bytes, bfh, bh2u, sha256d, to_bytes, var_int

# Note: this module used to be implemented on top of the pure-python `ecdsa`
# package. That package is vulnerable to a timing side-channel attack on every
# operation involving a private key (CVE-2024-23342) and is not maintained as a
# production implementation, so it was removed entirely -- see issue #8.
# Secret-dependent operations now go through ec_backend (pyca/cryptography, or
# libsecp256k1 via embit); public-key arithmetic lives in ec_math.


def generator() -> 'ECPubkey':
    return ECPubkey.from_point(ec_math.GENERATOR)


def point_at_infinity() -> 'ECPubkey':
    return ECPubkey(None)


def sig_string_from_der_sig(der_sig: bytes, order: int = CURVE_ORDER) -> bytes:
    r, s = ec_math.decode_der(der_sig)
    return ec_math.encode_string(r, s, order)


def der_sig_from_sig_string(sig_string: bytes, order: int = CURVE_ORDER) -> bytes:
    r, s = ec_math.decode_string(sig_string, order)
    return ec_math.encode_der(r, ec_math.canonicalize_s(s, order))


def der_sig_from_r_and_s(r: int, s: int, order: int = CURVE_ORDER) -> bytes:
    return ec_math.encode_der(r, ec_math.canonicalize_s(s, order))


def get_r_and_s_from_der_sig(der_sig: bytes, order: int = CURVE_ORDER) -> Tuple[int, int]:
    return ec_math.decode_der(der_sig)


def get_r_and_s_from_sig_string(sig_string: bytes, order: int = CURVE_ORDER) -> Tuple[int, int]:
    return ec_math.decode_string(sig_string, order)


def sig_string_from_r_and_s(r: int, s: int, order: int = CURVE_ORDER) -> bytes:
    return ec_math.encode_string(r, ec_math.canonicalize_s(s, order), order)


def is_secret_within_curve_range(secret: Union[int, bytes]) -> bool:
    return ec_math.is_secret_within_curve_range(secret)


class ECPubkey(object):

    def __init__(self, b: Optional[bytes]):
        if b is not None:
            assert_bytes(b)
            x, y = ec_math.ser_to_point(b)
            if not ec_math.contains_point(x, y):
                raise InvalidECPointException(
                    'public key is not on the secp256k1 curve')
            self._point = (x, y)
        else:
            self._point = (None, None)

    @classmethod
    def from_sig_string(cls, sig_string: bytes, recid: int, msg_hash: bytes) -> 'ECPubkey':
        assert_bytes(sig_string)
        if len(sig_string) != 64:
            raise Exception('Wrong encoding')
        if recid < 0 or recid > 3:
            raise ValueError('recid is {}, but should be 0 <= recid <= 3'.format(recid))
        return ECPubkey(ec_backend.recover_pubkey(sig_string, recid, msg_hash))

    @classmethod
    def from_signature65(cls, sig: bytes, msg_hash: bytes) -> Tuple['ECPubkey', bool]:
        if len(sig) != 65:
            raise Exception("Wrong encoding")
        nV = sig[0]
        if nV < 27 or nV >= 35:
            raise Exception("Bad encoding")
        if nV >= 31:
            compressed = True
            nV -= 4
        else:
            compressed = False
        recid = nV - 27
        return cls.from_sig_string(sig[1:], recid, msg_hash), compressed

    @classmethod
    def from_point(cls, point) -> 'ECPubkey':
        _bytes = point_to_ser(point, compressed=False)  # faster than compressed
        return ECPubkey(_bytes)

    def get_public_key_bytes(self, compressed: bool = True) -> bytes:
        if self.is_at_infinity():
            raise Exception('point is at infinity')
        return point_to_ser(self.point(), compressed)

    def get_public_key_hex(self, compressed: bool = True) -> str:
        return bh2u(self.get_public_key_bytes(compressed))

    def point(self) -> Tuple[int, int]:
        return self._point

    def _as_math_point(self) -> ec_math.Point:
        x, y = self._point
        if x is None:
            return ec_math.INFINITY
        return ec_math.Point(x, y, validate=False)

    def __mul__(self, other: int) -> 'ECPubkey':
        if not isinstance(other, int):
            raise TypeError('multiplication not defined for ECPubkey and {}'.format(type(other)))
        return self.from_point(self._as_math_point() * other)

    def __rmul__(self, other: int) -> 'ECPubkey':
        return self * other

    def __add__(self, other) -> 'ECPubkey':
        if not isinstance(other, ECPubkey):
            raise TypeError('addition not defined for ECPubkey and {}'.format(type(other)))
        return self.from_point(self._as_math_point() + other._as_math_point())

    def __eq__(self, other) -> bool:
        if not isinstance(other, ECPubkey):
            return NotImplemented
        return self._point == other._point

    def __ne__(self, other) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self._point)

    def verify_message_for_address(self, sig65: bytes, message: bytes) -> None:
        assert_bytes(message)
        h = sha256d(msg_magic(message))
        public_key, compressed = self.from_signature65(sig65, h)
        # check public key
        if public_key != self:
            raise Exception("Bad signature")
        # check message
        self.verify_message_hash(sig65[1:], h)

    def verify_message_hash(self, sig_string: bytes, msg_hash: bytes) -> None:
        assert_bytes(sig_string)
        if len(sig_string) != 64:
            raise Exception('Wrong encoding')
        r, s = ec_math.decode_string(sig_string)
        der_sig = ec_math.encode_der(r, s)
        if not ec_backend.verify_digest(
                self.get_public_key_bytes(compressed=False), der_sig, msg_hash):
            raise Exception('Bad signature')

    @classmethod
    def order(cls) -> int:
        return CURVE_ORDER

    def is_at_infinity(self) -> bool:
        return self._point[0] is None

    @classmethod
    def is_pubkey_bytes(cls, b: bytes) -> bool:
        try:
            ECPubkey(b)
            return True
        except Exception:
            return False


def msg_magic(message: bytes) -> bytes:
    length = bfh(var_int(len(message)))
    return b"\x18Bitcoin Signed Message:\n" + length + message


class ECPrivkey(ECPubkey):

    def __init__(self, privkey_bytes: bytes):
        assert_bytes(privkey_bytes)
        if len(privkey_bytes) != 32:
            raise Exception('unexpected size for secret. should be 32 bytes, not {}'.format(len(privkey_bytes)))
        self._privkey_bytes = bytes(privkey_bytes)
        secret = ec_math.string_to_number(privkey_bytes)
        if not is_secret_within_curve_range(secret):
            raise InvalidECPointException('Invalid secret scalar (not within curve order)')
        self.secret_scalar = secret

        # the secret scalar multiplication happens inside the hardened backend
        super().__init__(ec_backend.privkey_to_pubkey(self._privkey_bytes,
                                                      compressed=False))

    @classmethod
    def from_secret_scalar(cls, secret_scalar: int) -> 'ECPrivkey':
        secret_bytes = ec_math.number_to_string(secret_scalar, CURVE_ORDER)
        return ECPrivkey(secret_bytes)

    @classmethod
    def from_arbitrary_size_secret(cls, privkey_bytes: bytes) -> 'ECPrivkey':
        """This method is only for legacy reasons. Do not introduce new code that uses it.
        Unlike the default constructor, this method does not require len(privkey_bytes) == 32,
        and the secret does not need to be within the curve order either.
        """
        return ECPrivkey(cls.normalize_secret_bytes(privkey_bytes))

    @classmethod
    def normalize_secret_bytes(cls, privkey_bytes: bytes) -> bytes:
        scalar = ec_math.string_to_number(privkey_bytes) % CURVE_ORDER
        if scalar == 0:
            raise Exception('invalid EC private key scalar: zero')
        return ec_math.number_to_string(scalar, CURVE_ORDER)

    def get_private_key_bytes(self) -> bytes:
        return self._privkey_bytes

    def sign(self, data: bytes, sigencode=None, sigdecode=None) -> bytes:
        """Sign a 32-byte digest, enforcing the low-S rule.

        The nonce is chosen by the backend: RFC-6979 (deterministic) on
        libsecp256k1, random on cryptography/OpenSSL. Signatures are therefore
        no longer guaranteed to be byte-identical between runs or backends,
        though they remain valid and Bitcoin-compliant.
        """
        if sigencode is None:
            sigencode = sig_string_from_r_and_s
        if sigdecode is None:
            sigdecode = get_r_and_s_from_sig_string
        r, s = ec_backend.sign_digest(self._privkey_bytes, data)
        sig = sigencode(r, s, CURVE_ORDER)
        # sanity check that we can verify our own signature
        r2, s2 = sigdecode(sig, CURVE_ORDER)
        if not ec_backend.verify_digest(
                self.get_public_key_bytes(compressed=False),
                ec_math.encode_der(r2, s2), data):
            raise Exception('Sanity check verifying our own signature failed.')
        return sig

    def sign_transaction(self, hashed_preimage: bytes) -> bytes:
        return self.sign(hashed_preimage,
                         sigencode=der_sig_from_r_and_s,
                         sigdecode=get_r_and_s_from_der_sig)

    def sign_message(self, message: bytes, is_compressed: bool) -> bytes:
        def bruteforce_recid(sig_string):
            for recid in range(4):
                sig65 = construct_sig65(sig_string, recid, is_compressed)
                try:
                    self.verify_message_for_address(sig65, message)
                    return sig65, recid
                except Exception:
                    continue
            else:
                raise Exception("error: cannot sign message. no recid fits..")

        message = to_bytes(message, 'utf8')
        msg_hash = sha256d(msg_magic(message))
        sig_string = self.sign(msg_hash,
                               sigencode=sig_string_from_r_and_s,
                               sigdecode=get_r_and_s_from_sig_string)
        sig65, recid = bruteforce_recid(sig_string)
        return sig65


def construct_sig65(sig_string: bytes, recid: int, is_compressed: bool) -> bytes:
    comp = 4 if is_compressed else 0
    return bytes([27 + recid + comp]) + sig_string
