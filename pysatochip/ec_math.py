# -*- coding: utf-8 -*-
"""
Pure-python secp256k1 arithmetic and signature encoding.

Everything here operates on PUBLIC data only -- public keys, signatures and
message hashes. No function in this module ever touches a private key, so a
constant-time implementation is not required; secret-dependent operations live
in ec_backend.py and are delegated to a hardened library.

This replaces the parts of the `ecdsa` package that pysatochip used for
public-key handling (ecdsa.ellipticcurve, ecdsa.numbertheory, ecdsa.util).
See issue #8 / CVE-2024-23342.

The point arithmetic and the public key recovery below are ported from the
Electrum-derived code that previously lived in ecc.py.
"""

from typing import Optional, Tuple

# secp256k1 domain parameters (SEC 2, section 2.4.1)
CURVE_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_A = 0
CURVE_B = 7
CURVE_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
CURVE_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class InvalidECPointException(Exception):
    """e.g. not on curve, or infinity"""


def inverse_mod(a: int, m: int) -> int:
    """Modular inverse via the extended Euclidean algorithm.

    Spelled out rather than using pow(a, -1, m), which needs python 3.8 while
    setup.py still declares python_requires='>=3.6'.
    """
    a %= m
    if a == 0:
        raise ZeroDivisionError('no inverse of 0')
    old_r, r = a, m
    old_x, x = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
    if old_r != 1:
        raise ZeroDivisionError('{} has no inverse mod {}'.format(a, m))
    return old_x % m


def legendre_symbol(a: int, p: int) -> int:
    """ Compute the Legendre symbol a|p using Euler's criterion.
    p is a prime, a is relatively prime to p (if p divides a, then a|p = 0)

    Returns 1 if a has a square root modulo p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


# from http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/
def modular_sqrt(a: int, p: int) -> int:
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.

    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.

    0 is returned is no square root exists for
    these a and p.

    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


class Point:
    """An affine point on secp256k1, or the point at infinity (x is None).

    Only public values are ever multiplied here, so the double-and-add below is
    deliberately simple rather than constant-time.
    """

    __slots__ = ('x', 'y')

    def __init__(self, x: Optional[int], y: Optional[int], *, validate: bool = True):
        self.x = x
        self.y = y
        if validate and not self.is_at_infinity():
            if not contains_point(x, y):
                raise InvalidECPointException(
                    'point is not on the secp256k1 curve'
                )

    def is_at_infinity(self) -> bool:
        return self.x is None

    def __eq__(self, other):
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.x, self.y))

    def __neg__(self) -> 'Point':
        if self.is_at_infinity():
            return self
        return Point(self.x, (-self.y) % CURVE_P, validate=False)

    def __add__(self, other: 'Point') -> 'Point':
        if not isinstance(other, Point):
            return NotImplemented
        if self.is_at_infinity():
            return other
        if other.is_at_infinity():
            return self
        if self.x == other.x:
            if (self.y + other.y) % CURVE_P == 0:
                return INFINITY
            return self._double()
        lam = ((other.y - self.y) * inverse_mod(other.x - self.x, CURVE_P)) % CURVE_P
        x = (lam * lam - self.x - other.x) % CURVE_P
        y = (lam * (self.x - x) - self.y) % CURVE_P
        return Point(x, y, validate=False)

    def _double(self) -> 'Point':
        if self.is_at_infinity() or self.y == 0:
            return INFINITY
        lam = ((3 * self.x * self.x + CURVE_A) * inverse_mod(2 * self.y, CURVE_P)) % CURVE_P
        x = (lam * lam - 2 * self.x) % CURVE_P
        y = (lam * (self.x - x) - self.y) % CURVE_P
        return Point(x, y, validate=False)

    def __mul__(self, scalar: int) -> 'Point':
        if not isinstance(scalar, int):
            return NotImplemented
        scalar %= CURVE_ORDER
        if scalar == 0 or self.is_at_infinity():
            return INFINITY
        if scalar < 0:
            return (-self) * (-scalar)
        result = INFINITY
        addend = self
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend._double()
            scalar >>= 1
        return result

    def __rmul__(self, scalar: int) -> 'Point':
        return self * scalar


INFINITY = Point(None, None, validate=False)
GENERATOR = Point(CURVE_GX, CURVE_GY, validate=False)


def contains_point(x: int, y: int) -> bool:
    """True if (x, y) satisfies y^2 = x^3 + ax + b (mod p)."""
    if x is None or y is None:
        return False
    if not (0 <= x < CURVE_P) or not (0 <= y < CURVE_P):
        return False
    return (y * y - (x * x * x + CURVE_A * x + CURVE_B)) % CURVE_P == 0


#
# integer <-> big-endian bytes (replaces ecdsa.util.string_to_number /
# number_to_string)
#

def string_to_number(b: bytes) -> int:
    return int.from_bytes(bytes(b), byteorder='big')


def number_to_string(n: int, order: int = CURVE_ORDER) -> bytes:
    length = (order.bit_length() + 7) // 8
    if not 0 <= n < order:
        raise ValueError(f'number out of range: {n}')
    return n.to_bytes(length, byteorder='big')


#
# point serialization
#

def get_y_coord_from_x(x: int, odd: bool = True) -> int:
    x = x % CURVE_P
    y2 = (pow(x, 3, CURVE_P) + CURVE_A * x + CURVE_B) % CURVE_P
    y = modular_sqrt(y2, CURVE_P)
    if contains_point(x, y):
        if odd == bool(y & 1):
            return y
        return CURVE_P - y
    raise InvalidECPointException()


def ser_to_point(ser: bytes) -> Tuple[int, int]:
    ser = bytes(ser)
    if len(ser) == 0 or ser[0] not in (0x02, 0x03, 0x04):
        raise InvalidECPointException(
            'Unexpected first byte: {}'.format(ser[0] if ser else None))
    if ser[0] == 0x04:
        if len(ser) != 65:
            raise InvalidECPointException(
                'uncompressed pubkey must be 65 bytes, not {}'.format(len(ser)))
        return string_to_number(ser[1:33]), string_to_number(ser[33:])
    if len(ser) != 33:
        raise InvalidECPointException(
            'compressed pubkey must be 33 bytes, not {}'.format(len(ser)))
    x = string_to_number(ser[1:])
    return x, get_y_coord_from_x(x, ser[0] == 0x03)


def ser_to_point_obj(ser: bytes) -> Point:
    x, y = ser_to_point(ser)
    try:
        return Point(x, y)
    except InvalidECPointException:
        raise
    except Exception:
        raise InvalidECPointException()


def point_to_ser(P, compressed: bool = True) -> Optional[bytes]:
    if isinstance(P, Point):
        x, y = P.x, P.y
    elif isinstance(P, tuple):
        assert len(P) == 2, 'unexpected point: %s' % (P,)
        x, y = P
    else:  # duck-type the old ecdsa Point interface
        x, y = P.x(), P.y()
    if x is None or y is None:  # infinity
        return None
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


#
# signature encoding (replaces ecdsa.util.sigencode_* / sigdecode_*)
#

def _der_encode_int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), 'big')
    return b'\x02' + bytes([len(b)]) + b


def encode_der(r: int, s: int) -> bytes:
    body = _der_encode_int(r) + _der_encode_int(s)
    if len(body) > 0x7F:
        raise ValueError('signature too long to DER-encode')
    return b'\x30' + bytes([len(body)]) + body


def decode_der(der_sig: bytes) -> Tuple[int, int]:
    """Strict-enough DER decoder for ECDSA-Sig-Value."""
    der_sig = bytes(der_sig)
    if len(der_sig) < 8 or der_sig[0] != 0x30:
        raise ValueError('malformed signature: expected a DER sequence')
    if der_sig[1] != len(der_sig) - 2:
        raise ValueError('malformed signature: bad sequence length')

    def read_int(data: bytes, offset: int) -> Tuple[int, int]:
        if data[offset] != 0x02:
            raise ValueError('malformed signature: expected a DER integer')
        length = data[offset + 1]
        if length == 0 or offset + 2 + length > len(data):
            raise ValueError('malformed signature: bad integer length')
        chunk = data[offset + 2:offset + 2 + length]
        if chunk[0] & 0x80:
            raise ValueError('malformed signature: negative integer')
        if chunk[0] == 0x00 and length > 1 and not (chunk[1] & 0x80):
            raise ValueError('malformed signature: excess padding')
        return string_to_number(chunk), offset + 2 + length

    r, offset = read_int(der_sig, 2)
    s, offset = read_int(der_sig, offset)
    if offset != len(der_sig):
        raise ValueError('malformed signature: trailing bytes')
    return r, s


def encode_string(r: int, s: int, order: int = CURVE_ORDER) -> bytes:
    """64-byte compact encoding (r || s)."""
    return number_to_string(r, order) + number_to_string(s, order)


def decode_string(sig_string: bytes, order: int = CURVE_ORDER) -> Tuple[int, int]:
    sig_string = bytes(sig_string)
    length = (order.bit_length() + 7) // 8
    if len(sig_string) != 2 * length:
        raise ValueError(
            'malformed signature: expected {} bytes, got {}'.format(
                2 * length, len(sig_string)))
    return string_to_number(sig_string[:length]), string_to_number(sig_string[length:])


def canonicalize_s(s: int, order: int = CURVE_ORDER) -> int:
    """Enforce the low-S rule (BIP-62) required by Bitcoin consensus."""
    return order - s if s > order // 2 else s


#
# public key recovery
#

def recover_pubkey(sig_string: bytes, recid: int, msg_hash: bytes) -> bytes:
    """Recover the uncompressed public key that produced a signature.

    See http://www.secg.org/download/aid-780/sec1-v2.pdf, chapter 4.1.6.

    pyca/cryptography has no public key recovery API, so this pure-python
    implementation is the primary path there. It is also the reference against
    which the libsecp256k1 backend is checked.
    """
    if recid < 0 or recid > 3:
        raise ValueError(
            'recid is {}, but should be 0 <= recid <= 3'.format(recid))
    order = CURVE_ORDER
    # extract r,s from signature
    r, s = decode_string(sig_string, order)
    if not (0 < r < order) or not (0 < s < order):
        raise InvalidECPointException('signature values out of range')
    # 1.1
    x = r + (recid // 2) * order
    # 1.3
    alpha = (x * x * x + CURVE_A * x + CURVE_B) % CURVE_P
    beta = modular_sqrt(alpha, CURVE_P)
    y = beta if (beta - recid) % 2 == 0 else CURVE_P - beta
    # 1.4 the constructor checks that nR is at infinity
    try:
        R = Point(x, y)
    except Exception:
        raise InvalidECPointException()
    # 1.5 compute e from message:
    e = string_to_number(msg_hash)
    minus_e = -e % order
    # 1.6 compute Q = r^-1 (sR - eG)
    inv_r = inverse_mod(r, order)
    try:
        Q = inv_r * (s * R + minus_e * GENERATOR)
    except Exception:
        raise InvalidECPointException()
    if Q.is_at_infinity():
        raise InvalidECPointException('recovered point at infinity')
    return point_to_ser(Q, compressed=False)


def is_secret_within_curve_range(secret) -> bool:
    if isinstance(secret, (bytes, bytearray)):
        secret = string_to_number(secret)
    return 0 < secret < CURVE_ORDER
