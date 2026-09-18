# -*- coding: utf-8 -*-
"""Reference BIP340 (schnorr) and BIP341 (taproot tweak) implementation.

This is a *host-side reference*, written to be obviously-correct rather than
fast or constant time: it is the yardstick the Satochip applet is measured
against by tests/test_bip340.py (offline, official vectors) and by
test_satochip_taproot.py (on-card, compares the card output to this module).

It is deliberately built on pysatochip.ec_math only, so it pulls in no new
dependency: `cryptography` does not expose schnorr/x-only operations, and
libsecp256k1 bindings (coincurve, embit) are optional in this project.

The code below follows the pseudo-code of the BIPs line by line:
  https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
  https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

Do not import this from pysatochip/: it handles private keys (schnorr_sign,
taproot_tweak_seckey) with pure-python, non-constant-time arithmetic, which is
fine for test vectors but must never touch a user key.
"""

import hashlib
import os
import sys
from typing import Tuple, Union

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip import ec_math as m

P = m.CURVE_P
N = m.CURVE_ORDER
G = m.GENERATOR


class InvalidBIP340Error(Exception):
    """A key/signature/tweak that BIP340 or BIP341 requires us to reject."""


#
# helpers
#

def tagged_hash(tag: Union[str, bytes], msg: bytes) -> bytes:
    """BIP340 hash_tag(msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    if isinstance(tag, str):
        tag = tag.encode('utf-8')
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + bytes(msg)).digest()


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, 'big')


def has_even_y(point: m.Point) -> bool:
    if point.is_at_infinity():
        raise InvalidBIP340Error('has_even_y() of the point at infinity')
    return point.y % 2 == 0


def lift_x(x: Union[bytes, int]) -> m.Point:
    """BIP340 lift_x: the even-y point with the given x coordinate.

    Raises InvalidBIP340Error if x >= p or x is not on the curve -- both are
    'verification fails' cases in the official vectors, not exceptions to
    swallow silently.
    """
    if isinstance(x, (bytes, bytearray)):
        if len(x) != 32:
            raise InvalidBIP340Error(
                'x-only key must be 32 bytes, not %d' % len(x))
        x = int.from_bytes(bytes(x), 'big')
    if not 0 <= x < P:
        raise InvalidBIP340Error('x coordinate is not a field element')
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise InvalidBIP340Error('x coordinate is not on the curve')
    return m.Point(x, y if y % 2 == 0 else P - y)


def x_only(pubkey: Union[bytes, m.Point]) -> bytes:
    """The 32-byte x coordinate of a point, from any of the usual encodings.

    Accepts a Point, or a 32-byte x-only / 33-byte compressed / 65-byte
    uncompressed serialization -- the card returns the uncompressed form.
    """
    if isinstance(pubkey, m.Point):
        if pubkey.is_at_infinity():
            raise InvalidBIP340Error('x_only() of the point at infinity')
        return bytes_from_int(pubkey.x)
    pubkey = bytes(pubkey)
    if len(pubkey) == 32:
        return pubkey
    if len(pubkey) in (33, 65):
        return bytes(m.ser_to_point_obj(pubkey).x.to_bytes(32, 'big'))
    raise InvalidBIP340Error('unexpected pubkey length %d' % len(pubkey))


def pubkey_gen(seckey: bytes) -> bytes:
    """x-only public key for a private key (BIP340 pubkey_gen)."""
    d0 = int.from_bytes(bytes(seckey), 'big')
    if not 1 <= d0 <= N - 1:
        raise InvalidBIP340Error('private key out of range')
    return x_only(G * d0)


#
# BIP340 signing / verification
#

def schnorr_sign(seckey: bytes, msg: bytes, aux_rand: bytes) -> bytes:
    """BIP340 default signing, for reproducing the official test vectors.

    The Satochip draws aux_rand on-card (randomData.generateData), so card
    signatures are not reproducible; this is only used to check the reference
    against the vectors, and as a known-good signature in negative tests.
    """
    d0 = int.from_bytes(bytes(seckey), 'big')
    if not 1 <= d0 <= N - 1:
        raise InvalidBIP340Error('private key out of range')
    if len(aux_rand) != 32:
        raise InvalidBIP340Error('aux_rand must be 32 bytes')
    point_p = G * d0
    d = d0 if has_even_y(point_p) else N - d0
    t = d ^ int.from_bytes(tagged_hash('BIP0340/aux', aux_rand), 'big')
    rand = tagged_hash(
        'BIP0340/nonce', bytes_from_int(t) + x_only(point_p) + bytes(msg))
    k0 = int.from_bytes(rand, 'big') % N
    if k0 == 0:
        raise InvalidBIP340Error('failure. this happens only with negligible '
                                 'probability')
    point_r = G * k0
    k = k0 if has_even_y(point_r) else N - k0
    e = int.from_bytes(
        tagged_hash('BIP0340/challenge',
                    x_only(point_r) + x_only(point_p) + bytes(msg)),
        'big') % N
    sig = x_only(point_r) + bytes_from_int((k + e * d) % N)
    if not schnorr_verify(x_only(point_p), msg, sig):
        raise InvalidBIP340Error('sanity check failed: produced an invalid '
                                 'signature')
    return sig


def schnorr_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """BIP340 verification. Returns False on every malformed input.

    Strictness matters here, and the official vectors 5-14 are exactly the
    malformed cases: x >= p, point not on the curve, r >= p, s >= n, odd y(R),
    and sG - eP at infinity. A verifier that is lax about any of those would
    happily accept a broken card signature, so this returns False rather than
    raising.
    """
    pubkey = bytes(pubkey)
    sig = bytes(sig)
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    try:
        point_p = lift_x(pubkey)
    except InvalidBIP340Error:
        return False
    r = int.from_bytes(sig[0:32], 'big')
    s = int.from_bytes(sig[32:64], 'big')
    if r >= P or s >= N:
        return False
    e = int.from_bytes(
        tagged_hash('BIP0340/challenge', sig[0:32] + pubkey + bytes(msg)),
        'big') % N
    point_r = (G * s) + (point_p * (N - e))
    if point_r.is_at_infinity():
        return False
    if not has_even_y(point_r):
        return False
    return point_r.x == r


#
# BIP341 taproot tweak
#

def taproot_tweak_pubkey(internal_pubkey: bytes,
                         merkle_root: bytes = b'') -> Tuple[int, bytes]:
    """BIP341 taproot_tweak_pubkey(pubkey, h) -> (parity of Q, x-only Q).

    `merkle_root` is h: the 32-byte taproot merkle root, or the EMPTY byte
    string when the output commits to no script tree (key-path-only spending,
    as in BIP86). That distinction is the whole point of this function: the
    tagged hash is computed over the concatenation x(P) || h, so an empty h
    hashes 32 bytes and a merkle root hashes 64. Passing 32 zero bytes instead
    of b'' is a *different* tweak, and yields an unspendable BIP86 output.
    """
    merkle_root = bytes(merkle_root)
    if len(merkle_root) not in (0, 32):
        raise InvalidBIP340Error(
            'merkle root must be 32 bytes or empty, not %d' % len(merkle_root))
    pubkey = x_only(internal_pubkey)
    t = int.from_bytes(tagged_hash('TapTweak', pubkey + merkle_root), 'big')
    if t >= N:
        raise InvalidBIP340Error('tweak is not a valid scalar')
    point_q = lift_x(pubkey) + (G * t)
    return (0 if has_even_y(point_q) else 1, x_only(point_q))


def taproot_tweak_seckey(seckey: bytes, merkle_root: bytes = b'') -> bytes:
    """BIP341 taproot_tweak_seckey(seckey0, h). See taproot_tweak_pubkey."""
    merkle_root = bytes(merkle_root)
    if len(merkle_root) not in (0, 32):
        raise InvalidBIP340Error(
            'merkle root must be 32 bytes or empty, not %d' % len(merkle_root))
    d0 = int.from_bytes(bytes(seckey), 'big')
    if not 1 <= d0 <= N - 1:
        raise InvalidBIP340Error('private key out of range')
    point_p = G * d0
    d = d0 if has_even_y(point_p) else N - d0
    t = int.from_bytes(
        tagged_hash('TapTweak', x_only(point_p) + merkle_root), 'big')
    if t >= N:
        raise InvalidBIP340Error('tweak is not a valid scalar')
    return bytes_from_int((d + t) % N)


def legacy_xor_tweak_seckey(seckey: bytes, merkle_root: bytes) -> bytes:
    """The NON-BIP341 tweak of Satochip applet <= v0.15-0.1, for regression use.

    That version hashed the 32-byte XOR of x(P) and h instead of their
    concatenation, so t = H(x(P) XOR h). It coincides with BIP341 only when h
    is all-zero (which is why key-path-only/BIP86 keys survived the fix), and
    is reproduced here so a test can assert the two differ for a non-zero h.
    """
    merkle_root = bytes(merkle_root)
    if len(merkle_root) != 32:
        raise InvalidBIP340Error('legacy tweak needs a 32-byte h')
    d0 = int.from_bytes(bytes(seckey), 'big')
    point_p = G * d0
    d = d0 if has_even_y(point_p) else N - d0
    xored = bytes(a ^ b for a, b in zip(x_only(point_p), merkle_root))
    t = int.from_bytes(tagged_hash('TapTweak', xored), 'big')
    if t >= N:
        raise InvalidBIP340Error('tweak is not a valid scalar')
    return bytes_from_int((d + t) % N)
