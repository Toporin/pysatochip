# -*- coding: utf-8 -*-
"""Golden secp256k1 vectors.

Captured from the pre-0.18.0 `ecdsa`-based implementation (see issue #8) with
`_gen_vectors.py`, and frozen here. Any backend must reproduce these byte for
byte -- in particular ECDH_SHARED_X, which fixes the card secure-channel wire
format: if that changes, every Satochip/SeedKeeper/Satodime session breaks.

The private keys below are test-only values. Never use them on a real device.
"""

# fixed keypairs
PRIV_A = bytes.fromhex("c0ffee00112233445566778899aabbccddeeff0102030405060708090a0b0c0d")
PRIV_B = bytes.fromhex("1234567890abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978")

PUB_A_UNCOMPRESSED = bytes.fromhex(
    "046397d8ae2e489f3dfa0c1682e691048eb851c1ae7b6b725d84421f5c359590ca"
    "822d460fb3dba6ffb2c4ff8558de6eb123ea823d34942bb6feaa4d4882a2e2cc"
)
PUB_B_UNCOMPRESSED = bytes.fromhex(
    "04225e0851930f173babdd4f5b77ff86404634b1ed0ef13d421e3709338f4c418e"
    "1cea3065480934f437891853ef67a9e364b511fe874fef31508029a1cc3c7118"
)
PUB_A_COMPRESSED = bytes.fromhex(
    "026397d8ae2e489f3dfa0c1682e691048eb851c1ae7b6b725d84421f5c359590ca"
)
PUB_B_COMPRESSED = bytes.fromhex(
    "02225e0851930f173babdd4f5b77ff86404634b1ed0ef13d421e3709338f4c418e"
)

# ECDH raw x-coordinate shared secret -- the secure-channel wire-format gate
ECDH_SHARED_X = bytes.fromhex(
    "4e16dc8d4916a63231ae00070d3ccd7ce04602128dfe908241a844e71a80584e"
)

# signature over DIGEST by PRIV_A
DIGEST = bytes.fromhex("f258812ba99ba2fdf87d69fa08389e20bfcacc0cefdbce851bb3d461d851af62")
SIG_R = 0xD894335C72B3FB8DD9B44DE4CDB7072BDB9F01420FB4201237C513D2EBB1717B
SIG_S = 0x1438706A4C3ABD816E39FC0E3522F8B3039898DBCCB66850BF0F9CB773F61914

# low-S DER, as produced by the old RFC-6979 signer
SIG_DER_LOWS = bytes.fromhex(
    "3045022100d894335c72b3fb8dd9b44de4cdb7072bdb9f01420fb4201237c513d2ebb1717b"
    "02201438706a4c3abd816e39fc0e3522f8b3039898dbccb66850bf0f9cb773f61914"
)
# same signature with s negated -- valid ECDSA, but rejected by libsecp256k1
# unless normalized first
SIG_DER_HIGHS = bytes.fromhex(
    "3046022100d894335c72b3fb8dd9b44de4cdb7072bdb9f01420fb4201237c513d2ebb1717b"
    "022100ebc78f95b3c5427e91c603f1cadd074bb716440ae29237eb00c2c1d55c40282d"
)
# 64-byte compact (r || s)
SIG_STRING = bytes.fromhex(
    "d894335c72b3fb8dd9b44de4cdb7072bdb9f01420fb4201237c513d2ebb1717b"
    "1438706a4c3abd816e39fc0e3522f8b3039898dbccb66850bf0f9cb773f61914"
)

# pubkey recovery from (SIG_STRING, recid, DIGEST); None == no valid point
RECOVERY = {
    0: bytes.fromhex(
        "04ce4daee89a53f9c55bc1b5768df3109d7300254846a9442e3fdc7a2085900734"
        "850d24c3d8ada2beb8e4cf28a41e3413dab734c7b92132555de060e8774ca20b"
    ),
    1: PUB_A_UNCOMPRESSED,
    2: None,
    3: None,
}
RECID_FOR_PUB_A = 1

# secp256k1 signature over a SHA-512 digest -- the subCA->device certificate
# shape. Exercises the 32-byte hash truncation libsecp256k1 requires.
SHA512_MSG = bytes.fromhex("7462732d63657274696669636174652d62797465732d7374616e642d696e")
SHA512_SIG_DER = bytes.fromhex(
    "3045022100c457ac5db450b5fd32c372622d6e57c24888129a7c95080b79e36ac6fee6eec4"
    "0220536459d43e7181504309fb09fb4d4bcf89cf185dc34df625d09ce1cf12cbd413"
)

# Bitcoin signed message, compressed recid form (sign_message output)
MESSAGE = bytes.fromhex("5361746f636869702074657374206d657373616765")
SIG65_COMPRESSED = bytes.fromhex(
    "1f1ebaa3ab487299fb56aa9a048479ed22273d1e9f4dd9689c6a749e19aacfc7f6"
    "0fb9b92e2fc4196917096fc6e61112b66704a4b2dfa9bbd560dc0cc30a962fc3"
)
