# -*- coding: utf-8 -*-
"""Official BIP340 / BIP341 / BIP86 test vectors, transcribed verbatim.

Generated from the upstream files, do not edit by hand:
  bip-0340/test-vectors.csv          -> BIP340_VECTORS
  bip-0341/wallet-test-vectors.json  -> BIP341_TWEAK_VECTORS
  bip-0086.mediawiki (Test vectors)  -> BIP86_SEED / BIP86_KEYS

These pin the Satochip against the standard rather than against itself: a
self-consistent-but-wrong tweak or nonce derivation would pass a round-trip
test and still produce coins nobody can spend.

The private keys here are published test values. Never use them on a device
holding funds.
"""

# index, secret key, public key, aux_rand, message, signature, result, comment
# An empty secret key means the vector is verification-only.
BIP340_VECTORS = [
    dict(
        index=0,
        seckey="0000000000000000000000000000000000000000000000000000000000000003",
        pubkey="f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        aux_rand="0000000000000000000000000000000000000000000000000000000000000000",
        msg="0000000000000000000000000000000000000000000000000000000000000000",
        sig="e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
        "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
        result=True,
        comment="",
    ),
    dict(
        index=1,
        seckey="b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="0000000000000000000000000000000000000000000000000000000000000001",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de3341"
        "8906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
        result=True,
        comment="",
    ),
    dict(
        index=2,
        seckey="c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
        pubkey="dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
        aux_rand="c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
        msg="7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
        sig="5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1b"
        "ab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
        result=True,
        comment="",
    ),
    dict(
        index=3,
        seckey="0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
        pubkey="25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        aux_rand="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        msg="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        sig="7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec"
        "97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
        result=True,
        comment="test fails if msg is reduced modulo p or n",
    ),
    dict(
        index=4,
        seckey="",
        pubkey="d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9",
        aux_rand="",
        msg="4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703",
        sig="00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63"
        "76afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4",
        result=True,
        comment="",
    ),
    dict(
        index=5,
        seckey="",
        pubkey="eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769"
        "69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result=False,
        comment="public key not on the curve",
    ),
    dict(
        index=6,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"
        "3cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2",
        result=False,
        comment="has_even_y(R) is false",
    ),
    dict(
        index=7,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f"
        "28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd",
        result=False,
        comment="negated message",
    ),
    dict(
        index=8,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769"
        "961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6",
        result=False,
        comment="negated s value",
    ),
    dict(
        index=9,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="0000000000000000000000000000000000000000000000000000000000000000"
        "123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051",
        result=False,
        comment="sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0",
    ),
    dict(
        index=10,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="0000000000000000000000000000000000000000000000000000000000000001"
        "7615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197",
        result=False,
        comment="sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1",
    ),
    dict(
        index=11,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d"
        "69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result=False,
        comment="sig[0:32] is not an X coordinate on the curve",
    ),
    dict(
        index=12,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        "69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result=False,
        comment="sig[0:32] is equal to field size",
    ),
    dict(
        index=13,
        seckey="",
        pubkey="dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769"
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        result=False,
        comment="sig[32:64] is equal to curve order",
    ),
    dict(
        index=14,
        seckey="",
        pubkey="fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
        aux_rand="",
        msg="243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
        sig="6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769"
        "69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
        result=False,
        comment="public key is not a valid X coordinate because it exceeds the field size",
    ),
    dict(
        index=15,
        seckey="0340034003400340034003400340034003400340034003400340034003400340",
        pubkey="778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
        aux_rand="0000000000000000000000000000000000000000000000000000000000000000",
        msg="",
        sig="71535db165ecd9fbbc046e5ffaea61186bb6ad436732fccc25291a55895464cf"
        "6069ce26bf03466228f19a3a62db8a649f2d560fac652827d1af0574e427ab63",
        result=True,
        comment="message of size 0 (added 2022-12)",
    ),
    dict(
        index=16,
        seckey="0340034003400340034003400340034003400340034003400340034003400340",
        pubkey="778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
        aux_rand="0000000000000000000000000000000000000000000000000000000000000000",
        msg="11",
        sig="08a20a0afef64124649232e0693c583ab1b9934ae63b4c3511f3ae1134c6a303"
        "ea3173bfea6683bd101fa5aa5dbc1996fe7cacfc5a577d33ec14564cec2bacbf",
        result=True,
        comment="message of size 1 (added 2022-12)",
    ),
    dict(
        index=17,
        seckey="0340034003400340034003400340034003400340034003400340034003400340",
        pubkey="778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
        aux_rand="0000000000000000000000000000000000000000000000000000000000000000",
        msg="0102030405060708090a0b0c0d0e0f1011",
        sig="5130f39a4059b43bc7cac09a19ece52b5d8699d1a71e3c52da9afdb6b50ac370"
        "c4a482b77bf960f8681540e25b6771ece1e5a37fd80e5a51897c5566a97ea5a5",
        result=True,
        comment="message of size 17 (added 2022-12)",
    ),
    dict(
        index=18,
        seckey="0340034003400340034003400340034003400340034003400340034003400340",
        pubkey="778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
        aux_rand="0000000000000000000000000000000000000000000000000000000000000000",
        msg="9999999999999999999999999999999999999999999999999999999999999999"
        "9999999999999999999999999999999999999999999999999999999999999999"
        "9999999999999999999999999999999999999999999999999999999999999999"
        "99999999",
        sig="403b12b0d8555a344175ea7ec746566303321e5dbfa8be6f091635163eca79a8"
        "585ed3e3170807e7c03b720fc54c7b23897fcba0e9d0b4a06894cfd249f22367",
        result=True,
        comment="message of size 100 (added 2022-12)",
    ),
]

# internal pubkey, merkle root h ("" = commits to no script tree), expected
# tweak t and expected tweaked (output) pubkey, all x-only.
BIP341_TWEAK_VECTORS = [
    dict(
        internal_pubkey="d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
        merkle_root="",
        tweak="b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
        tweaked_pubkey="53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        script_pubkey="512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dd"
        "a343",
    ),
    dict(
        internal_pubkey="187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
        merkle_root="5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
        tweak="cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
        tweaked_pubkey="147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        script_pubkey="5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f"
        "3ea3",
    ),
    dict(
        internal_pubkey="93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
        merkle_root="c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
        tweak="6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
        tweaked_pubkey="e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        script_pubkey="5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5"
        "450e",
    ),
    dict(
        internal_pubkey="ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
        merkle_root="6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
        tweak="9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
        tweaked_pubkey="712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        script_pubkey="5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b1"
        "7df5",
    ),
    dict(
        internal_pubkey="f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
        merkle_root="ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
        tweak="639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
        tweaked_pubkey="77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        script_pubkey="512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050a"
        "b220",
    ),
    dict(
        internal_pubkey="e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
        merkle_root="ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
        tweak="b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
        tweaked_pubkey="91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        script_pubkey="512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc2178"
        "3605",
    ),
    dict(
        internal_pubkey="55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
        merkle_root="2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
        tweak="6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
        tweaked_pubkey="75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        script_pubkey="512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907"
        "b831",
    ),
]

# BIP86 test vectors: mnemonic "abandon abandon abandon abandon abandon abandon
# abandon abandon abandon abandon abandon about" with an empty passphrase.
# These exercise the key-path-only (no script tree) tweak end to end: the card
# derives the internal key from the seed, then tweaks it with an EMPTY h.
BIP86_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
BIP86_SEED = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)
BIP86_KEYS = [
    dict(
        path="m/86'/0'/0'/0/0",
        internal_key="cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        output_key="a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
        script_pubkey="5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
        address="bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    ),
    dict(
        path="m/86'/0'/0'/0/1",
        internal_key="83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
        output_key="a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
        script_pubkey="5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
        address="bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    ),
    dict(
        path="m/86'/0'/0'/1/0",
        internal_key="399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
        output_key="882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
        script_pubkey="5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
        address="bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
    ),
]

# Test-only private key used by the on-card taproot tests (keyslot import).
# Arbitrary value, chosen once so card runs are reproducible.
CARD_TEST_PRIVKEY = (
    "0f0e0d0c0b0a09080706050403020100f0e1d2c3b4a596879a8b7c6d5e4f3021"
)
