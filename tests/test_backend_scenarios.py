# -*- coding: utf-8 -*-
"""End-to-end checks of each deployment environment (issue #8).

Backend selection happens at import time, so each scenario runs in its own
subprocess with the relevant packages blocked. The scenarios that matter:

* desktop            -- cryptography present, the default
* seedsigner-os      -- embit + pycryptodomex only; no cryptography, no
                        pyOpenSSL. This is what actually ships on the Raspberry
                        Pi images (BR2_PACKAGE_PYTHON_EMBIT=y,
                        BR2_PACKAGE_PYTHON_PYCRYPTODOMEX=y, and notably no
                        BR2_PACKAGE_PYTHON_CRYPTOGRAPHY).
* no backend at all  -- private-key operations must fail loudly rather than
                        quietly using something vulnerable
"""

import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

def run_scenario(blocked, body):
    """Run `body` in a subprocess with `blocked` packages unimportable."""
    script = """
import sys
sys.path.insert(0, {tests!r})
sys.path.insert(0, {root!r})
import _blocker
_blocker.block(*{blocked!r})
import vectors as v
from pysatochip import ec_backend as b
{body}
""".format(tests=HERE, root=ROOT, blocked=list(blocked), body=body)
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True, cwd=ROOT)
    return proc


class ScenarioTestCase(unittest.TestCase):

    def assert_scenario(self, blocked, body, msg=""):
        proc = run_scenario(blocked, body)
        self.assertEqual(
            proc.returncode, 0,
            "%s\nstdout:\n%s\nstderr:\n%s" % (msg, proc.stdout, proc.stderr))
        return proc.stdout


class TestDesktopScenario(ScenarioTestCase):

    def test_prefers_cryptography(self):
        self.assert_scenario([], """
assert b.HAS_CRYPTOGRAPHY, "cryptography should be installed for this test"
assert b.BACKEND == "cryptography", b.BACKEND
assert b.ecdh_shared_x(v.PRIV_A, v.PUB_B_UNCOMPRESSED) == v.ECDH_SHARED_X
assert b.privkey_to_pubkey(v.PRIV_A, False) == v.PUB_A_UNCOMPRESSED
""")


class TestSeedsignerScenario(ScenarioTestCase):
    """No cryptography and no pyOpenSSL, exactly like the shipped Pi images."""

    BLOCKED = ["cryptography", "OpenSSL", "ecdsa"]

    def setUp(self):
        proc = run_scenario(self.BLOCKED, "assert b.HAS_EMBIT\n")
        if proc.returncode != 0:
            self.skipTest("embit not installed; install pysatochip[embedded]")

    def test_falls_back_to_libsecp256k1(self):
        self.assert_scenario(self.BLOCKED, """
assert not b.HAS_CRYPTOGRAPHY
assert b.BACKEND == "embit", b.BACKEND
""")

    def test_uses_libsecp256k1_not_pure_python(self):
        """embit.util.secp256k1 silently falls back to embit.util.py_secp256k1,
        which is NOT constant time. We must be bound to the ctypes module."""
        self.assert_scenario(self.BLOCKED, """
assert b._secp.__name__.endswith("ctypes_secp256k1"), b._secp.__name__
assert hasattr(b._secp, "_secp"), "expected the loaded ctypes library handle"
import embit.util.py_secp256k1 as pure
assert b._secp is not pure
""")

    def test_card_operations_work(self):
        self.assert_scenario(self.BLOCKED, """
assert b.ecdh_shared_x(v.PRIV_A, v.PUB_B_UNCOMPRESSED) == v.ECDH_SHARED_X
assert b.privkey_to_pubkey(v.PRIV_A, False) == v.PUB_A_UNCOMPRESSED
assert b.recover_pubkey(v.SIG_STRING, v.RECID_FOR_PUB_A, v.DIGEST) == v.PUB_A_UNCOMPRESSED
assert b.verify_digest(v.PUB_A_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST)
assert b.verify_digest(v.PUB_A_UNCOMPRESSED, v.SIG_DER_HIGHS, v.DIGEST)
assert b.verify_message(v.PUB_A_UNCOMPRESSED, v.SHA512_MSG, v.SHA512_SIG_DER, "sha512")
r, s = b.sign_digest(v.PRIV_A, v.DIGEST)
from pysatochip import ec_math
assert b.verify_digest(v.PUB_A_UNCOMPRESSED, ec_math.encode_der(r, s), v.DIGEST)
""")

    def test_secure_channel_works(self):
        self.assert_scenario(self.BLOCKED, """
from pysatochip.SecureChannel import SecureChannel
card_priv, card_pub = b.generate_keypair()
sc = SecureChannel()
sc.initiate_secure_channel(card_pub)
assert sc.shared_key == b.ecdh_shared_x(card_priv, sc.sc_pubkey_serialized)
iv, ct, mac = sc.encrypt_secure_channel(b"hello card")
assert bytes(sc.decrypt_secure_channel(iv, ct)) == b"hello card"
""")

    def test_card_connector_imports(self):
        self.assert_scenario(self.BLOCKED, """
from pysatochip.CardConnector import CardConnector
from pysatochip.certificate_validator import HAS_OPENSSL
assert HAS_OPENSSL is False
from pysatochip.ecc import ECPrivkey, ECPubkey
pk = ECPrivkey(v.PRIV_A)
assert pk.get_public_key_bytes(True) == v.PUB_A_COMPRESSED
ECPubkey(v.PUB_A_UNCOMPRESSED).verify_message_for_address(v.SIG65_COMPRESSED, v.MESSAGE)
""")

    def test_p384_certificate_leg_uses_pycryptodomex(self):
        self.assert_scenario(self.BLOCKED, """
import base64, re, os
from Cryptodome.Util.asn1 import DerSequence, DerBitString
assert not b.HAS_CRYPTOGRAPHY and b.HAS_PYCRYPTODOMEX
def _der(p):
    txt = open(p).read()
    m = re.search(r"-----BEGIN CERTIFICATE-----\\s*(.*?)\\s*-----END CERTIFICATE-----", txt, re.S)
    return base64.b64decode(''.join(m.group(1).split()))
def parts(p):
    s = DerSequence(); s.decode(_der(p))
    bs = DerBitString(); bs.decode(s[2]); return s[0], bs.value
def pub(p):
    s = DerSequence(); s.decode(_der(p)); t = DerSequence(); t.decode(s[0])
    k = DerSequence(); k.decode(t[6]); bs = DerBitString(); bs.decode(k[1]); return bs.value
d = os.path.join("pysatochip", "cert")
ca = pub(os.path.join(d, "ca.cert"))
for dev in ("satochip", "seedkeeper", "satodime"):
    tbs, sig = parts(os.path.join(d, "subca-%s.cert" % dev))
    assert b.verify_p384(ca, tbs, sig, "sha512"), dev
""")

    def test_ecdsa_is_never_imported(self):
        self.assert_scenario(self.BLOCKED, """
import pysatochip.CardConnector, pysatochip.ecc, pysatochip.SecureChannel
import pysatochip.certificate_validator
assert "ecdsa" not in sys.modules
""")


class TestNoBackendScenario(ScenarioTestCase):
    """Neither hardened backend available: fail loudly, never silently."""

    BLOCKED = ["cryptography", "embit", "ecdsa"]

    def test_backend_is_none(self):
        self.assert_scenario(self.BLOCKED, """
assert b.BACKEND is None
assert b.available_backends() == ()
""")

    def test_private_key_operations_raise(self):
        self.assert_scenario(self.BLOCKED, """
for call in (
    lambda: b.generate_keypair(),
    lambda: b.privkey_to_pubkey(v.PRIV_A),
    lambda: b.ecdh_shared_x(v.PRIV_A, v.PUB_B_UNCOMPRESSED),
    lambda: b.sign_digest(v.PRIV_A, v.DIGEST),
):
    try:
        call()
        raise AssertionError("expected NoECBackendError")
    except b.NoECBackendError as ex:
        assert "cryptography" in str(ex) and "embit" in str(ex), str(ex)
""")

    def test_verification_and_recovery_still_work(self):
        """These involve no secret, so they must not be disabled."""
        self.assert_scenario(self.BLOCKED, """
assert b.verify_digest(v.PUB_A_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST)
assert b.verify_digest(v.PUB_A_UNCOMPRESSED, v.SIG_DER_HIGHS, v.DIGEST)
assert not b.verify_digest(v.PUB_B_UNCOMPRESSED, v.SIG_DER_LOWS, v.DIGEST)
assert b.recover_pubkey(v.SIG_STRING, v.RECID_FOR_PUB_A, v.DIGEST) == v.PUB_A_UNCOMPRESSED
""")

    def test_p384_still_works_via_pycryptodomex(self):
        self.assert_scenario(self.BLOCKED, """
assert b.HAS_PYCRYPTODOMEX
""")


if __name__ == "__main__":
    unittest.main(verbosity=2)
