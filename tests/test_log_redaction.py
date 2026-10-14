# -*- coding: utf-8 -*-
"""Regression tests: secrets must never reach logs or stdout.

Before 0.18.5 the library leaked key material three ways:

  * `print()` of the raw private-key import APDU (and of MuSig2 nonces),
    unconditionally, to stdout -- no log level could silence it;
  * the BIP32 `xprv` logged at INFO;
  * APDU logging driven by a hand-maintained deny-list that covered only the
    *command* direction, so decrypted responses carrying exported masterseeds
    were written verbatim at DEBUG.

These tests are the guard, in the same spirit as
test_ec_backend.test_ecdsa_is_not_imported for issue #8.
"""

import io
import logging
import os
import re
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip import CardConnector as cc_mod
from pysatochip.CardConnector import _LOGGABLE_INS, _redact_apdu, _redact_response
from pysatochip.JCconstants import JCconstants

SECRET = list(bytes.fromhex(
    'c0ffee0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d'))
SECRET_HEX_RE = re.compile(r'c0\s*ff\s*ee\s*01', re.IGNORECASE)


class TestRedactionHelpers(unittest.TestCase):

    def test_secret_bearing_instructions_are_masked(self):
        """Every instruction that can carry key material must be masked. These
        are exactly the ones the old deny-list forgot."""
        for ins in (JCconstants.INS_IMPORT_KEY,          # raw private key
                    JCconstants.INS_BIP32_IMPORT_SEED,
                    JCconstants.INS_BIP32_GET_EXTENDED_KEY,  # can return xprv
                    JCconstants.INS_VERIFY_PIN,
                    JCconstants.INS_CREATE_PIN,
                    JCconstants.INS_CHANGE_PIN,
                    JCconstants.INS_UNBLOCK_PIN,
                    JCconstants.INS_SETUP,
                    JCconstants.INS_SET_2FA_KEY,
                    0xA1,                                # SeedKeeper ImportSecret
                    0xA2,                                # SeedKeeper ExportSecret
                    0xAC,                                # ImportEncryptedSecret
                    0xB7):                               # Satocash import_proof
            with self.subTest(ins=hex(ins)):
                apdu = [0xB0, ins, 0x00, 0x00, len(SECRET)] + SECRET
                self.assertNotRegex(_redact_apdu(apdu), SECRET_HEX_RE)
                self.assertNotRegex(_redact_response(SECRET, ins), SECRET_HEX_RE)

    def test_unknown_instruction_is_masked(self):
        """Deny-by-default: an instruction nobody has classified yet must not
        start logging its body just because it was added."""
        apdu = [0xB0, 0xEE, 0x00, 0x00, len(SECRET)] + SECRET
        self.assertNotRegex(_redact_apdu(apdu), SECRET_HEX_RE)
        self.assertNotRegex(_redact_response(SECRET, 0xEE), SECRET_HEX_RE)

    def test_response_with_unknown_ins_is_masked(self):
        """card_decrypt_secure_channel defaults ins=None for external callers."""
        self.assertNotRegex(_redact_response(SECRET, None), SECRET_HEX_RE)

    def test_header_is_still_visible_for_masked_apdu(self):
        """Masking must stay useful for debugging: the 5-byte header shows."""
        apdu = [0xB0, JCconstants.INS_IMPORT_KEY, 0x01, 0x02, len(SECRET)] + SECRET
        self.assertTrue(_redact_apdu(apdu).startswith("B0 32 01 02"))

    def test_loggable_instructions_are_rendered_in_full(self):
        for ins in (JCconstants.INS_GET_STATUS, JCconstants.INS_INIT_SECURE_CHANNEL):
            with self.subTest(ins=hex(ins)):
                apdu = [0xB0, ins, 0x00, 0x00, 0x02, 0xAB, 0xCD]
                self.assertIn("AB CD", _redact_apdu(apdu))

    def test_no_secret_bearing_instruction_is_on_the_allow_list(self):
        for ins in (JCconstants.INS_IMPORT_KEY, JCconstants.INS_BIP32_IMPORT_SEED,
                    JCconstants.INS_VERIFY_PIN, JCconstants.INS_BIP32_GET_EXTENDED_KEY,
                    0xA1, 0xA2, 0xAC):
            self.assertNotIn(ins, _LOGGABLE_INS, "ins %s must not be loggable" % hex(ins))


class TestNoSecretsInLogs(unittest.TestCase):
    """Drive the real logging paths at DEBUG and assert the secret is absent."""

    def setUp(self):
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setLevel(logging.DEBUG)
        self.logger = logging.getLogger('pysatochip.CardConnector')
        self.logger.addHandler(self.handler)
        self._saved_level = self.logger.level
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self._saved_level)

    def test_import_key_apdu_is_not_logged(self):
        apdu = [0xB0, JCconstants.INS_IMPORT_KEY, 0x00, 0x00, len(SECRET)] + SECRET
        cc_mod.logger.debug(f"Plaintext C-APDU: {_redact_apdu(apdu)}")
        self.assertNotRegex(self.stream.getvalue(), SECRET_HEX_RE)

    def test_exported_secret_response_is_not_logged(self):
        cc_mod.logger.debug(f"Plaintext R-APDU: {_redact_response(SECRET, 0xA2)}")
        self.assertNotRegex(self.stream.getvalue(), SECRET_HEX_RE)


class TestNoStdoutWrites(unittest.TestCase):
    """A library must not write to stdout at all: no log level can silence it."""

    LIBRARY_MODULES = [
        'CardConnector.py', 'CardDataParser.py', 'SecureChannel.py', 'TxParser.py',
        'util.py', 'ecc.py', 'ec_math.py', 'ec_backend.py', 'aes_backend.py',
        'certificate_validator.py', 'Satochip2FA.py', 'electrum_mnemonic.py',
    ]

    def test_no_print_statements_in_library_modules(self):
        pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'pysatochip')
        offenders = []
        for name in self.LIBRARY_MODULES:
            path = os.path.join(pkg, name)
            if not os.path.exists(path):
                continue
            with io.open(path, encoding='utf-8') as fd:
                for lineno, line in enumerate(fd, 1):
                    if re.match(r'^\s*print\s*\(', line):
                        offenders.append("%s:%d: %s" % (name, lineno, line.strip()))
        self.assertEqual(offenders, [], "library modules must not print():\n" +
                         "\n".join(offenders))

    def test_importing_pysatochip_is_silent(self):
        """Importing the package must not emit anything on stdout."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            import importlib
            import pysatochip.CardConnector
            importlib.reload(pysatochip.CardConnector)
        self.assertEqual(buf.getvalue(), "")


class TestNoImportTimeLoggingConfig(unittest.TestCase):
    """Library modules must not configure logging on import -- that overrides
    whatever the consuming application (e.g. Electrum) set up."""

    def test_no_module_level_setlevel_or_basicconfig(self):
        pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'pysatochip')
        offenders = []
        for name in sorted(os.listdir(pkg)):
            if not name.endswith('.py') or name == 'satochip_cli.py':
                continue
            with io.open(os.path.join(pkg, name), encoding='utf-8') as fd:
                for lineno, line in enumerate(fd, 1):
                    if re.match(r'^(logger\.setLevel|logging\.basicConfig)', line):
                        offenders.append("%s:%d: %s" % (name, lineno, line.strip()))
        self.assertEqual(offenders, [], "import-time logging config:\n" +
                         "\n".join(offenders))


class TestLogLevelConfiguration(unittest.TestCase):
    """The level belongs to the application, not to the library.

    Before 0.18.5 every constructor called `logger.setLevel(loglevel)` on its
    *module* logger, with a default of WARNING. Constructing any object
    therefore silently overrode whatever the host application had configured,
    and a second instance retroactively changed the first. Levels are now set
    only when the caller explicitly asks, and on the package logger so they
    cascade."""

    PKG = 'pysatochip'
    SUBS = ('pysatochip.CardConnector', 'pysatochip.CardDataParser',
            'pysatochip.SecureChannel', 'pysatochip.certificate_validator',
            'pysatochip.ec_backend', 'pysatochip.aes_backend')

    def setUp(self):
        self._saved = {n: logging.getLogger(n).level
                       for n in (self.PKG,) + self.SUBS}

    def tearDown(self):
        for name, level in self._saved.items():
            logging.getLogger(name).setLevel(level)

    def test_module_loggers_stay_at_notset(self):
        """A module logger with its own level would block the cascade."""
        for name in self.SUBS:
            with self.subTest(logger=name):
                self.assertEqual(logging.getLogger(name).level, logging.NOTSET)

    def test_set_log_level_cascades_to_every_module(self):
        import pysatochip
        for level in (logging.DEBUG, logging.ERROR):
            pysatochip.set_log_level(level)
            for name in self.SUBS:
                with self.subTest(logger=name, level=level):
                    self.assertEqual(
                        logging.getLogger(name).getEffectiveLevel(), level)

    def test_default_construction_does_not_touch_the_level(self):
        """The regression: an application's explicit choice must survive."""
        import pysatochip
        from pysatochip.CardDataParser import CardDataParser
        pysatochip.set_log_level(logging.DEBUG)
        CardDataParser()
        self.assertEqual(
            logging.getLogger('pysatochip.CardDataParser').getEffectiveLevel(),
            logging.DEBUG)

    def test_second_instance_does_not_clobber_the_first(self):
        from pysatochip.CardDataParser import CardDataParser
        CardDataParser(logging.DEBUG)
        CardDataParser()
        self.assertEqual(
            logging.getLogger('pysatochip.CardDataParser').getEffectiveLevel(),
            logging.DEBUG)

    def test_explicit_loglevel_is_still_honoured(self):
        """Backward compatibility: the constructor argument still works."""
        import pysatochip
        from pysatochip.CardDataParser import CardDataParser
        pysatochip.set_log_level(logging.WARNING)
        CardDataParser(logging.DEBUG)
        self.assertEqual(
            logging.getLogger('pysatochip.CardDataParser').getEffectiveLevel(),
            logging.DEBUG)

    def test_package_has_a_null_handler(self):
        """Without one, library records fall through to logging.lastResort
        and print to stderr in applications that configure no logging."""
        import pysatochip  # importing the package is what installs the handler
        handlers = logging.getLogger(pysatochip.__name__).handlers
        self.assertTrue(any(isinstance(h, logging.NullHandler) for h in handlers),
                        "pysatochip package logger needs a NullHandler")


if __name__ == "__main__":
    unittest.main(verbosity=2)
