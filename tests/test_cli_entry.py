# -*- coding: utf-8 -*-
"""The CLI must ask Click which command ran, not read sys.argv (B5).

`main()` inferred the device filter and decided whether to open the card from
`sys.argv[1]`. That is the *first argument*, not the command: with any global
option in front of the command it saw the option instead, so

    satochip-cli --verbose util-generate-local-keypair

inferred no device filter and then opened the card and set up a secure channel
for a util- command that needs neither. It now uses `ctx.invoked_subcommand`,
which AliasedGroup resolves to the full command name, so abbreviations work too.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from click.testing import CliRunner

import satochip_cli

CLI_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'satochip_cli.py')


def main_body(src):
    start = src.index('def main(ctx, verbose, devicefilter):')
    end = src.index('@main.command()', start)
    return src[start:end]


class TestNoArgvInspection(unittest.TestCase):

    def test_main_does_not_read_sys_argv(self):
        body = main_body(open(CLI_PATH, encoding='utf-8').read())
        code = re.sub(r'#.*', '', body)          # ignore comments
        self.assertNotIn('sys.argv', code,
                         "main() still infers the command from sys.argv")

    def test_main_uses_the_click_context(self):
        body = main_body(open(CLI_PATH, encoding='utf-8').read())
        self.assertIn('ctx.invoked_subcommand', body)


class TestUtilCommandsDoNotOpenTheCard(unittest.TestCase):
    """util- commands must skip card setup however the options are ordered."""

    def setUp(self):
        self.constructed = []
        self._real = satochip_cli.CardConnector

        def spy(*args, **kwargs):
            self.constructed.append(args)
            raise AssertionError("CardConnector must not be built for a util- command")

        satochip_cli.CardConnector = spy
        self.runner = CliRunner()

    def tearDown(self):
        satochip_cli.CardConnector = self._real

    def test_util_command_skips_card_setup(self):
        result = self.runner.invoke(satochip_cli.main, ['util-generate-local-keypair'])
        self.assertEqual(self.constructed, [], "card was opened for a util- command")
        self.assertEqual(result.exit_code, 0, result.output)

    def test_util_command_skips_card_setup_after_a_global_option(self):
        """The regression: the option used to be mistaken for the command."""
        result = self.runner.invoke(
            satochip_cli.main, ['--verbose', 'util-generate-local-keypair'])
        self.assertEqual(self.constructed, [],
                         "card was opened because --verbose was read as the command")
        self.assertEqual(result.exit_code, 0, result.output)

    def test_abbreviated_util_command_also_skips_card_setup(self):
        """AliasedGroup resolves prefixes; the full name must be what we test."""
        result = self.runner.invoke(satochip_cli.main, ['util-generate-local'])
        self.assertEqual(self.constructed, [])
        self.assertEqual(result.exit_code, 0, result.output)


class TestNoArgumentsIsHandled(unittest.TestCase):

    def test_bare_invocation_prints_help(self):
        result = CliRunner().invoke(satochip_cli.main, [])
        self.assertNotIsInstance(result.exception, IndexError)
        self.assertIn('Usage:', result.output)

    def test_help_does_not_open_the_card(self):
        result = CliRunner().invoke(satochip_cli.main, ['--help'])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('Usage:', result.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
