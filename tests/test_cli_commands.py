# -*- coding: utf-8 -*-
"""CLI commands must not be invoked as plain functions (audit finding B5).

`@main.command()` binds the name to a `click.Command`, not to the function it
decorates. Calling one runs Click's standalone `main()`, which re-parses argv,
re-prompts for the PIN and then calls `sys.exit()`. Two call sites did exactly
that:

    common_set_card_label(["--label", label])   # inside common_initial_setup
    common_initial_setup(["--satodime"])        # inside satodime_ownership_claim

so `common-initial-setup --label X` exited before returning, and
`satodime-ownership-claim` passed an option that `common_initial_setup` does not
accept, aborting with a Click UsageError (exit code 2) before anything ran.

The shared bodies are now plain helpers that both the commands and the internal
callers use.
"""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import click

import satochip_cli

CLI_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'satochip_cli.py')


def command_names(tree):
    """Names bound to a click.Command by an @main.command() decorator."""
    return {node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and any(isinstance(d, ast.Call)
                    and getattr(d.func, 'attr', None) == 'command'
                    for d in node.decorator_list)}


class TestNoCommandCalledAsFunction(unittest.TestCase):

    def test_no_command_is_called_as_a_function(self):
        tree = ast.parse(open(CLI_PATH, encoding='utf-8').read())
        commands = command_names(tree)
        self.assertGreater(len(commands), 10, "no commands found; check the AST walk")
        offenders = [
            "%s() at line %d" % (node.func.id, node.lineno)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, 'id', None) in commands
            # the module entry point is the one legitimate case
            and node.func.id != 'main'
        ]
        self.assertEqual(offenders, [], "click Commands invoked as functions: %s" % offenders)


class TestSharedBodiesAreHelpers(unittest.TestCase):
    """The reusable bodies must be plain functions, and the commands thin."""

    def test_helpers_are_plain_functions(self):
        for name in ('set_card_label', 'initial_setup'):
            with self.subTest(helper=name):
                helper = getattr(satochip_cli, name, None)
                self.assertIsNotNone(helper, "%s() is missing" % name)
                self.assertNotIsInstance(helper, click.Command)
                self.assertTrue(callable(helper))

    def test_initial_setup_is_callable_without_arguments(self):
        """satodime_ownership_claim() calls it with none."""
        import inspect
        sig = inspect.signature(satochip_cli.initial_setup)
        bound = sig.bind()          # raises TypeError if a value were required
        self.assertEqual(bound.arguments, {})


class TestCommandsStillRegistered(unittest.TestCase):
    """The refactor must not drop any command or change its options."""

    EXPECTED = {
        'common_set_card_label': ['label'],
        'common_initial_setup': ['label'],
        'satodime_ownership_claim': [],
    }

    def test_commands_exist_with_their_options(self):
        for name, params in self.EXPECTED.items():
            with self.subTest(command=name):
                cmd = getattr(satochip_cli, name)
                self.assertIsInstance(cmd, click.Command)
                self.assertEqual([p.name for p in cmd.params], params)

    def test_commands_are_reachable_from_the_group(self):
        registered = satochip_cli.main.commands
        for name in self.EXPECTED:
            with self.subTest(command=name):
                self.assertIn(name.replace('_', '-'), registered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
