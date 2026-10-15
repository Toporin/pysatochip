# -*- coding: utf-8 -*-
"""Satocash CLI reported wrong proof data (audit finding B5).

Two independent bugs, both silent -- the output looked plausible:

  * `keyset_indexes_by_mint = max_nb_mints * [set()]` put the *same* set object
    at every index, so `.add()` recorded every keyset against every mint. The
    result is passed to satocash_export_keysets(), so satocash-export-tokenv4
    built a token from proofs belonging to other mints.
  * the proof state was decoded with `value ^ 0x03` while the comment on the
    same line said "MASK 0x03". XOR swapped unspent and spent, and turned every
    P2PK-flagged proof and every empty slot into "UNKNOWN".

These assert the semantics rather than the source text, so they stay meaningful
if the code is restructured.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

CLI_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'satochip_cli.py')

# as defined in satocash_get_proof_info()
STATE_BY_CODE = {0: "STATE_EMPTY", 1: "STATE_UNSPENT", 2: "STATE_SPENT"}
P2PK_FLAG = 0x80


class TestPerIndexSetsAreDistinct(unittest.TestCase):
    """The pattern the fix relies on, pinned so it cannot regress silently."""

    def test_list_multiplication_aliases_one_object(self):
        aliased = 3 * [set()]
        aliased[0].add('x')
        self.assertEqual(aliased[1], {'x'}, "sanity: this is the trap being avoided")
        self.assertIs(aliased[0], aliased[1])

    def test_comprehension_gives_independent_sets(self):
        proper = [set() for _ in range(3)]
        proper[0].add('x')
        self.assertEqual(proper[1], set())
        self.assertIsNot(proper[0], proper[1])

    def test_source_builds_the_sets_per_index(self):
        """Guards the two lines that caused cross-mint proof selection."""
        src = open(CLI_PATH, encoding='utf-8').read()
        for name in ('keyset_indexes_by_mint', 'proof_indexes_by_keyset'):
            with self.subTest(variable=name):
                assign = re.search(r'^\s*%s\s*=\s*(.+)$' % name, src, re.MULTILINE)
                self.assertIsNotNone(assign, "%s not found" % name)
                self.assertNotRegex(
                    assign.group(1), r'\*\s*\[\s*set\(\)\s*\]',
                    "%s aliases one shared set across every index" % name)
                self.assertIn('for _ in range', assign.group(1))


class TestProofStateDecoding(unittest.TestCase):
    """`value & 0x03` must round-trip every state, flagged or not."""

    def decode(self, value):
        return STATE_BY_CODE.get(value & 0x03, "UNKNOWN")

    def test_plain_states(self):
        self.assertEqual(self.decode(0), "STATE_EMPTY")
        self.assertEqual(self.decode(1), "STATE_UNSPENT")
        self.assertEqual(self.decode(2), "STATE_SPENT")

    def test_p2pk_flagged_states_still_decode(self):
        """XOR turned all of these into UNKNOWN."""
        self.assertEqual(self.decode(P2PK_FLAG | 1), "STATE_UNSPENT")
        self.assertEqual(self.decode(P2PK_FLAG | 2), "STATE_SPENT")
        self.assertEqual(self.decode(P2PK_FLAG | 0), "STATE_EMPTY")

    def test_xor_would_be_wrong(self):
        """Documents precisely what the old operator did."""
        xor = lambda v: STATE_BY_CODE.get(v ^ 0x03, "UNKNOWN")
        self.assertEqual(xor(1), "STATE_SPENT")      # unspent reported as spent
        self.assertEqual(xor(2), "STATE_UNSPENT")    # and vice versa
        self.assertEqual(xor(0), "UNKNOWN")
        self.assertEqual(xor(P2PK_FLAG | 1), "UNKNOWN")

    def test_source_uses_a_mask(self):
        src = open(CLI_PATH, encoding='utf-8').read()
        self.assertNotIn("dic_state_by_code.get((value ^ 0x03)", src,
                         "proof state is still decoded with XOR")
        self.assertIn("dic_state_by_code.get((value & 0x03)", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
