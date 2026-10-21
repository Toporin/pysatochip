# -*- coding: utf-8 -*-
"""make_header() must encode label_size as the UTF-8 byte count (audit finding).

`label_size = len(label)` counted characters while `label.encode('utf8')`
produced the bytes actually appended to the header. For any non-ASCII label
(e.g. "てすと": 3 characters, 9 bytes) the card parsed label_size bytes for
the label and read every following field (sid_pubkey, iv, padded secret size)
from a shifted offset, failing the import with 0x6F00 and corrupting the
on-card object table.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector

LABEL_SIZE_OFFSET = 14  # [id(2)|type|origin|rights|counters(3)|fp(4)|rfu(2)|label_size|label]


def make_header(label):
    cc = CardConnector.__new__(CardConnector)  # pure method: no card needed
    return bytes.fromhex(cc.make_header(0x10, 0x01, label))


class TestMakeHeaderLabelSize(unittest.TestCase):

    def test_ascii_label(self):
        header = make_header("my password")
        self.assertEqual(header[LABEL_SIZE_OFFSET], len("my password"))
        self.assertEqual(len(header), LABEL_SIZE_OFFSET + 1 + len("my password"))

    def test_non_ascii_label_uses_byte_count(self):
        label = "てすと"  # 3 characters, 9 UTF-8 bytes
        header = make_header(label)
        self.assertEqual(header[LABEL_SIZE_OFFSET], 9)
        self.assertEqual(len(header), LABEL_SIZE_OFFSET + 1 + 9)

    def test_label_round_trips_as_the_card_parses_it(self):
        for label in ("a", "my password", "てすと", " café ☕ ", "пароль"):
            with self.subTest(label=label):
                header = make_header(label)
                label_size = header[LABEL_SIZE_OFFSET]
                parsed = header[LABEL_SIZE_OFFSET + 1:LABEL_SIZE_OFFSET + 1 + label_size]
                self.assertEqual(parsed.decode("utf8"), label)
                self.assertEqual(len(header), LABEL_SIZE_OFFSET + 1 + label_size,
                                 "header must contain exactly label_size label bytes")

    def test_empty_label(self):
        header = make_header("")
        self.assertEqual(header[LABEL_SIZE_OFFSET], 0)
        self.assertEqual(len(header), LABEL_SIZE_OFFSET + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
