# -*- coding: utf-8 -*-
"""Password secrets with a structured label (type 0x90, subtype 0x01).

For this subtype the secret is [password_size(1b) | password] and the header
label is [descriptor_size(1b) | descriptor | login_size(1b) | login |
url_size(1b) | url], each field UTF-8, optional, but not all empty, and the
whole label at most 127 bytes. parse_seedkeeper_header() exposes it as
'label_dict' and as a '|'-joined display string in 'label'.
"""

import os
import sys
import hashlib
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from pysatochip.CardConnector import CardConnector
from pysatochip.CardDataParser import (CardDataParser, encode_password_label,
                                       decode_password_label)
from pysatochip.JCconstants import (SEEDKEEPER_SECRET_TYPE_PASSWORD,
                                    SEEDKEEPER_PASSWORD_SUBTYPE_LABEL_WITH_META,
                                    SEEDKEEPER_MAX_LABEL_SIZE)

PASSWORD = SEEDKEEPER_SECRET_TYPE_PASSWORD
WITH_META = SEEDKEEPER_PASSWORD_SUBTYPE_LABEL_WITH_META


def new_cc():
    cc = CardConnector.__new__(CardConnector)  # no card needed
    cc.parser = CardDataParser()
    return cc


def parse(secret_type, subtype, label):
    header = new_cc().make_header(secret_type, 0x01, label, subtype=subtype)
    return CardDataParser().parse_seedkeeper_header(list(bytes.fromhex(header)))


class TestEncodeDecode(unittest.TestCase):

    def test_wire_format(self):
        self.assertEqual(bytes(encode_password_label('ab', '', 'c')),
                         b'\x02ab\x00\x01c')

    def test_round_trip(self):
        for fields in (('mail', 'alice', 'https://mail.example.com'),
                       ('', 'bob', ''),
                       ('café ☕', 'пароль', ''),
                       ('', '', 'u')):
            with self.subTest(fields=fields):
                label = encode_password_label(*fields)
                self.assertEqual(decode_password_label(label),
                                 dict(zip(('descriptor', 'login', 'url'), fields)))

    def test_all_fields_empty_is_rejected(self):
        with self.assertRaises(ValueError):
            encode_password_label()

    def test_max_size_includes_size_bytes(self):
        max_field = SEEDKEEPER_MAX_LABEL_SIZE - 3
        self.assertEqual(len(encode_password_label('a' * max_field)), SEEDKEEPER_MAX_LABEL_SIZE)
        with self.assertRaises(ValueError):
            encode_password_label('a' * (max_field + 1))
        with self.assertRaises(ValueError):
            encode_password_label('a' * 300)

    def test_malformed_labels_are_rejected(self):
        for label in (b'', b'\x01a', b'\x05ab\x00\x00', b'\x00\x00\x00x',
                      b'\x02\xff\xfe\x00\x00'):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    decode_password_label(label)


class TestParseHeader(unittest.TestCase):

    def test_structured_label(self):
        label = encode_password_label('mail', 'alice', 'https://mail.example.com')
        header = parse(PASSWORD, WITH_META, label)
        self.assertEqual(header['label'], 'mail|alice|https://mail.example.com')
        self.assertEqual(header['label_dict'], {'descriptor': 'mail', 'login': 'alice',
                                                'url': 'https://mail.example.com'})
        self.assertEqual(header['label_list'], label)  # raw bytes kept

    def test_empty_fields_are_skipped_in_label(self):
        header = parse(PASSWORD, WITH_META, encode_password_label('', 'alice', 'example.com'))
        self.assertEqual(header['label'], 'alice|example.com')

    def test_default_subtype_is_unchanged(self):
        header = parse(PASSWORD, 0x00, "my password")
        self.assertEqual(header['label'], "my password")
        self.assertNotIn('label_dict', header)

    def test_other_type_with_subtype_1_is_unchanged(self):
        # e.g. Masterseed with BIP39 info: the label stays plain text
        header = parse(0x10, 0x01, "\x02ab\x00\x00")
        self.assertEqual(header['label'], "\x02ab\x00\x00")
        self.assertNotIn('label_dict', header)

    def test_malformed_structured_label_falls_back_to_text(self):
        header = parse(PASSWORD, WITH_META, "plain label")
        self.assertEqual(header['label'], "plain label")
        self.assertNotIn('label_dict', header)


class TestMakeHeader(unittest.TestCase):

    def test_bytes_label(self):
        label = encode_password_label('d', 'l', 'u')
        header = bytes.fromhex(new_cc().make_header(PASSWORD, 0x01, label, subtype=WITH_META))
        self.assertEqual(header[12], WITH_META)
        self.assertEqual(header[14], len(label))
        self.assertEqual(list(header[15:]), label)

    def test_label_too_long_is_rejected(self):
        new_cc().make_header(PASSWORD, 0x01, 'a' * SEEDKEEPER_MAX_LABEL_SIZE)
        with self.assertRaises(ValueError):
            new_cc().make_header(PASSWORD, 0x01, 'a' * (SEEDKEEPER_MAX_LABEL_SIZE + 1))


class TestImportSecret(unittest.TestCase):
    """seedkeeper_import_secret() must not store a malformed structured label."""

    def setUp(self):
        self.cc = new_cc()
        self.apdus = []

        def transmit(apdu):
            self.apdus.append(apdu)
            # OP_FINAL response: [id(2) | fingerprint(4)]
            return [0x00, 0x01] + list(bytes.fromhex(self.fingerprint)), 0x90, 0x00
        self.cc.card_transmit = transmit

    def import_secret(self, label):
        secret_list = [3] + list(b'pwd')
        self.fingerprint = hashlib.sha256(bytes(secret_list)).hexdigest()[0:8]
        header = self.cc.make_header(PASSWORD, 0x01, label, subtype=WITH_META)
        return self.cc.seedkeeper_import_secret({'header': header, 'secret_list': secret_list})

    def test_valid_label_is_imported(self):
        sid, _ = self.import_secret(encode_password_label('d', 'l', 'u'))
        self.assertEqual(sid, 1)
        self.assertEqual(len(self.apdus), 2)  # OP_INIT + OP_FINAL

    def test_malformed_label_is_rejected_before_any_apdu(self):
        with self.assertRaises(ValueError):
            self.import_secret("plain label")
        self.assertEqual(self.apdus, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
