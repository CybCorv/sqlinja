#!/usr/bin/env python3
"""Contracts for the three kinds of extraction domain: sparse chars
(tolerant, flags out-of-domain with a placeholder), numeric (strict,
bounded so it can't converge outside [min, max]), and hex (an ordinary
sparse-char extraction over a fixed alphabet). Written against a real,
syntactically vulnerable SQLite query, like test_sqlinja.py."""

import string
import unittest

from sqlinja import CandidateTooNarrow, SqlInja, Mode, SqliteConfig

from tests._sqlite_fixture import SqliteInjectionTestCase


class SparseCharDomainTestCase(SqliteInjectionTestCase):
    def setUp(self):
        super().setUp()
        self.candidates = string.ascii_letters + string.digits

    def test_char_deep_inside_a_gap_is_reported_not_guessed(self):
        # "abcxyz" leaves a gap 100-119: 'm' (109) sits deep inside it
        self.add_user("m", "10.0.0.30")

        with self.assertRaises(CandidateTooNarrow):
            list(self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.30'",
                "abcxyz",
            ))

    def test_chars_inside_the_domain_are_unaffected(self):
        # same gapped alphabet as the test above: proves the gap itself
        # isn't what breaks extraction, only a char actually outside it
        self.add_user("cab", "10.0.0.31")

        chars = list(self.helper.extract_by_length(
            "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.31'",
            "abcxyz",
        ))

        self.assertEqual("".join(chars), "cab")

    def test_out_of_domain_char_blames_the_domain_not_the_oracle(self):
        # a char outside the domain is denied on every retry, which is what
        # separates it from an oracle that lies at random
        self.add_user("Z", "10.0.0.32")
        helper = SqlInja(
            SqliteConfig(), self.exec_request, mode=Mode.BOOLEAN,
            confirm_char_max_retries=2,
        )

        with self.assertRaises(CandidateTooNarrow) as caught:
            list(helper.extract_until_end_char(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.32'",
                string.ascii_lowercase,
            ))

        self.assertIn("all 3 attempts", str(caught.exception))

    def test_zero_retries_reports_the_diagnosis_as_ambiguous(self):
        # with no retry budget the two causes cannot be told apart, and the
        # error must say so rather than blame the candidate set
        self.add_user("Z", "10.0.0.33")
        helper = SqlInja(
            SqliteConfig(), self.exec_request, mode=Mode.BOOLEAN,
            confirm_char_max_retries=0,
        )

        with self.assertRaises(CandidateTooNarrow) as caught:
            list(helper.extract_until_end_char(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.33'",
                string.ascii_lowercase,
            ))

        self.assertIn("no retry budget", str(caught.exception))

    def test_empty_candidate_domain_is_rejected(self):
        for name in ("extract_until_end_char", "extract_by_length"):
            with self.subTest(method=name):
                with self.assertRaises(ValueError):
                    list(getattr(self.helper, name)(
                        "SELECT UserName FROM Users WHERE Id = 1", ""
                    ))


class NumericDomainTestCase(SqliteInjectionTestCase):
    def test_too_narrow_upper_bound_raises(self):
        with self.assertRaises(ValueError):
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 0, 2)

    def test_too_high_lower_bound_raises(self):
        with self.assertRaises(ValueError):
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 10, 20)

    def test_inverted_bounds_are_rejected(self):
        with self.assertRaises(ValueError):
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 100, 0)

    def test_resolved_value_never_exceeds_max_value(self):
        # the search domain is bounded to [min_value, max_value]; a
        # confirmed result outside it would mean the bound was not enforced
        value = self.helper.extract_val("SELECT COUNT(*) FROM Users", 0, 3)
        self.assertLessEqual(value, 3)


class HexBlobDomainTestCase(SqliteInjectionTestCase):
    """Blob-as-hex: HEX(Avatar) is an ordinary sparse-char extraction over
    "0123456789ABCDEF", extracted with the same extract_by_length() as any
    other alphabet; pairing hex digits back into bytes happens on the
    caller's side. Raw-byte extraction isn't an option here: a 0x00 byte
    would be indistinguishable from end_char (also 0x00) -- HEX() sidesteps
    that."""

    HEX_ALPHABET = "0123456789ABCDEF"
    BLOB = bytes([0x00, 0xDE, 0xAD, 0x00, 0xBE, 0xEF, 0xFF, 0x10])

    def setUp(self):
        super().setUp()
        self.add_user("binuser", "10.0.0.20", avatar=self.BLOB)
        self.request = "HEX(Avatar) FROM Users WHERE LastLoginIP = '10.0.0.20'"

    def read_hex(self, column_expr: str) -> str:
        chars = self.helper.extract_by_length(
            f"SELECT {column_expr}", self.HEX_ALPHABET
        )
        return "".join(chars)

    def test_hex_extraction_round_trips_bytes_including_embedded_nulls(self):
        hex_value = self.read_hex(self.request)
        data = bytes.fromhex(hex_value)
        self.assertEqual(data, self.BLOB)

    def test_hex_extraction_does_not_stop_at_first_null_byte(self):
        self.assertEqual(self.BLOB[0], 0x00)
        hex_value = self.read_hex(self.request)
        self.assertEqual(len(hex_value), len(self.BLOB) * 2)

    def test_empty_blob_yields_empty_hex_string(self):
        self.add_user("emptyblob", "10.0.0.21", avatar=b"")
        hex_value = self.read_hex(
            "HEX(Avatar) FROM Users WHERE LastLoginIP = '10.0.0.21'"
        )
        self.assertEqual(hex_value, "")

    def test_hex_output_length_is_always_even(self):
        hex_value = self.read_hex(self.request)
        self.assertEqual(len(hex_value) % 2, 0)


if __name__ == "__main__":
    unittest.main()
