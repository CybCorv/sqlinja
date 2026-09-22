#!/usr/bin/env python3
"""Contracts for the three kinds of extraction domain: sparse chars
(tolerant, flags out-of-domain with a placeholder), numeric (strict,
bounded so it can't converge outside [min, max]), and hex (an ordinary
sparse-char extraction over a fixed alphabet). Written against a real,
syntactically vulnerable SQLite query, like test_sqlinja.py."""

import sqlite3
import string
import unittest

from sqlinja import CandidateTooNarrow, SqlInja, Mode, SqliteConfig


class DomainTestCaseBase(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.cur = self.con.cursor()
        self.cur.execute(
            "CREATE TABLE Users(Id INTEGER PRIMARY KEY, UserName TEXT, "
            "LastLoginIP TEXT, Avatar BLOB)"
        )
        self.cur.executemany(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (?, ?)",
            [("soham", "10.0.0.1"), ("admin", "10.0.0.2"), ("guest", "10.0.0.3")],
        )
        self.con.commit()
        self.helper = SqlInja(SqliteConfig(), self.exec_request, mode=Mode.BOOLEAN)

    def tearDown(self):
        self.con.close()

    def exec_request(self, payload: str, sleep_duration: int) -> bool:
        query = (
            "SELECT * FROM Users WHERE LastLoginIP = '"
            f"nonexistent' OR ({payload}) -- "
            "'"
        )
        return self.cur.execute(query).fetchone() is not None


class SparseCharDomainTestCase(DomainTestCaseBase):
    def setUp(self):
        super().setUp()
        self.candidates = string.ascii_letters + string.digits

    def test_out_of_domain_char_is_reported_not_guessed(self):
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES ('a/b', '10.0.0.7')"
        )
        self.con.commit()

        with self.assertRaises(CandidateTooNarrow):
            list(self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.7'",
                self.candidates,
            ))

    def test_char_deep_inside_a_gap_is_reported_not_guessed(self):
        # "abcxyz" leaves a gap 100-119: 'm' (109) sits deep inside it
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES ('m', '10.0.0.30')"
        )
        self.con.commit()

        with self.assertRaises(CandidateTooNarrow):
            list(self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.30'",
                "abcxyz",
            ))

    def test_chars_inside_the_domain_are_unaffected(self):
        # confirming each resolved char must not change what a well-formed
        # extraction returns
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES ('cab', '10.0.0.31')"
        )
        self.con.commit()

        chars = list(self.helper.extract_by_length(
            "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.31'",
            "abcxyz",
        ))

        self.assertEqual("".join(chars), "cab")

    def test_out_of_domain_char_blames_the_domain_not_the_oracle(self):
        # a char outside the domain is denied on every retry, which is what
        # separates it from an oracle that lies at random
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES ('Z', '10.0.0.32')"
        )
        self.con.commit()
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
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES ('Z', '10.0.0.33')"
        )
        self.con.commit()
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

    def test_end_char_inside_domain_is_rejected(self):
        candidates = self.candidates + chr(SqliteConfig().end_char)
        with self.assertRaises(ValueError):
            list(self.helper.extract_until_end_char(
                "SELECT UserName FROM Users WHERE Id = 1", candidates
            ))


class NumericDomainTestCase(DomainTestCaseBase):
    def test_resolves_value_inside_bounds(self):
        self.assertEqual(
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 0, 100), 3
        )

    def test_single_value_range(self):
        self.assertEqual(self.helper.extract_val("SELECT 3", 3, 3), 3)

    def test_too_narrow_upper_bound_raises(self):
        with self.assertRaises(ValueError):
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 0, 2)

    def test_too_high_lower_bound_raises(self):
        with self.assertRaises(ValueError):
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 10, 20)

    def test_inverted_bounds_are_rejected(self):
        with self.assertRaises(ValueError):
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 100, 0)

    def test_never_yields_the_replacement_char_code(self):
        for max_value in (2, 5, 100):
            try:
                value = self.helper.extract_val(
                    "SELECT COUNT(*) FROM Users", 0, max_value
                )
            except ValueError:
                continue
            self.assertNotEqual(value, ord("�"))
            self.assertLessEqual(value, max_value)


class HexBlobDomainTestCase(DomainTestCaseBase):
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
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP, Avatar) VALUES (?, ?, ?)",
            ("binuser", "10.0.0.20", self.BLOB),
        )
        self.con.commit()
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
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP, Avatar) VALUES (?, ?, ?)",
            ("emptyblob", "10.0.0.21", b""),
        )
        self.con.commit()
        hex_value = self.read_hex(
            "HEX(Avatar) FROM Users WHERE LastLoginIP = '10.0.0.21'"
        )
        self.assertEqual(hex_value, "")

    def test_hex_output_length_is_always_even(self):
        hex_value = self.read_hex(self.request)
        self.assertEqual(len(hex_value) % 2, 0)


if __name__ == "__main__":
    unittest.main()
