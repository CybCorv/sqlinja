#!/usr/bin/env python3
"""Shared SQLite fixture: a genuine string-concatenation injection point
(no HTTP) simulating a route built as:
SELECT * FROM Users WHERE LastLoginIP = '<user input>'

Used by both test_sqlinja.py and test_domains.py so the two suites probe
the exact same vulnerable route instead of two slightly different ones."""

import sqlite3
import unittest
from typing import Callable

from sqlinja import Mode, SqlInja, SqliteConfig


class RecordingProbe:
    """Wraps an exec_request callable, recording every (payload, result)
    pair and the call count -- for tests asserting on request shape or
    volume rather than just the extracted value."""

    def __init__(self, exec_request: Callable[[str, int], bool]) -> None:
        self._exec_request = exec_request
        self.calls: list[tuple[str, bool]] = []

    @property
    def count(self) -> int:
        return len(self.calls)

    def reset_count(self) -> None:
        self.calls.clear()

    def __call__(self, payload: str, sleep_duration: int) -> bool:
        result = self._exec_request(payload, sleep_duration)
        self.calls.append((payload, result))
        return result


class SqliteInjectionTestCase(unittest.TestCase):
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

    def add_user(self, username: str | None, last_login_ip: str, avatar: bytes | None = None) -> None:
        self.cur.execute(
            "INSERT INTO Users(UserName, LastLoginIP, Avatar) VALUES (?, ?, ?)",
            (username, last_login_ip, avatar),
        )
        self.con.commit()

    def run_vulnerable_route(self, user_input: str) -> bool:
        query = "SELECT * FROM Users WHERE LastLoginIP = '" + user_input + "'"
        return self.cur.execute(query).fetchone() is not None

    def exec_request(self, payload: str, sleep_duration: int) -> bool:
        injected = f"nonexistent' OR ({payload}) -- "
        return self.run_vulnerable_route(injected)

    def recording_exec_request(self) -> RecordingProbe:
        return RecordingProbe(self.exec_request)
