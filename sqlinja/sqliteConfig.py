#!/bin/python

from .abstractConfig import AbstractConfig

class SqliteConfig(AbstractConfig):
    """Contains Sqlite specificities"""
    end_char: int = 0
    start_index: int = 1

    equal      = staticmethod(lambda v: f"={v}")
    range_     = staticmethod(lambda v, mn, mx: f" BETWEEN {v + 1} AND {mx}")
    substring  = staticmethod(lambda expr, i: f"SUBSTR(({expr}),{i},1)")
    char_code  = staticmethod(lambda expr: f"UNICODE({expr})")
    length     = staticmethod(lambda expr: f"LENGTH({expr})")
    code_or_end = staticmethod(lambda expr: f"IFNULL(({expr}),0)")
    is_null     = staticmethod(lambda expr: f"({expr}) IS NULL")
    has_result  = staticmethod(lambda req: f"EXISTS({req})")
    limit      = staticmethod(lambda offset, n: f"LIMIT {offset},{n}")
    as_boolean = staticmethod(lambda cond: f"({cond})")
    as_time    = None  # SQLite has no SLEEP/WAITFOR equivalent
