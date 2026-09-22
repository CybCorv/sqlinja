#!/bin/python

from enum import Enum
from typing import Callable

class Mode(Enum):
    """Blind-injection extraction strategy."""
    BOOLEAN = "boolean"
    TIME = "time"

class AbstractConfig:
    """Contract every dialect must fulfil.

    Each field below is a small callable (a delegate, akin to a C#
    Func<...,string>) producing one SQL fragment. Override any single one
    on an instance -- e.g. `config.range_ = lambda v, mn, mx: f">={v+1}"`
    to work around a WAF/blacklist -- without subclassing.
    """

    end_char: int = 0
    """the int value of the '\\0' equivalent for this database"""

    start_index: int = 1
    """the index of the first item for this database"""

    # -- comparing a value we control against the target; operands never NULL --
    equal: Callable[[int], str]
    """value == candidate, e.g. lambda v: f"={v}" """

    range_: Callable[[int, int, int], str]
    """candidate is within [min, max], e.g. lambda v, mn, mx: f" BETWEEN {v+1} AND {mx}" """

    # -- reading one character out of a string expression --
    substring: Callable[[str, int], str]
    """the nth character of expr, e.g. lambda expr, i: f"SUBSTR(({expr}),{i},1)" """

    char_code: Callable[[str], str]
    """the character code (ASCII/UNICODE/ORD) of expr"""

    length: Callable[[str], str]
    """the length in characters of a string expr, e.g. lambda expr: f"LEN({expr})" """

    code_or_end: Callable[[str], str]
    """coalesce a char_code result to end_char past the end of the string --
    UNICODE('') is NULL in T-SQL but ORD('') is 0 in MySQL"""

    is_null: Callable[[str], str]
    """true iff expr is NULL, e.g. lambda expr: f"({expr}) IS NULL" """

    has_result: Callable[[str], str]
    """true iff request yields a row, NULL included -- testing the value
    ("(req) IS NOT NULL") truncates a column at its first NULL cell"""

    # -- pagination for column-wide extraction --
    limit: Callable[[int, int], str]
    """LIMIT/OFFSET fragment for (offset, count)"""

    # -- wrapping the whole condition into the injectable statement --
    as_boolean: Callable[[str], str]
    """embeds condition into a boolean-blind statement"""

    as_time: Callable[[str, int], str] | None = None
    """embeds condition into a time-blind statement (condition, delay);
    None if this dialect has no timing primitive"""
