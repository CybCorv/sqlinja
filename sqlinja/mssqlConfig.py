#!/bin/python

from .abstractConfig import AbstractConfig

class MsSqlConfig(AbstractConfig):
    """Contains Mssql specificities"""
    end_char: int = 0
    start_index: int = 1

    equal      = staticmethod(lambda v: f"={v}")
    range_     = staticmethod(lambda v, mn, mx: f" BETWEEN {v + 1} AND {mx}")
    substring  = staticmethod(lambda expr, i: f"SUBSTRING(({expr}),{i},1)")
    char_code  = staticmethod(lambda expr: f"UNICODE({expr})")
    length     = staticmethod(lambda expr: f"LEN({expr})")
    code_or_end = staticmethod(lambda expr: f"ISNULL(({expr}),0)")
    is_null     = staticmethod(lambda expr: f"({expr}) IS NULL")
    has_result  = staticmethod(lambda req: f"EXISTS({req})")
    limit      = staticmethod(lambda offset, n: f"OFFSET {offset} ROWS FETCH NEXT {n} ROWS ONLY")
    as_boolean = staticmethod(lambda cond: f"({cond})")
    as_time    = staticmethod(
        lambda cond, delay: f";IF ({cond}) WAITFOR DELAY '0:0:{delay}'"
    )
