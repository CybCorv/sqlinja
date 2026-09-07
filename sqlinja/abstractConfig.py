#!/bin/python

from abc import abstractmethod

class AbstractConfig:
    """Contains the Database's specificities"""

    end_char: int = 0
    """the int value of then '\0' equivalent for this database"""

    start_index: int = 1
    """the index of the fist item for this database"""

    @abstractmethod
    def get_equal_compare(self, value: int) -> str:
        """Generate equality comparator for this database"""
        pass

    @abstractmethod
    def get_diff_compare(self, value: int) -> str:
        """Generate none equality comparator for this database"""
        pass

    @abstractmethod
    def get_supp_compare(self, value: int, min: int, max: int) -> str:
        """Generate superior comparator for this database"""
        pass

    def wrap_request(self, request: str) -> str:
        """Normalize a NULL result of the request to an empty string for this database"""
        return request
