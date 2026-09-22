#!/usr/bin/env python3
"""Unit tests for CandidateSet: the normalized (candidates + end_char)
domain used by SqlInja's search strategies."""

import string
import unittest

from sqlinja import CandidateSet


class CandidateSetTestCase(unittest.TestCase):
    def test_domain_is_candidates_plus_end_char(self):
        candidates = {ord(c) for c in string.ascii_letters + string.digits}
        candidate_set = CandidateSet(candidates, end_char=0)

        self.assertEqual(set(candidate_set.all), candidates | {0})
        self.assertEqual(candidate_set.all, sorted(candidate_set.all))

    def test_accepts_string_candidates(self):
        candidate_set = CandidateSet("ba", end_char=0)
        self.assertEqual(candidate_set.candidates, [ord("a"), ord("b")])

    def test_deduplicates_and_sorts_candidates(self):
        candidate_set = CandidateSet([66, 65, 65, 66], end_char=0)
        self.assertEqual(candidate_set.candidates, [65, 66])

    def test_empty_candidates_holds_only_end_char(self):
        candidate_set = CandidateSet(set(), end_char=0)
        self.assertEqual(candidate_set.candidates, [])
        self.assertEqual(candidate_set.all, [0])

    def test_no_code_between_candidates_is_searchable(self):
        # 'A' (65) and 'C' (67) leave a gap at 'B' (66): it is not a
        # candidate, so it must not be searchable either
        candidate_set = CandidateSet([65, 67], end_char=0)
        self.assertNotIn(66, candidate_set.all)

    def test_end_char_among_candidates_is_not_duplicated(self):
        candidate_set = CandidateSet([65, 66], end_char=65)
        self.assertEqual(candidate_set.all.count(65), 1)

    def test_indexable_for_binary_search(self):
        candidate_set = CandidateSet([67, 65], end_char=0)
        self.assertEqual(len(candidate_set), 3)
        self.assertEqual([candidate_set[i] for i in range(3)], [0, 65, 67])


if __name__ == "__main__":
    unittest.main()
