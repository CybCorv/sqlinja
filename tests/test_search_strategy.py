#!/usr/bin/env python3
"""Unit tests for BinarySearch, PrefixReplay and SearchContext -- the
probe/narrow strategies SqlInja drives, and the state that wires them
together. Exercised directly against a plain oracle, no SQLite involved."""

import unittest
from typing import Callable

from sqlinja import AbstractConfig, BinarySearch, CandidateSet, PrefixReplay, SearchContext, SearchStrategy, SqliteConfig


def resolve(
    strategy: SearchStrategy,
    config: AbstractConfig,
    oracle: Callable[[str], bool],
) -> int:
    """Drive one probe/narrow loop to convergence."""
    result: int | None = None
    while result is None:
        operator = strategy.next_operator(config)
        result = strategy.narrow(oracle(operator))
    return result


class BinarySearchTestCase(unittest.TestCase):
    def setUp(self):
        self.config = SqliteConfig()
        # candidates 65..90 (A-Z), no gaps -> no sentinels in range
        self.candidates = CandidateSet(list(range(65, 91)), end_char=0)

    def make_oracle(self, target: int):
        """A boolean oracle for the operators SqliteConfig emits:
        "=N" (equal) and " BETWEEN a AND b" (range_)."""
        def oracle(operator: str) -> bool:
            if operator.startswith("="):
                return int(operator[1:]) == target
            # " BETWEEN {v+1} AND {mx}" -- true iff target is in [v+1, mx]
            _, low, _, high = operator.split()
            return int(low) <= target <= int(high)
        return oracle

    def test_converges_on_each_candidate(self):
        for target in self.candidates.candidates:
            search = BinarySearch(self.candidates)
            oracle = self.make_oracle(target)
            self.assertEqual(resolve(search, self.config, oracle), target)

    def test_out_of_domain_char_converges_without_equality(self):
        # 'B' (66) is not a candidate: the dichotomy still lands on some
        # entry, but never via an equality the target answered true
        gapped_candidates = CandidateSet([ord("A"), ord("C")], end_char=0)
        self.assertNotIn(ord("B"), gapped_candidates.all)
        search = BinarySearch(gapped_candidates)
        oracle = self.make_oracle(ord("B"))
        result = resolve(search, self.config, oracle)
        self.assertIn(result, gapped_candidates.all)
        self.assertFalse(search.resolved_by_equality())


class PrefixReplayTestCase(unittest.TestCase):
    def setUp(self):
        self.config = SqliteConfig()
        self.candidates = CandidateSet(list(range(65, 91)), end_char=0)

    def test_resolves_prefix_char_with_a_single_equal_probe(self):
        fallback = BinarySearch(self.candidates)
        strategy = PrefixReplay(
            start_with=[ord("A")],
            current_injection_char=1,
            start_index=1,
            fallback=fallback,
        )
        probes = []

        def oracle(operator: str) -> bool:
            probes.append(operator)
            return True  # the guessed prefix char is confirmed right away

        result = resolve(strategy, self.config, oracle)
        self.assertEqual(result, ord("A"))
        self.assertEqual(probes, [self.config.equal(ord("A"))])

    def test_falls_back_to_binary_search_on_prefix_mismatch(self):
        fallback = BinarySearch(self.candidates)
        strategy = PrefixReplay(
            start_with=[ord("A")],
            current_injection_char=1,
            start_index=1,
            fallback=fallback,
        )

        def oracle(operator: str) -> bool:
            if operator.startswith("="):
                return int(operator[1:]) == ord("Z")
            _, low, _, high = operator.split()
            return int(low) <= ord("Z") <= int(high)

        result = resolve(strategy, self.config, oracle)
        self.assertEqual(result, ord("Z"))

    def test_inactive_beyond_prefix_length_delegates_immediately(self):
        fallback = BinarySearch(self.candidates)
        strategy = PrefixReplay(
            start_with=[ord("A")],
            current_injection_char=2,
            start_index=1,
            fallback=fallback,
        )

        def oracle(operator: str) -> bool:
            if operator.startswith("="):
                return int(operator[1:]) == ord("B")
            _, low, _, high = operator.split()
            return int(low) <= ord("B") <= int(high)

        result = resolve(strategy, self.config, oracle)
        self.assertEqual(result, ord("B"))


class SearchContextTestCase(unittest.TestCase):
    def setUp(self):
        self.config = SqliteConfig()

    def test_uses_prefix_replay_strategy_when_start_with_given(self):
        context = SearchContext(
            self.config, candidates={ord("A"), ord("B")}, start_with=[ord("A")]
        )
        self.assertIsInstance(context.new_strategy(), PrefixReplay)

    def test_uses_binary_search_strategy_when_no_start_with(self):
        context = SearchContext(self.config, candidates={ord("A"), ord("B")})
        self.assertIsInstance(context.new_strategy(), BinarySearch)

    def test_advance_to_next_char_moves_position_and_rebuilds_strategy(self):
        context = SearchContext(self.config, candidates={ord("A"), ord("B")})
        self.assertEqual(context.current_index, self.config.start_index)
        context.advance_to_next_char()
        self.assertEqual(context.current_index, self.config.start_index + 1)

    def test_restart_resets_position_and_keeps_candidate_domain(self):
        context = SearchContext(self.config, candidates={ord("A"), ord("B")})
        context.advance_to_next_char()
        context.advance_to_next_char()
        candidate_set_before = context.candidate_set

        context.restart(start_with=[ord("B")])

        self.assertEqual(context.current_index, self.config.start_index)
        self.assertIs(context.candidate_set, candidate_set_before)
        self.assertIsInstance(context.new_strategy(), PrefixReplay)

    def test_restart_without_start_with_keeps_previous_prefix(self):
        context = SearchContext(
            self.config, candidates={ord("A"), ord("B")}, start_with=[ord("A")]
        )
        context.restart()
        self.assertEqual(context.start_with, [ord("A")])

    def test_new_strategy_returns_a_fresh_instance_each_call(self):
        context = SearchContext(self.config, candidates={ord("A"), ord("B")})
        context.advance_to_next_char()
        index_before = context.current_index

        self.assertIsNot(context.new_strategy(), context.new_strategy())
        self.assertEqual(context.current_index, index_before)


if __name__ == "__main__":
    unittest.main()
