# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html)

## [0.3.0] - 2026-09-22

**Near-complete rewrite.** Most public entry points changed name, signature or
return type; `0.2.0` code will not run unchanged. An extraction now returns a
value the target confirmed, or raises -- never a plausible guess.

### Added

- `CandidateTooNarrow`, raised when a char is denied on every retry (i.e. it is
  outside `candidates`). A noisy oracle lies at random and gives way to a retry;
  retrying is what tells the two apart.
- `confirm_char_max_retries` (default `2`) to size that retry budget.
- `Mode.BOOLEAN` / `Mode.TIME`; `Mode.TIME` on a config without `as_time` now
  fails at construction, not at the first probe.
- `SqliteConfig`, `MsSqlConfig`.
- `extract_char()`, `extract_column_rows()`.
- `extract_cell()` and `is_null()`, to tell a NULL cell from an empty one:
  the char-yielding extractors produce nothing in both cases, so
  `extract_cell()` spends one extra request and returns `None` for NULL.
  `extract_column_rows()` yields `None` per NULL row.
- `start_with`, to resume an interrupted run without re-probing known chars.
- `max_length` (255) and `max_index` (999) caps.
- `py.typed` (PEP 561).
- `__all__` now covers the whole supported surface: `AbstractConfig` (to write
  a dialect) and the search internals `SearchStrategy`, `BinarySearch`,
  `PrefixReplay`, `CandidateSet`, `SearchContext` (to plug in a custom probing
  strategy). All importable straight from `sqlinja`.

### Changed

- Extraction returns text: single-char `str` from the cell/column extractors, a
  whole-row `str` from `extract_column_rows()`. Streaming is unchanged.
  `extract_val()` still returns `int`.
- `extract_cell()` → `extract_until_end_char()`, `extract_string()` →
  `extract_by_length()`. Same result; they differ only in end-of-value
  detection. The first is cheaper, the second needs no `end_char`.
  **`extract_cell()` still exists but means something else** (see Added):
  it returns a whole `str`, or `None` for NULL.
- Dialects are callable-based `AbstractConfig` subclasses; any fragment is
  overridable per instance to dodge a WAF. `isnull` → `code_or_end`,
  `isnull_code` → `is_null` (which now tests for NULL rather than
  coalescing it).
- `string.Template` dropped: the injection point lives in `execute_request`.
- `candidates` / `start_with` accept a plain `str`.
- `extract_val()` takes explicit bounds and confirms the result; a range
  excluding the real value raises `ValueError`.
- `has_result()` tests row existence, not non-NULL.
- `python_requires` `>=3.6` → `>=3.10` (it was wrong: the code uses PEP 604
  unions and `Protocol`).

### Removed

- `prepare_new()` — extraction state no longer persists between calls.
- `string_to_candidates()`, `string_to_prefix()` — pass the string directly.
- The `U+FFFD` placeholder — unresolvable chars raise instead.
- Candidate sentinels — they only guarded codes adjacent to a run, and made
  readable chars at those edges unreadable. Per-char confirmation replaces them.

### Fixed

- Chars outside `candidates` are no longer rounded to the nearest candidate.
- A `NULL` cell no longer truncates a column extraction.
- `extract_val()` no longer materialises its domain, so `[0, 1_000_000_000]` is
  practical.
- `extract_column()` row generators collected before being read no longer all
  resolve against the last request.

## [0.2.0] - 2023-04-16

Initial packaged release: `string.Template` injection point, `MySqlConfig`,
boolean/time-blind extraction of a scalar, a cell or a column.

[0.3.0]: https://github.com/CybCorv/sqlinja/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/CybCorv/sqlinja/releases/tag/v0.2.0
