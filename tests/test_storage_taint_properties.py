"""Property-based tests for ai_codescan.storage_taint parsers.

Hypothesis-driven tests assert structural invariants of the regex- and
sqlglot-backed helpers under generated inputs. The unit tests in
``test_storage_taint.py`` cover specific call shapes; these complement
them by exercising the spaces of strings the helpers refuse / accept.
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_codescan.storage_taint import (
    _key_pattern_to_regex,
    classify_call,
    classify_sql_op,
    detect_sql_storage_ids,
)

# ---------------------------------------------------------------------------
# detect_sql_storage_ids
# ---------------------------------------------------------------------------


def test_detect_sql_storage_ids_handles_empty() -> None:
    assert detect_sql_storage_ids("") == []


@given(st.text(max_size=200))
@settings(max_examples=200, deadline=2000)
def test_detect_sql_storage_ids_never_raises(garbage: str) -> None:
    """The parser must swallow malformed SQL silently and return a list."""
    out = detect_sql_storage_ids(garbage)
    assert isinstance(out, list)
    for item in out:
        assert isinstance(item, str)


@given(
    table=st.from_regex(r"\A[a-z][a-z_0-9]{0,16}\Z", fullmatch=True),
    column=st.from_regex(r"\A[a-z][a-z_0-9]{0,16}\Z", fullmatch=True),
)
@settings(max_examples=200, deadline=2000)
def test_detect_sql_storage_ids_canonicalises_select(table: str, column: str) -> None:
    """``SELECT <col> FROM <table>`` always yields ``sql:<table>.<col>``."""
    sql = f"SELECT {column} FROM {table}"
    ids = detect_sql_storage_ids(sql)
    assert f"sql:{table}.{column}" in ids


@given(
    table=st.from_regex(r"\A[a-z][a-z_0-9]{0,12}\Z", fullmatch=True),
    column=st.from_regex(r"\A[a-z][a-z_0-9]{0,12}\Z", fullmatch=True),
)
@settings(max_examples=200, deadline=2000)
def test_detect_sql_storage_ids_results_are_lowercased(table: str, column: str) -> None:
    """Storage_ids are lowercased so case-insensitive SQL doesn't fan out."""
    sql = f"SELECT {column.upper()} FROM {table.upper()}"
    ids = detect_sql_storage_ids(sql)
    for sid in ids:
        kind, _, body = sid.partition(":")
        assert kind == "sql"
        assert body == body.lower()


# ---------------------------------------------------------------------------
# classify_sql_op
# ---------------------------------------------------------------------------


@given(st.text(max_size=200))
@settings(max_examples=200, deadline=2000)
def test_classify_sql_op_returns_known_or_none(text: str) -> None:
    """The classifier returns one of {'read', 'write', None} on any input."""
    op = classify_sql_op(text)
    assert op in {"read", "write", None}


@given(
    table=st.from_regex(r"\A[a-z][a-z_0-9]{0,12}\Z", fullmatch=True),
    column=st.from_regex(r"\A[a-z][a-z_0-9]{0,12}\Z", fullmatch=True),
)
@settings(max_examples=100, deadline=2000)
def test_classify_sql_op_select_is_read(table: str, column: str) -> None:
    assert classify_sql_op(f"SELECT {column} FROM {table}") == "read"


@given(
    table=st.from_regex(r"\A[a-z][a-z_0-9]{0,12}\Z", fullmatch=True),
    column=st.from_regex(r"\A[a-z][a-z_0-9]{0,12}\Z", fullmatch=True),
)
@settings(max_examples=100, deadline=2000)
def test_classify_sql_op_update_is_write(table: str, column: str) -> None:
    assert classify_sql_op(f"UPDATE {table} SET {column} = 1") == "write"


# ---------------------------------------------------------------------------
# classify_call (cross-language receiver+method matcher)
# ---------------------------------------------------------------------------


@given(st.text(max_size=200))
@settings(max_examples=300, deadline=2000)
def test_classify_call_returns_known_kinds_or_none(callee: str) -> None:
    """``classify_call`` always returns a tuple of two known strings or None."""
    out = classify_call(callee)
    if out is None:
        return
    kind, op = out
    assert kind in {"sql_column", "cache_key", "queue_topic", "file_path", "env_var"}
    assert op in {"read", "write", "unknown"}


@given(
    receiver=st.sampled_from(["cache", "redis", "client", "r", "kv", "memcache", "mc"]),
    method=st.sampled_from(["set", "hset", "setex", "mset", "hmset", "psetex"]),
)
def test_classify_call_cache_writes(receiver: str, method: str) -> None:
    out = classify_call(f"{receiver}.{method}")
    assert out == ("cache_key", "write")


@given(
    receiver=st.sampled_from(["cache", "redis", "client", "r", "kv", "memcache", "mc"]),
    method=st.sampled_from(["get", "hget", "mget", "hgetall", "get_multi"]),
)
def test_classify_call_cache_reads(receiver: str, method: str) -> None:
    out = classify_call(f"{receiver}.{method}")
    assert out == ("cache_key", "read")


# ---------------------------------------------------------------------------
# _key_pattern_to_regex (LLM-suggested storage_id → source-line matcher)
# ---------------------------------------------------------------------------


@given(
    prefix=st.sampled_from(["cache", "queue", "session", "kv"]),
    body=st.from_regex(r"\A[a-z]{1,8}(:[a-z]{1,8}){0,3}\Z", fullmatch=True),
)
def test_key_pattern_to_regex_matches_literal_self(prefix: str, body: str) -> None:
    """A literal storage_id (no ``*`` holes) matches its own tail."""
    storage_id = f"{prefix}:{body}"
    regex = _key_pattern_to_regex(storage_id)
    # The tail (``body`` after the kind prefix) must match the regex.
    assert regex.search(body) is not None


@given(
    prefix=st.sampled_from(["cache", "queue", "session"]),
    head=st.from_regex(r"\A[a-z]{1,6}\Z", fullmatch=True),
    tail=st.from_regex(r"\A[a-z]{1,6}\Z", fullmatch=True),
    runtime_value=st.from_regex(r"\A[a-zA-Z0-9_-]{1,12}\Z", fullmatch=True),
)
def test_key_pattern_to_regex_star_matches_runtime_value(
    prefix: str, head: str, tail: str, runtime_value: str
) -> None:
    """``cache:user:*:profile`` matches ``user:abc123:profile`` template
    instances regardless of which token fills the ``*``."""
    storage_id = f"{prefix}:{head}:*:{tail}"
    regex = _key_pattern_to_regex(storage_id)
    concrete = f"{head}:{runtime_value}:{tail}"
    assert regex.search(concrete) is not None


@given(
    prefix=st.sampled_from(["cache", "queue"]),
    head=st.from_regex(r"\A[a-z]{1,6}\Z", fullmatch=True),
    tail=st.from_regex(r"\A[a-z]{1,6}\Z", fullmatch=True),
    other=st.from_regex(r"\A[a-z]{1,6}\Z", fullmatch=True),
)
def test_key_pattern_to_regex_returns_compiled_pattern(
    prefix: str, head: str, tail: str, other: str
) -> None:
    """Result is always a compiled re.Pattern (case-insensitive)."""
    storage_id = f"{prefix}:{head}:*:{tail}"
    regex = _key_pattern_to_regex(storage_id)
    assert isinstance(regex, re.Pattern)
    # IGNORECASE is set when the regex was built — verify by matching mixed case.
    upper_concrete = f"{head.upper()}:{other}:{tail.upper()}"
    assert regex.search(upper_concrete) is not None
