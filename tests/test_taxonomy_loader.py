"""Tests for ai_codescan.taxonomy.loader."""

import pytest

from ai_codescan.taxonomy.loader import (
    UnknownBugClassError,
    list_classes,
    resolve_classes,
)


def test_resolve_single_class() -> None:
    classes = resolve_classes(["xss"])
    assert {c.name for c in classes} == {"xss"}


def test_resolve_alias_to_canonical() -> None:
    classes = resolve_classes(["sql-injection"])
    assert {c.name for c in classes} == {"sqli"}


def test_resolve_group_expansion() -> None:
    classes = resolve_classes(["@injection"])
    names = {c.name for c in classes}
    assert "xss" in names and "sqli" in names and "cmdi" in names


def test_resolve_unknown_suggests_match() -> None:
    with pytest.raises(UnknownBugClassError) as exc:
        resolve_classes(["xs"])
    assert "did you mean 'xss'" in str(exc.value).lower()


def test_list_classes_returns_all_canonical_names() -> None:
    names = {c.name for c in list_classes()}
    assert "xss" in names and "ssrf" in names


def test_idor_class_marked_needs_semantic() -> None:
    classes = resolve_classes(["idor"])
    assert classes[0].needs_semantic is True


def test_xss_class_does_not_need_semantic() -> None:
    classes = resolve_classes(["xss"])
    assert classes[0].needs_semantic is False
