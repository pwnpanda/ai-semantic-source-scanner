"""Tests for ai_codescan.taxonomy.diff."""

import datetime as _dt
from pathlib import Path

import pytest

from ai_codescan.taxonomy import diff as tax_diff


@pytest.fixture
def tmp_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path / "ai-codescan"


def test_known_tags_includes_existing_classes() -> None:
    known = tax_diff._known_tags()  # type: ignore[attr-defined]
    assert "security/cwe/cwe-079" in known  # xss
    assert "security/cwe/cwe-089" in known  # sqli


def test_diff_returns_empty_when_codeql_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    diff = tax_diff.diff_against_installed_codeql()
    assert diff.is_empty


def test_diff_finds_missing_tag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    pack = tmp_path / ".codeql" / "packages" / "test" / "1.0.0" / "queries"
    pack.mkdir(parents=True)
    (pack / "shiny.ql").write_text(
        "/**\n"
        " * @name a query\n"
        " * @id js/shiny\n"
        " * @tags security\n"
        " *       security/cwe/cwe-9999\n"
        " */\n",
        encoding="utf-8",
    )
    diff = tax_diff.diff_against_installed_codeql()
    assert "security/cwe/cwe-9999" in diff.missing_tags
    assert "cwe-9999" in diff.suggested_stubs_yaml


def test_mark_taxonomy_checked_writes_timestamp(tmp_config: Path) -> None:
    tax_diff.mark_taxonomy_checked()
    assert tax_diff.days_since_last_check() == 0


def test_is_stale_when_no_record(tmp_config: Path) -> None:
    assert tax_diff.is_stale() is True


def test_is_stale_after_threshold(tmp_config: Path) -> None:
    last = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=10)
    p = tax_diff._last_check_file()  # type: ignore[attr-defined]
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(last.isoformat(timespec="seconds"), encoding="utf-8")
    assert tax_diff.is_stale(threshold_days=7) is True
    assert tax_diff.is_stale(threshold_days=30) is False
