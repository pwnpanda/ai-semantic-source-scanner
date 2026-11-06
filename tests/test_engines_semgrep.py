"""Tests for ai_codescan.engines.semgrep rule pinning.

``--config=auto`` resolves against the live Semgrep registry on every run, so
the same code at the same scanner commit produced different findings on
different days. Prep is the base every later stage builds on, so that drift
silently changed the candidate set mid-scan. These tests cover the local
snapshot that pins it.
"""

from __future__ import annotations

import urllib.error
from pathlib import Path

import pytest

from ai_codescan.engines import semgrep as semgrep_eng


@pytest.fixture
def fetches(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record registry fetches and serve a fixed ruleset."""
    calls: list[str] = []

    def fake_fetch(ref: str) -> str:
        calls.append(ref)
        return f"rules:\n- id: pinned-{len(calls)}\n"

    monkeypatch.setattr(semgrep_eng, "_fetch_registry_ruleset", fake_fetch)
    return calls


def test_snapshot_is_downloaded_once_and_then_reused(tmp_path: Path, fetches: list[str]) -> None:
    first = semgrep_eng.ensure_registry_snapshot(tmp_path)
    second = semgrep_eng.ensure_registry_snapshot(tmp_path)

    assert first == second == semgrep_eng.registry_snapshot_path(tmp_path)
    assert fetches == [semgrep_eng.DEFAULT_REGISTRY_RULESET], "registry was re-fetched"
    assert first is not None
    assert "pinned-1" in first.read_text(encoding="utf-8")


def test_refresh_rewrites_the_snapshot(tmp_path: Path, fetches: list[str]) -> None:
    semgrep_eng.ensure_registry_snapshot(tmp_path)
    refreshed = semgrep_eng.ensure_registry_snapshot(tmp_path, refresh=True)

    assert len(fetches) == 2
    assert refreshed is not None
    assert "pinned-2" in refreshed.read_text(encoding="utf-8")


def test_fetch_failure_without_a_snapshot_degrades_instead_of_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A registry outage must not fail the scan; it costs reproducibility only."""

    def boom(ref: str) -> str:
        raise urllib.error.URLError("registry unreachable")

    monkeypatch.setattr(semgrep_eng, "_fetch_registry_ruleset", boom)

    assert semgrep_eng.ensure_registry_snapshot(tmp_path) is None
    assert semgrep_eng.resolve_config(tmp_path, "") == "auto"


def test_fetch_failure_keeps_the_existing_snapshot(
    tmp_path: Path, fetches: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = semgrep_eng.ensure_registry_snapshot(tmp_path)
    assert snapshot is not None

    def boom(ref: str) -> str:
        raise TimeoutError("registry timed out")

    monkeypatch.setattr(semgrep_eng, "_fetch_registry_ruleset", boom)
    kept = semgrep_eng.ensure_registry_snapshot(tmp_path, refresh=True)

    assert kept == snapshot
    assert "pinned-1" in snapshot.read_text(encoding="utf-8")


def test_empty_registry_response_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(semgrep_eng, "_fetch_registry_ruleset", lambda ref: "   \n")
    assert semgrep_eng.ensure_registry_snapshot(tmp_path) is None


def test_resolve_config_defaults_to_the_pinned_snapshot(tmp_path: Path, fetches: list[str]) -> None:
    resolved = semgrep_eng.resolve_config(tmp_path, "")
    assert resolved == str(semgrep_eng.registry_snapshot_path(tmp_path))


def test_resolve_config_honours_an_explicit_choice(tmp_path: Path, fetches: list[str]) -> None:
    """``auto`` stays available as a deliberate opt-in to live rules."""
    assert semgrep_eng.resolve_config(tmp_path, "auto") == "auto"
    assert semgrep_eng.resolve_config(tmp_path, "p/ci") == "p/ci"
    assert fetches == [], "an explicit config must not touch the registry"


def test_run_semgrep_passes_the_snapshot_not_auto(
    tmp_path: Path, fetches: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default scan path pins rules rather than resolving them live."""
    captured: list[list[str]] = []

    def fake_run(cmd: list[str], *, project_id: str, timeout: int) -> None:
        captured.append(cmd)
        output = Path(cmd[cmd.index("--output") + 1])
        output.write_text('{"runs": []}', encoding="utf-8")

    monkeypatch.setattr(semgrep_eng, "is_available", lambda: True)
    monkeypatch.setattr(semgrep_eng, "_run_semgrep_process", fake_run)

    project = tmp_path / "src"
    project.mkdir()
    semgrep_eng.run_semgrep(project, cache_dir=tmp_path, project_id="proj")

    cmd = captured[0]
    snapshot = str(semgrep_eng.registry_snapshot_path(tmp_path))
    assert f"--config={snapshot}" in cmd
    assert "--config=auto" not in cmd


@pytest.mark.parametrize(
    ("config", "pinned"),
    [
        ("auto", False),
        ("p/ci", False),
        ("https://semgrep.dev/c/p/ci", False),
        ("", False),
    ],
)
def test_config_is_pinned_rejects_registry_references(config: str, pinned: bool) -> None:
    assert semgrep_eng.config_is_pinned(config) is pinned


def test_config_is_pinned_accepts_a_local_snapshot(tmp_path: Path, fetches: list[str]) -> None:
    snapshot = semgrep_eng.ensure_registry_snapshot(tmp_path)
    assert snapshot is not None
    assert semgrep_eng.config_is_pinned(str(snapshot)) is True
