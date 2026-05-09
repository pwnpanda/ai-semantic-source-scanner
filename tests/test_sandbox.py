"""Tests for ai_codescan.sandbox."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.sandbox import (
    DEFAULT_SIGNAL,
    SandboxResult,
    SandboxUnavailableError,
    image_for_lang,
    run_in_sandbox,
)


def _has_docker() -> bool:
    return shutil.which("docker") is not None


def test_image_for_lang_node() -> None:
    assert image_for_lang("javascript") == "node:22-alpine"
    assert image_for_lang("TypeScript") == "node:22-alpine"


def test_image_for_lang_python() -> None:
    assert image_for_lang("python") == "python:3.13-alpine"


def test_image_for_lang_default() -> None:
    assert image_for_lang("rust") == "alpine:3.20"


def test_run_in_sandbox_raises_when_docker_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(SandboxUnavailableError):
        run_in_sandbox(["echo", "hi"], image="alpine:3.20", work_dir=tmp_path)


@pytest.mark.integration
@pytest.mark.skipif(not _has_docker(), reason="docker not on PATH")
def test_run_in_sandbox_captures_signal(tmp_path: Path) -> None:
    result = run_in_sandbox(
        ["sh", "-c", f"echo {DEFAULT_SIGNAL}"],
        image="alpine:3.20",
        work_dir=tmp_path,
    )
    assert isinstance(result, SandboxResult)
    assert result.exit_code == 0
    assert result.signal_seen is True
    assert DEFAULT_SIGNAL in result.stdout


@pytest.mark.integration
@pytest.mark.skipif(not _has_docker(), reason="docker not on PATH")
def test_run_in_sandbox_no_signal_when_benign(tmp_path: Path) -> None:
    result = run_in_sandbox(
        ["sh", "-c", "echo BENIGN"],
        image="alpine:3.20",
        work_dir=tmp_path,
    )
    assert result.exit_code == 0
    assert result.signal_seen is False
