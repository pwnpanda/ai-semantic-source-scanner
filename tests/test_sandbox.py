"""Tests for ai_codescan.sandbox."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.sandbox import (
    DEFAULT_SIGNAL,
    SandboxResult,
    SandboxUnavailableError,
    image_for_lang,
    profile_for_lang,
    run_in_sandbox,
    runtime_binary,
)


def _has_docker() -> bool:
    return shutil.which("docker") is not None


def test_image_for_lang_node() -> None:
    assert image_for_lang("javascript") == "node:22-alpine"
    assert image_for_lang("TypeScript") == "node:22-alpine"


def test_image_for_lang_python() -> None:
    assert image_for_lang("python") == "python:3.13-alpine"


def test_image_for_lang_php() -> None:
    assert image_for_lang("php") == "php:8-alpine"


def test_image_for_lang_default_falls_back_to_python() -> None:
    # Unknown languages fall back to Python (default PoC interpreter).
    assert image_for_lang("rust") == "python:3.13-alpine"


def test_profile_for_lang_returns_extension_and_interpreter() -> None:
    js = profile_for_lang("javascript")
    assert js.extension == ".js"
    assert js.interpreter == "node"
    php = profile_for_lang("php")
    assert php.extension == ".php"


def test_runtime_binary_rejects_none() -> None:
    with pytest.raises(SandboxUnavailableError):
        runtime_binary("none")


def test_runtime_binary_rejects_unknown() -> None:
    with pytest.raises(SandboxUnavailableError):
        runtime_binary("kubernetes")


def test_run_in_sandbox_raises_when_runtime_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(SandboxUnavailableError):
        run_in_sandbox(["echo", "hi"], image="alpine:3.20", work_dir=tmp_path, runtime="docker")


@pytest.mark.integration
@pytest.mark.skipif(not _has_docker(), reason="docker not on PATH")
def test_run_in_sandbox_captures_signal(tmp_path: Path) -> None:
    result = run_in_sandbox(
        ["sh", "-c", f"echo {DEFAULT_SIGNAL}"],
        image="alpine:3.20",
        work_dir=tmp_path,
        runtime="docker",
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
        runtime="docker",
    )
    assert result.exit_code == 0
    assert result.signal_seen is False
