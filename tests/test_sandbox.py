"""Tests for ai_codescan.sandbox."""

import shutil
from pathlib import Path

import pytest

from ai_codescan.sandbox import (
    DEFAULT_SIGNAL,
    SandboxResult,
    SandboxUnavailableError,
    UnsupportedPocLanguageError,
    image_for_lang,
    profile_for_extension,
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
    assert image_for_lang("python") == "python:3.13-slim"


def test_image_for_lang_php() -> None:
    assert image_for_lang("php") == "php:8.3-cli-alpine"


def test_image_for_lang_default_falls_back_to_python() -> None:
    # Unknown languages fall back to Python (default PoC interpreter).
    assert image_for_lang("rust") == "python:3.13-slim"


def test_profile_for_lang_returns_extension_and_interpreter() -> None:
    js = profile_for_lang("javascript")
    assert js.extension == ".js"
    assert js.interpreter == "node"
    php = profile_for_lang("php")
    assert php.extension == ".php"


def test_profile_for_extension_python() -> None:
    p = profile_for_extension(".py")
    assert p.name == "python"
    assert p.image == "python:3.13-slim"
    assert p.local_supported is True


def test_profile_for_extension_javascript() -> None:
    p = profile_for_extension(".js")
    assert p.name == "javascript"
    assert p.image == "node:22-alpine"
    assert p.interpreter == "node"
    # .mjs is also routed to node.
    assert profile_for_extension(".mjs").name == "javascript"


def test_profile_for_extension_typescript_uses_tsx() -> None:
    p = profile_for_extension(".ts")
    assert p.image == "node:22-alpine"
    # `npx --yes tsx` runs the script without a precompile step.
    assert "tsx" in p.interpreter


def test_profile_for_extension_go() -> None:
    p = profile_for_extension(".go")
    assert p.image == "golang:1.22-alpine"
    assert p.interpreter == "go run"


def test_profile_for_extension_ruby() -> None:
    p = profile_for_extension(".rb")
    assert p.image == "ruby:3.3-alpine"
    assert p.interpreter == "ruby"


def test_profile_for_extension_java() -> None:
    p = profile_for_extension(".java")
    assert p.image == "openjdk:21-slim"
    assert p.interpreter == "java"


def test_profile_for_extension_php() -> None:
    p = profile_for_extension(".php")
    assert p.image == "php:8.3-cli-alpine"
    assert p.interpreter == "php"


def test_profile_for_extension_shell() -> None:
    sh = profile_for_extension(".sh")
    assert sh.image == "bash:5"
    assert sh.interpreter == "bash"
    assert profile_for_extension(".bash").name == "shell"


def test_profile_for_extension_case_insensitive() -> None:
    assert profile_for_extension(".JS").name == "javascript"


def test_profile_for_extension_rejects_unknown() -> None:
    with pytest.raises(UnsupportedPocLanguageError) as info:
        profile_for_extension(".rs")
    msg = str(info.value)
    assert ".rs" in msg
    # Error message lists supported extensions so the user can pivot.
    assert ".py" in msg


def test_only_python_supports_local_execution() -> None:
    # Local (--no-sandbox) fallback requires the toolchain on the host.
    # We only promise that for Python; everything else is Docker-required.
    assert profile_for_lang("python").local_supported is True
    for lang in ("javascript", "typescript", "java", "go", "ruby", "php", "shell", "csharp"):
        assert profile_for_lang(lang).local_supported is False, lang


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
