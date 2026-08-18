"""Tests for ai_codescan.sandbox."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

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


def test_run_in_sandbox_uses_available_credential_helper_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker_config = tmp_path / "docker"
    docker_config.mkdir()
    (docker_config / "config.json").write_text(
        json.dumps(
            {
                "auths": {},
                "credsStore": "desktop",
                "credHelpers": {
                    "available.example": "pass",
                    "missing.example": "desktop",
                },
            }
        ),
        encoding="utf-8",
    )
    observed_config: dict[str, object] = {}
    temporary_config_dir: Path | None = None

    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal temporary_config_dir
        env = cast("dict[str, str]", kwargs.get("env"))
        docker_config_value = env.get("DOCKER_CONFIG")
        assert isinstance(docker_config_value, str)
        temporary_config_dir = Path(docker_config_value)
        observed_config.update(
            json.loads((temporary_config_dir / "config.json").read_text(encoding="utf-8"))
        )
        return subprocess.CompletedProcess([], 0, stdout=DEFAULT_SIGNAL, stderr="")

    def fake_which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in {"docker", "docker-credential-pass"} else None

    monkeypatch.setenv("DOCKER_CONFIG", str(docker_config))
    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_in_sandbox(
        ["python3", "poc.py"],
        image="python:3.13-slim",
        work_dir=tmp_path,
        runtime="docker",
    )

    assert result.exit_code == 0
    assert result.signal_seen is True
    assert observed_config["credsStore"] == "pass"
    assert observed_config["credHelpers"] == {"available.example": "pass"}
    assert temporary_config_dir is not None
    assert not temporary_config_dir.exists()


def test_run_in_sandbox_falls_back_to_file_based_docker_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker_config = tmp_path / "docker"
    docker_config.mkdir()
    (docker_config / "config.json").write_text(
        json.dumps(
            {
                "auths": {"registry.example": {"auth": "encoded"}},
                "credsStore": "desktop",
                "credHelpers": {"registry.example": "desktop"},
            }
        ),
        encoding="utf-8",
    )
    observed_config: dict[str, object] = {}

    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        env = cast("dict[str, str]", kwargs.get("env"))
        docker_config_value = env.get("DOCKER_CONFIG")
        assert isinstance(docker_config_value, str)
        config_path = Path(docker_config_value) / "config.json"
        observed_config.update(json.loads(config_path.read_text(encoding="utf-8")))
        return subprocess.CompletedProcess([], 0, stdout="BENIGN", stderr="")

    monkeypatch.setenv("DOCKER_CONFIG", str(docker_config))
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    monkeypatch.setattr(subprocess, "run", fake_run)

    sandbox_result = run_in_sandbox(
        ["python3", "poc.py"],
        image="python:3.13-slim",
        work_dir=tmp_path,
        runtime="docker",
    )

    assert sandbox_result.exit_code == 0
    assert "credsStore" not in observed_config
    assert "credHelpers" not in observed_config
    assert "auths" in observed_config


def test_run_in_sandbox_removes_missing_registry_credential_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker_config = tmp_path / "docker"
    docker_config.mkdir()
    (docker_config / "config.json").write_text(
        json.dumps(
            {
                "auths": {"registry.example": {"auth": "encoded"}},
                "credHelpers": {"registry.example": "desktop"},
            }
        ),
        encoding="utf-8",
    )
    observed_config: dict[str, object] = {}

    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        env = cast("dict[str, str]", kwargs.get("env"))
        config_path = Path(env["DOCKER_CONFIG"]) / "config.json"
        observed_config.update(json.loads(config_path.read_text(encoding="utf-8")))
        return subprocess.CompletedProcess([], 0, stdout="BENIGN", stderr="")

    monkeypatch.setenv("DOCKER_CONFIG", str(docker_config))
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_in_sandbox(
        ["python3", "poc.py"],
        image="python:3.13-slim",
        work_dir=tmp_path,
        runtime="docker",
    )

    assert result.exit_code == 0
    assert "credHelpers" not in observed_config
    assert "auths" in observed_config


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
