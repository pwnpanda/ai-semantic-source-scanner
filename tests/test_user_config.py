"""Tests for ai_codescan.user_config."""

from pathlib import Path

import pytest

from ai_codescan import user_config


@pytest.fixture
def isolated_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("AICS_CONTAINER_RUNTIME", raising=False)
    monkeypatch.delenv("AICS_POC_LANG", raising=False)
    return tmp_path / "ai-codescan"


def test_load_returns_defaults_when_file_absent(isolated_config_dir: Path) -> None:
    cfg = user_config.load()
    assert cfg.container_runtime == "docker"
    assert cfg.poc_language_preference == "auto"


def test_save_then_load_roundtrips(isolated_config_dir: Path) -> None:
    user_config.save(
        user_config.UserConfig(container_runtime="podman", poc_language_preference="javascript")
    )
    cfg = user_config.load()
    assert cfg.container_runtime == "podman"
    assert cfg.poc_language_preference == "javascript"


def test_invalid_runtime_falls_back_to_docker(isolated_config_dir: Path) -> None:
    isolated_config_dir.mkdir(parents=True, exist_ok=True)
    (isolated_config_dir / "config.yaml").write_text(
        "container_runtime: kubernetes\npoc_language_preference: rust\n",
        encoding="utf-8",
    )
    cfg = user_config.load()
    assert cfg.container_runtime == "docker"
    assert cfg.poc_language_preference == "auto"


def test_env_var_overrides_disk(isolated_config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    user_config.save(user_config.UserConfig(container_runtime="docker"))
    monkeypatch.setenv("AICS_CONTAINER_RUNTIME", "podman")
    monkeypatch.setenv("AICS_POC_LANG", "php")
    cfg = user_config.load()
    assert cfg.container_runtime == "podman"
    assert cfg.poc_language_preference == "php"


def test_config_path_under_xdg_config_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert user_config.config_path() == tmp_path / "ai-codescan" / "config.yaml"
