"""Tests for ai_codescan.llm."""

import pytest

from ai_codescan.llm import (
    GateOverrides,
    LLMConfig,
    UnknownProviderError,
    build_argv,
    is_available,
    parse_provider_model,
)


def test_llm_config_rejects_unknown_provider() -> None:
    with pytest.raises(UnknownProviderError):
        LLMConfig(provider="not-a-thing")


def test_build_argv_claude_no_model() -> None:
    assert build_argv(LLMConfig(provider="claude"), "hi") == ["claude", "-p", "hi"]


def test_build_argv_claude_with_model() -> None:
    assert build_argv(LLMConfig(provider="claude", model="opus"), "hi") == [
        "claude",
        "--model",
        "opus",
        "-p",
        "hi",
    ]


def test_build_argv_gemini_with_model() -> None:
    assert build_argv(LLMConfig(provider="gemini", model="gemini-2.5-pro"), "hi") == [
        "gemini",
        "-m",
        "gemini-2.5-pro",
        "-p",
        "hi",
    ]


def test_build_argv_codex_with_model() -> None:
    argv = build_argv(LLMConfig(provider="codex", model="o3"), "hi")
    assert argv == ["codex", "exec", "-c", 'model="o3"', "hi"]


def test_build_argv_codex_no_model() -> None:
    assert build_argv(LLMConfig(provider="codex"), "hi") == ["codex", "exec", "hi"]


def test_parse_provider_model_just_provider() -> None:
    cfg = parse_provider_model("claude")
    assert cfg.provider == "claude"
    assert cfg.model is None


def test_parse_provider_model_with_model() -> None:
    cfg = parse_provider_model("claude:opus")
    assert cfg.provider == "claude"
    assert cfg.model == "opus"


def test_parse_provider_model_rejects_unknown() -> None:
    with pytest.raises(UnknownProviderError):
        parse_provider_model("not-real:model")


def test_gate_overrides_falls_back_to_default() -> None:
    default = LLMConfig(provider="claude")
    overrides = GateOverrides()
    assert overrides.for_gate("gate_1", default) is default


def test_gate_overrides_returns_per_gate() -> None:
    default = LLMConfig(provider="claude")
    g1 = LLMConfig(provider="gemini", model="gemini-2.5-pro")
    overrides = GateOverrides(by_gate={"gate_1": g1})
    assert overrides.for_gate("gate_1", default) is g1
    assert overrides.for_gate("nominate", default) is default


def test_is_available_for_unknown_provider() -> None:
    assert is_available("nonexistent-cli") is False


def test_is_available_returns_bool_for_known() -> None:
    # Just verifying it returns bool — actual presence depends on the host.
    assert isinstance(is_available("claude"), bool)
