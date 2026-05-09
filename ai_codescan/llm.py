"""Provider-agnostic LLM CLI invocation.

Supports ``claude``, ``gemini``, and ``codex`` CLIs. The user picks which
binary to invoke via ``--llm-provider`` and (optionally) ``--llm-model``.
Each gate / HITL step can override the provider and model independently
of the scan-wide default.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Final

PROVIDERS: Final = ("claude", "gemini", "codex")
"""Supported LLM CLI providers (must match the binary name on PATH)."""


class UnknownProviderError(ValueError):
    """Raised when a provider name isn't in :data:`PROVIDERS`."""


@dataclass(frozen=True, slots=True)
class LLMConfig:
    """Selected provider + optional model for one invocation."""

    provider: str
    model: str | None = None

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise UnknownProviderError(
                f"Unknown provider '{self.provider}'. Choose from: {', '.join(PROVIDERS)}."
            )


@dataclass(frozen=True, slots=True)
class GateOverrides:
    """Per-gate overrides keyed by gate name (e.g. ``"gate_1"``)."""

    by_gate: dict[str, LLMConfig] = field(default_factory=dict)

    def for_gate(self, gate: str, default: LLMConfig) -> LLMConfig:
        return self.by_gate.get(gate, default)


def is_available(provider: str) -> bool:
    """Return True when the provider's CLI binary is on PATH."""
    if provider not in PROVIDERS:
        return False
    return shutil.which(provider) is not None


def build_argv(config: LLMConfig, prompt: str) -> list[str]:
    """Return the argv list for ``config`` + ``prompt``.

    - claude: ``claude [--model X] -p <prompt>``
    - gemini: ``gemini [-m X] -p <prompt>``
    - codex:  ``codex exec [-c model=X] <prompt>``
    """
    if config.provider == "claude":
        argv = ["claude"]
        if config.model:
            argv += ["--model", config.model]
        argv += ["-p", prompt]
        return argv

    if config.provider == "gemini":
        argv = ["gemini"]
        if config.model:
            argv += ["-m", config.model]
        argv += ["-p", prompt]
        return argv

    if config.provider == "codex":
        argv = ["codex", "exec"]
        if config.model:
            argv += ["-c", f'model="{config.model}"']
        argv.append(prompt)
        return argv

    raise UnknownProviderError(f"build_argv: unknown provider '{config.provider}'.")


def parse_provider_model(spec: str) -> LLMConfig:
    """Parse ``"provider"`` or ``"provider:model"`` into :class:`LLMConfig`.

    Examples:
      - ``"claude"``           → ``LLMConfig("claude")``
      - ``"claude:opus"``      → ``LLMConfig("claude", "opus")``
      - ``"gemini:gemini-2.5-pro"`` → ``LLMConfig("gemini", "gemini-2.5-pro")``
    """
    if ":" not in spec:
        return LLMConfig(provider=spec.strip())
    provider, _, model = spec.partition(":")
    return LLMConfig(provider=provider.strip(), model=model.strip() or None)
