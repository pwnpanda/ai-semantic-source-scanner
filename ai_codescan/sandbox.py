"""Hardened sandbox runner for PoC execution.

Supports Docker, Podman, or no-sandbox (local) modes. The runtime is picked
from :mod:`ai_codescan.user_config` (set at install time, overridable per-run
with the ``--no-sandbox`` flag or the ``AICS_CONTAINER_RUNTIME`` env var).

Defaults block the network, drop all capabilities, mount the work directory
read-only, and limit memory / CPU / pids. Use only with explicitly written
PoC scripts produced by the validator skill — never run untrusted code from
the target repo here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_codescan.user_config import load as load_user_config

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_SIGNAL = "OK_VULN"

# Hardening flags shared by docker and podman (compatible CLI surface).
_HARDENING_FLAGS: tuple[str, ...] = (
    "--rm",
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--read-only",
    "--tmpfs=/tmp:size=128m,mode=1777",
    "--memory=512m",
    "--cpus=1",
    "--pids-limit=64",
)
_DOCKER_HELPER_FALLBACKS: tuple[str, ...] = (
    "secretservice",
    "pass",
    "osxkeychain",
    "wincred",
    "desktop",
)


class SandboxUnavailableError(RuntimeError):
    """Raised when no sandbox runtime is available on PATH."""


@dataclass(frozen=True, slots=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float
    signal_seen: bool
    timed_out: bool
    runtime: str = "docker"


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def configured_runtime() -> str:
    """Return the runtime selected at install time (``docker``/``podman``/``none``)."""
    return load_user_config().container_runtime


def runtime_binary(name: str) -> str:
    """Return the binary path for ``name`` (``docker`` or ``podman``)."""
    if name == "none":
        raise SandboxUnavailableError(
            "container runtime is set to 'none'; PoC validation requires docker or podman."
        )
    if name not in {"docker", "podman"}:
        raise SandboxUnavailableError(f"unknown runtime: {name!r}")
    if shutil.which(name) is None:
        raise SandboxUnavailableError(
            f"{name} is not on PATH; install it or run `bash scripts/install.sh` to pick a runtime."
        )
    return name


def _run_container_command(
    container_argv: list[str],
    *,
    timeout: int,
    signal_pattern: str,
    runtime: str,
    env: dict[str, str] | None = None,
) -> SandboxResult:
    try:
        proc = subprocess.run(  # noqa: S603 - argv-only, no shell
            container_argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return SandboxResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_sec=float(timeout),
            signal_seen=signal_pattern in proc.stdout,
            timed_out=False,
            runtime=runtime,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _decode(exc.stdout)
        return SandboxResult(
            exit_code=124,
            stdout=stdout,
            stderr=_decode(exc.stderr),
            duration_sec=float(timeout),
            signal_seen=signal_pattern in stdout,
            timed_out=True,
            runtime=runtime,
        )


def _load_docker_config() -> tuple[Path, dict[str, object]] | None:
    configured_dir = os.environ.get("DOCKER_CONFIG")
    config_dir = Path(configured_dir).expanduser() if configured_dir else Path.home() / ".docker"
    config_path = config_dir / "config.json"
    try:
        parsed = json.loads(config_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if not isinstance(parsed, dict):
        return None
    return config_path, {str(key): value for key, value in parsed.items()}


def _helper_available(helper: str) -> bool:
    return shutil.which(f"docker-credential-{helper}") is not None


def _fallback_helper() -> str | None:
    return next((helper for helper in _DOCKER_HELPER_FALLBACKS if _helper_available(helper)), None)


def _fallback_docker_config(config: dict[str, object]) -> dict[str, object] | None:
    updated = config.copy()
    changed = False
    configured_helper = config.get("credsStore")
    if isinstance(configured_helper, str) and not _helper_available(configured_helper):
        fallback_helper = _fallback_helper()
        if fallback_helper:
            updated["credsStore"] = fallback_helper
        else:
            updated.pop("credsStore", None)
        changed = True

    configured_registry_helpers = config.get("credHelpers")
    if isinstance(configured_registry_helpers, dict):
        available_registry_helpers = {
            str(registry): helper
            for registry, helper in configured_registry_helpers.items()
            if isinstance(helper, str) and _helper_available(helper)
        }
        if len(available_registry_helpers) != len(configured_registry_helpers):
            changed = True
            if available_registry_helpers:
                updated["credHelpers"] = available_registry_helpers
            else:
                updated.pop("credHelpers", None)
    return updated if changed else None


@contextmanager
def _docker_environment() -> Iterator[dict[str, str] | None]:
    loaded = _load_docker_config()
    if loaded is None:
        yield None
        return
    _config_path, config = loaded
    fallback_config = _fallback_docker_config(config)
    if fallback_config is None:
        yield None
        return
    with TemporaryDirectory(prefix="ai-codescan-docker-") as docker_config:
        fallback_path = Path(docker_config) / "config.json"
        fallback_path.write_text(json.dumps(fallback_config), encoding="utf-8")
        fallback_path.chmod(0o600)
        env = os.environ.copy()
        env["DOCKER_CONFIG"] = docker_config
        yield env


def run_in_sandbox(  # noqa: PLR0913 - kw-only args mirror the CLI surface
    argv: list[str],
    *,
    image: str,
    work_dir: Path,
    timeout: int = DEFAULT_TIMEOUT_SEC,
    signal_pattern: str = DEFAULT_SIGNAL,
    runtime: str | None = None,
) -> SandboxResult:
    """Run ``argv`` inside a hardened container using the configured runtime.

    ``work_dir`` is mounted read-only at ``/work``. ``argv`` is passed straight
    to the entrypoint. Stdout is scanned for ``signal_pattern``; presence
    flips :class:`SandboxResult.signal_seen` to ``True``. ``runtime`` defaults
    to the value stored at install time.
    """
    chosen = runtime or configured_runtime()
    binary = runtime_binary(chosen)

    container_argv = [
        binary,
        "run",
        *_HARDENING_FLAGS,
        "-v",
        f"{work_dir}:/work:ro",
        "--workdir",
        "/work",
        image,
        *argv,
    ]
    if chosen != "docker":
        return _run_container_command(
            container_argv,
            timeout=timeout,
            signal_pattern=signal_pattern,
            runtime=chosen,
        )
    with _docker_environment() as env:
        return _run_container_command(
            container_argv,
            timeout=timeout,
            signal_pattern=signal_pattern,
            runtime=chosen,
            env=env,
        )


# ---------------------------------------------------------------------------
# Language → image / interpreter mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LanguageProfile:
    """How to run a PoC written in a given language.

    ``interpreter`` is the argv-prefix (split on whitespace) that runs the
    script inside the container; the script path is appended by the caller.
    ``local_supported`` flags whether the ``--no-sandbox`` fallback is allowed
    — only Python is supported locally; everything else requires Docker or
    Podman because we can't assume the host has the toolchain installed.
    """

    name: str  # canonical lang
    extension: str  # ".py" / ".js" / …
    image: str  # default container image
    interpreter: str  # entrypoint argv inside the image (whitespace-split)
    local_supported: bool = False


_PROFILES: dict[str, LanguageProfile] = {
    "python": LanguageProfile("python", ".py", "python:3.13-slim", "python3", local_supported=True),
    "javascript": LanguageProfile("javascript", ".js", "node:22-alpine", "node"),
    # TypeScript runs through tsx (https://tsx.is) — no compile step required.
    "typescript": LanguageProfile("typescript", ".ts", "node:22-alpine", "npx --yes tsx"),
    # JEP 330 single-file source-code execution; needs JDK >= 11.
    "java": LanguageProfile("java", ".java", "openjdk:21-slim", "java"),
    "go": LanguageProfile("go", ".go", "golang:1.22-alpine", "go run"),
    "ruby": LanguageProfile("ruby", ".rb", "ruby:3.3-alpine", "ruby"),
    "php": LanguageProfile("php", ".php", "php:8.3-cli-alpine", "php"),
    # .NET 8 doesn't yet support file-based apps (`dotnet run path.cs`); that
    # arrives in .NET 10 (preview at time of writing). Keep the profile so a
    # PoC that ships its own .csproj can still be wired up via the LLM, but
    # the validator route flags it as unsupported below — see ``ext_to_profile``.
    "csharp": LanguageProfile("csharp", ".cs", "mcr.microsoft.com/dotnet/sdk:8.0", "dotnet run"),
    "shell": LanguageProfile("shell", ".sh", "bash:5", "bash"),
}


_LANG_ALIASES: dict[str, str] = {
    "python": "python",
    "py": "python",
    "javascript": "javascript",
    "node": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "java": "java",
    "go": "go",
    "golang": "go",
    "ruby": "ruby",
    "rb": "ruby",
    "php": "php",
    "csharp": "csharp",
    "cs": "csharp",
    "dotnet": "csharp",
    "shell": "shell",
    "sh": "shell",
    "bash": "shell",
}


# Extension → canonical language. Drives PoC routing in the validator.
# The .cs entry is intentionally omitted: file-based execution needs .NET 10
# (we're on 8). PoCs that need C# must ship as a csproj — track as TODO.
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "shell",
    ".bash": "shell",
}


class UnsupportedPocLanguageError(ValueError):
    """Raised when a PoC file's extension has no registered language profile."""


def profile_for_lang(lang: str) -> LanguageProfile:
    """Return the language profile for ``lang`` (case-insensitive); python fallback."""
    canonical = _LANG_ALIASES.get(lang.lower(), "python")
    return _PROFILES[canonical]


def profile_for_extension(extension: str) -> LanguageProfile:
    """Return the language profile for a file extension (e.g. ``.js``).

    Raises :class:`UnsupportedPocLanguageError` for extensions we don't route.
    Always pass the leading dot — that's what :attr:`pathlib.Path.suffix` returns.
    """
    canonical = _EXT_TO_LANG.get(extension.lower())
    if canonical is None:
        supported = ", ".join(sorted(_EXT_TO_LANG))
        raise UnsupportedPocLanguageError(
            f"no PoC language profile for extension {extension!r}; "
            f"supported extensions: {supported}"
        )
    return _PROFILES[canonical]


def image_for_lang(lang: str) -> str:
    """Backward-compat shim: return just the default image for ``lang``."""
    return profile_for_lang(lang).image
