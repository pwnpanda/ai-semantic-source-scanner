"""Hardened Docker sandbox runner for PoC execution.

Defaults block the network, drop all capabilities, mount the work directory
read-only, and limit memory / CPU / pids. Use only with explicitly written
PoC scripts produced by the validator skill — never run untrusted code from
the target repo here.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_SIGNAL = "OK_VULN"

_DOCKER_HARDENING_FLAGS: tuple[str, ...] = (
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


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _ensure_docker() -> None:
    if shutil.which("docker") is None:
        raise SandboxUnavailableError(
            "docker is not on PATH; install Docker or pass --no-sandbox to skip."
        )


def run_in_sandbox(
    argv: list[str],
    *,
    image: str,
    work_dir: Path,
    timeout: int = DEFAULT_TIMEOUT_SEC,
    signal_pattern: str = DEFAULT_SIGNAL,
) -> SandboxResult:
    """Run ``argv`` inside a hardened ``docker run`` container.

    ``work_dir`` is mounted read-only at ``/work``. ``argv`` is passed straight
    to the entrypoint. Stdout is scanned for ``signal_pattern``; presence
    flips :class:`SandboxResult.signal_seen` to ``True``.
    """
    _ensure_docker()
    docker_argv = [
        "docker",
        "run",
        *_DOCKER_HARDENING_FLAGS,
        "-v",
        f"{work_dir}:/work:ro",
        "--workdir",
        "/work",
        image,
        *argv,
    ]
    timed_out = False
    try:
        proc = subprocess.run(  # noqa: S603 - argv-only, no shell
            docker_argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
        duration = float(timeout)  # subprocess.run doesn't expose duration; placeholder
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = _decode(exc.stdout)
        stderr = _decode(exc.stderr)
        duration = float(timeout)

    return SandboxResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_sec=duration,
        signal_seen=signal_pattern in stdout,
        timed_out=timed_out,
    )


def image_for_lang(lang: str) -> str:
    """Return a sensible default image for the given language tag."""
    lang_lc = lang.lower()
    if lang_lc in {"javascript", "typescript", "node", "ts", "js"}:
        return "node:22-alpine"
    if lang_lc in {"python", "py"}:
        return "python:3.13-alpine"
    return "alpine:3.20"
