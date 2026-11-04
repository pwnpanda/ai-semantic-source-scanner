"""Semgrep engine wrapper.

Runs ``semgrep --config=auto --sarif`` against a project. SARIF output is
ingested into the same ``flows`` table the CodeQL engine writes to, with
``engine='semgrep'`` so the hybrid engine can dedupe.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ai_codescan.artifact_id import normalize_artifact_id

_BUNDLED_RULES_DIR = Path(__file__).parent / "semgrep_rules"
"""Directory of project-specific rules shipped with ai-codescan. Always
passed to semgrep alongside ``--config=auto`` so we extend (not replace)
the community ruleset with patterns the OSS pack misses (e.g. CWE-208
timing-attack on env-var secrets)."""
_RULES_ROOT_REGISTRY = "aics-semgrep-rules.json"


def configured_rules_roots(cache_dir: Path) -> list[Path]:
    """Return per-repo Semgrep roots whose promoted rules are active."""
    roots = [cache_dir / ".semgrep"]
    registry = cache_dir / _RULES_ROOT_REGISTRY
    try:
        payload = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return roots
    if isinstance(payload, dict) and payload.get("rules_root"):
        roots.append(Path(str(payload["rules_root"])).expanduser())
    return list(dict.fromkeys(root.resolve() for root in roots))


def register_rules_root(cache_dir: Path, rules_root: Path) -> Path:
    """Record the custom Semgrep root so future scans load its promoted rules."""
    registry = cache_dir / _RULES_ROOT_REGISTRY
    registry.parent.mkdir(parents=True, exist_ok=True)
    temporary = registry.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"rules_root": str(rules_root.expanduser().resolve())}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(registry)
    return registry


def active_rule_dirs(cache_dir: Path) -> list[Path]:
    """Return promoted custom-rule directories; never include ``rules.staged``."""
    active: list[Path] = []
    for root in configured_rules_roots(cache_dir):
        candidate = root.resolve() / "rules"
        if candidate not in active and candidate.is_dir():
            active.append(candidate)
    return active


class SemgrepUnavailableError(RuntimeError):
    """Raised when ``semgrep`` isn't on PATH."""


def is_available() -> bool:
    return shutil.which("semgrep") is not None


def _semgrep_command(
    project_root: Path,
    *,
    cache_dir: Path,
    config: str,
    output_path: Path,
) -> list[str]:
    cmd = [
        "semgrep",
        "scan",
        # Pin the project root to the directory we are scanning. Semgrep
        # otherwise walks up looking for a ``.git`` and switches to
        # ``git ls-files`` target discovery. A stray or broken ``.git``
        # above the cache root (``~/.git`` is a common dotfiles-repo
        # artifact) makes that call exit 128, and semgrep then reports zero
        # targets and zero findings with no error in the SARIF - silently
        # disabling the whole Semgrep layer for every language.
        f"--project-root={project_root}",
        f"--config={config}",
        "--sarif",
        "--output",
        str(output_path),
    ]
    if _BUNDLED_RULES_DIR.is_dir() and any(_BUNDLED_RULES_DIR.glob("*.yaml")):
        cmd.append(f"--config={_BUNDLED_RULES_DIR}")
    for rules_dir in active_rule_dirs(cache_dir):
        has_rules = any(
            path.is_file() and path.suffix in {".yml", ".yaml"} for path in rules_dir.rglob("*")
        )
        if has_rules:
            cmd.append(f"--config={rules_dir}")
    from ai_codescan.proposal_triage import enabled_packs  # noqa: PLC0415

    cmd.extend(f"--config={pack}" for pack in enabled_packs(cache_dir))
    cmd.append(str(project_root))
    return cmd


def _validate_sarif(path: Path, *, project_id: str) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"semgrep produced invalid SARIF for {project_id}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise RuntimeError(f"semgrep produced invalid SARIF for {project_id}")


def _run_semgrep_process(cmd: list[str], *, project_id: str, timeout: int) -> None:
    result = subprocess.run(  # noqa: S603 - argv-only, no shell
        cmd,  # noqa: S607
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode == 0:
        return
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
    raise RuntimeError(
        f"semgrep exited {result.returncode} for {project_id}: {stderr.strip() or 'no stderr'}"
    )


def run_semgrep(
    project_root: Path,
    *,
    cache_dir: Path,
    project_id: str,
    config: str = "auto",
    timeout: int = 600,
) -> Path:
    """Run semgrep against ``project_root``; emit SARIF to the cache.

    Returns the path to the SARIF file. ``config='auto'`` uses Semgrep's
    default rule registry (Semgrep CE; OSS rules only). The bundled
    rules under ``semgrep_rules/`` are appended so security gaps in the
    community pack (e.g. CWE-208 timing-attack on ``process.env``) get
    matched too.

    Phase 3: when the cache_dir contains ``aics-enabled-packs.json``
    (written by `ai_codescan.proposal_triage.enable_pack_for_repo`),
    every pack id listed is passed as an additional ``--config=`` arg so
    the next scan picks up auto-routed packs without manual config.
    """
    if not is_available():
        raise SemgrepUnavailableError(
            "semgrep is not on PATH; pip install semgrep or skip --engine hybrid."
        )
    project_id = normalize_artifact_id(project_id)
    sarif_dir = cache_dir / "semgrep"
    sarif_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = sarif_dir / f"{project_id}.sarif"
    sarif_path.unlink(missing_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=sarif_dir, prefix=f".{project_id}-", suffix=".sarif", delete=False
    ) as temporary_file:
        temporary_path = Path(temporary_file.name)
    temporary_path.unlink()
    cmd = _semgrep_command(
        project_root,
        cache_dir=cache_dir,
        config=config,
        output_path=temporary_path,
    )
    try:
        _run_semgrep_process(cmd, project_id=project_id, timeout=timeout)
        if not temporary_path.is_file():
            raise RuntimeError(f"semgrep did not produce SARIF for {project_id}")
        _validate_sarif(temporary_path, project_id=project_id)
        temporary_path.replace(sarif_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return sarif_path
