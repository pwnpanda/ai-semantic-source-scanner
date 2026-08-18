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
    cmd = [
        "semgrep",
        "scan",
        f"--config={config}",
        "--sarif",
        "--output",
        str(temporary_path),
    ]
    if _BUNDLED_RULES_DIR.is_dir() and any(_BUNDLED_RULES_DIR.glob("*.yaml")):
        cmd.append(f"--config={_BUNDLED_RULES_DIR}")
    for rules_dir in active_rule_dirs(cache_dir):
        if any(
            path.is_file() and path.suffix in {".yml", ".yaml"} for path in rules_dir.rglob("*")
        ):
            cmd.append(f"--config={rules_dir}")
    # Local-import to avoid a circular dependency at module load time —
    # proposal_triage is a higher-level module that itself imports model_proposals.
    from ai_codescan.proposal_triage import enabled_packs  # noqa: PLC0415

    for pack in enabled_packs(cache_dir):
        cmd.append(f"--config={pack}")
    cmd.append(str(project_root))
    try:
        result = subprocess.run(  # noqa: S603 - argv-only, no shell
            cmd,  # noqa: S607
            check=False,
            capture_output=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
            raise RuntimeError(
                f"semgrep exited {result.returncode} for {project_id}: "
                f"{stderr.strip() or 'no stderr'}"
            )
        if not temporary_path.is_file():
            raise RuntimeError(f"semgrep did not produce SARIF for {project_id}")
        payload = json.loads(temporary_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
            raise RuntimeError(f"semgrep produced invalid SARIF for {project_id}")
        temporary_path.replace(sarif_path)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"semgrep produced invalid SARIF for {project_id}") from exc
    finally:
        temporary_path.unlink(missing_ok=True)
    return sarif_path
