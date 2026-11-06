"""Semgrep engine wrapper.

Runs ``semgrep --config=auto --sarif`` against a project. SARIF output is
ingested into the same ``flows`` table the CodeQL engine writes to, with
``engine='semgrep'`` so the hybrid engine can dedupe.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from ai_codescan.artifact_id import normalize_artifact_id

log = logging.getLogger(__name__)

DEFAULT_REGISTRY_RULESET = "p/default"
"""Registry ruleset pinned into a local snapshot on first use.

``--config=auto`` resolves against the live Semgrep registry on every run, so
the same code at the same scanner commit produces different findings on
different days. That silently changes the candidate set a scan is built on.
Snapshotting a concrete ruleset makes prep reproducible and lets later runs
work offline; pass ``config='auto'`` explicitly to opt back into live rules.
"""

_REGISTRY_SNAPSHOT_NAME = "registry-snapshot.yaml"
_REGISTRY_URL = "https://semgrep.dev/c/{ref}"
_REGISTRY_FETCH_TIMEOUT = 180

_BUNDLED_RULES_DIR = Path(__file__).parent / "semgrep_rules"
"""Directory of project-specific rules shipped with ai-codescan. Always
passed to semgrep alongside ``--config=auto`` so we extend (not replace)
the community ruleset with patterns the OSS pack misses (e.g. CWE-208
timing-attack on env-var secrets)."""
_RULES_ROOT_REGISTRY = "aics-semgrep-rules.json"


def registry_snapshot_path(cache_dir: Path) -> Path:
    """Return the per-repo pinned copy of the registry ruleset."""
    return cache_dir / "semgrep" / _REGISTRY_SNAPSHOT_NAME


def _fetch_registry_ruleset(ref: str) -> str:
    url = _REGISTRY_URL.format(ref=ref)
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https registry URL: {url!r}")
    # S310: scheme is checked immediately above; the URL is built from a
    # constant template and a ruleset identifier, never from scan input.
    with urllib.request.urlopen(url, timeout=_REGISTRY_FETCH_TIMEOUT) as response:  # noqa: S310
        return response.read().decode("utf-8")


def ensure_registry_snapshot(
    cache_dir: Path,
    *,
    ruleset: str = DEFAULT_REGISTRY_RULESET,
    refresh: bool = False,
) -> Path | None:
    """Return a pinned local copy of ``ruleset``, downloading it once.

    Returns ``None`` when no snapshot exists and the download fails, so the
    caller can fall back to the live registry rather than failing the scan.
    Refreshing rewrites the snapshot, which changes the prep fingerprint and
    correctly invalidates downstream stages.
    """
    snapshot = registry_snapshot_path(cache_dir)
    if snapshot.is_file() and not refresh:
        return snapshot
    try:
        payload = _fetch_registry_ruleset(ruleset)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        if snapshot.is_file():
            log.warning("semgrep registry refresh failed (%s); keeping existing snapshot", exc)
            return snapshot
        log.warning(
            "could not fetch semgrep ruleset %s (%s); falling back to the live registry, "
            "which makes this prep non-reproducible",
            ruleset,
            exc,
        )
        return None
    if not payload.strip():
        log.warning("semgrep registry returned an empty ruleset for %s; ignoring", ruleset)
        return snapshot if snapshot.is_file() else None
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    temporary = snapshot.with_suffix(".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(snapshot)
    return snapshot


def config_is_pinned(config: str) -> bool:
    """Return True when ``config`` names a local ruleset file rather than the registry.

    A registry reference (``auto``, ``p/ci``, a URL) can resolve differently
    on every run, which is what makes a scan's findings non-reproducible.
    """
    if not config or config == "auto" or "://" in config:
        return False
    return Path(config).is_file()


def resolve_config(cache_dir: Path, config: str, *, refresh: bool = False) -> str:
    """Resolve the ``--config`` value, preferring the pinned snapshot.

    An explicit value (including ``'auto'``) is honoured as-is; only the
    default empty value opts into pinning.
    """
    if config:
        return config
    snapshot = ensure_registry_snapshot(cache_dir, refresh=refresh)
    return str(snapshot) if snapshot is not None else "auto"


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
    config: str = "",
    timeout: int = 600,
) -> Path:
    """Run semgrep against ``project_root``; emit SARIF to the cache.

    Returns the path to the SARIF file. By default the registry ruleset is
    pinned to a local snapshot (see :func:`ensure_registry_snapshot`) so the
    same code at the same scanner commit yields the same findings; pass
    ``config='auto'`` to use the live registry instead, accepting that prep
    is then not reproducible. The bundled rules under ``semgrep_rules/`` are
    appended so security gaps in the community pack (e.g. CWE-208
    timing-attack on ``process.env``) get matched too.

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
        config=resolve_config(cache_dir, config),
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
