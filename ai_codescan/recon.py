"""Hunt-recon: nominate sibling files worth a second scan (Phase 13).

Two of `evilsocket/audit`'s pillars are about *where to look next* rather
than how to judge a finding:

- **Git-history recon** — past security-fix commits point at files that
  were once vulnerable; sibling files sharing the same idiom often still
  are.
- **Feedback loop** — once a finding is confirmed (a reviewer said
  true-positive and an adversarial challenger could not disprove it),
  the same bug class is worth hunting in its sibling files too.

Both reduce to the same output: a deduplicated list of files worth
re-hunting, with a reason. This module produces `recon_hints.jsonl`; the
nominator / miss-finder can prioritise those files on the next pass.

Recall-first: recon only ever *adds* candidates to look at. It never
removes or down-ranks anything.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

import duckdb

log = logging.getLogger(__name__)

# Commit-message substrings that mark a security fix. Matched case-insensitively
# against `git log --grep`. Kept broad — recall-first, a false hint just means
# one extra file gets re-hunted.
_SECURITY_FIX_KEYWORDS = (
    "security",
    "vulnerab",
    "cve-",
    "cwe-",
    "injection",
    "xss",
    "ssrf",
    "csrf",
    "rce",
    "sanitiz",
    "escape",
    "auth bypass",
    "exploit",
    "path traversal",
    "deserializ",
)

# Extensions recon considers "code" — siblings only make sense within these.
_CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".mjs",
        ".cjs",
        ".java",
        ".kt",
        ".go",
        ".rb",
        ".php",
        ".cs",
    }
)


@dataclass(frozen=True, slots=True)
class ReconHint:
    """One file worth re-hunting, with provenance."""

    file: str
    reason: str
    source: str  # "git-history" | "feedback-loop"

    def to_jsonable(self) -> dict[str, str]:
        return asdict(self)


def _run_git(repo_path: Path, *args: str) -> str:
    """Run a read-only git command; return stdout, or '' on any failure."""
    try:
        result = subprocess.run(  # noqa: S603 - argv-only, no shell
            ["git", "-C", str(repo_path), *args],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log.warning("git recon command failed: %s", exc)
        return ""
    return result.stdout if result.returncode == 0 else ""


def security_fix_files(repo_path: Path, *, max_commits: int = 200) -> set[str]:
    """Files touched by commits whose message looks like a security fix.

    Scans the most recent ``max_commits`` security-keyworded commits. Paths
    are repo-relative POSIX strings. Empty set when the dir isn't a git repo
    or git isn't available — recon then simply contributes no git hints.
    """
    grep_args: list[str] = []
    for keyword in _SECURITY_FIX_KEYWORDS:
        grep_args += ["--grep", keyword]
    out = _run_git(
        repo_path,
        "log",
        "--no-merges",
        "-i",
        *grep_args,
        f"--max-count={max_commits}",
        "--name-only",
        "--pretty=format:",
    )
    files: set[str] = set()
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if line and Path(line).suffix in _CODE_SUFFIXES:
            files.add(line)
    return files


def sibling_files(target: str, *, source_root: Path) -> set[str]:
    """Files in the same directory as ``target`` sharing its extension.

    A sibling is the cheapest "same idiom" heuristic — code in one directory
    tends to share framework, conventions, and bugs. Returns repo-relative
    POSIX paths, excluding ``target`` itself.
    """
    rel = Path(target)
    suffix = rel.suffix
    if suffix not in _CODE_SUFFIXES:
        return set()
    dir_abs = source_root / rel.parent
    if not dir_abs.is_dir():
        return set()
    out: set[str] = set()
    for entry in dir_abs.iterdir():
        if entry.is_file() and entry.suffix == suffix:
            rel_sibling = (rel.parent / entry.name).as_posix()
            if rel_sibling != rel.as_posix():
                out.add(rel_sibling)
    return out


def confirmed_finding_files(conn: duckdb.DuckDBPyConnection) -> set[str]:
    """Source files of findings that survived review + adversarial challenge.

    A finding counts as confirmed when its review verdict is
    ``true-positive`` AND no adversarial challenger disputed it (a row in
    `adversarial_challenges` with result ``disputed`` cancels it). Returns
    repo-relative-ish paths as stored on the verdict's `source_path`.
    """
    tables = {
        str(r[0])
        for r in conn.execute("SELECT table_name FROM information_schema.tables").fetchall()
    }
    if "review_verdicts" not in tables:
        return set()
    disputed: set[str] = set()
    if "adversarial_challenges" in tables:
        disputed = {
            str(r[0])
            for r in conn.execute(
                "SELECT finding_id FROM adversarial_challenges WHERE result = 'disputed'"
            ).fetchall()
        }
    rows = conn.execute(
        "SELECT finding_id, source_path FROM review_verdicts WHERE verdict = 'true-positive'"
    ).fetchall()
    return {str(src) for fid, src in rows if src and str(fid) not in disputed}


def collect_recon_hints(
    repo_path: Path,
    *,
    source_root: Path,
    conn: duckdb.DuckDBPyConnection | None = None,
) -> list[ReconHint]:
    """Build the deduplicated re-hunt list from both recon sources.

    ``repo_path`` is the original git checkout (for `git log`); ``source_root``
    is the snapshot dir recon resolves sibling files against. ``conn`` is the
    DuckDB index — when None, only git-history recon runs.
    """
    by_file: dict[str, ReconHint] = {}

    def _add(file: str, reason: str, source: str) -> None:
        # First reason wins; git-history and feedback-loop rarely collide,
        # and when they do either reason is fine.
        by_file.setdefault(file, ReconHint(file=file, reason=reason, source=source))

    for fixed in sorted(security_fix_files(repo_path)):
        _add(fixed, "file was touched by a past security-fix commit", "git-history")
        for sibling in sorted(sibling_files(fixed, source_root=source_root)):
            _add(
                sibling,
                f"shares a directory with {fixed}, a past security-fix file",
                "git-history",
            )

    if conn is not None:
        for confirmed in sorted(confirmed_finding_files(conn)):
            for sibling in sorted(sibling_files(confirmed, source_root=source_root)):
                _add(
                    sibling,
                    f"shares a directory with {confirmed}, a confirmed finding",
                    "feedback-loop",
                )

    return [by_file[key] for key in sorted(by_file)]


def write_recon_hints(hints: list[ReconHint], *, out_path: Path) -> Path:
    """Write hints as JSONL; the nominator / miss-finder can prioritise them."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for hint in hints:
            f.write(json.dumps(hint.to_jsonable(), sort_keys=True))
            f.write("\n")
    return out_path
