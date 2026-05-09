"""Diff our bug-class taxonomy against the locally-installed CodeQL packs.

CodeQL ships query metadata in ``~/.codeql/packages/<pack>/<ver>/**/*.qhelp``
and ``*.ql`` headers; each query carries a list of ``@tags`` like
``security/cwe/cwe-079``. We collect those tags, compare against the
``codeql_tags`` declared in ``bug_classes.yaml``, and report which CodeQL
tags are unknown to our taxonomy.

Use cases:

- ``ai-codescan taxonomy diff`` — print missing tags + YAML stubs.
- ``ai-codescan taxonomy diff --apply`` — auto-append stub entries to the
  YAML for human review.

Stale-detection: ``mark_taxonomy_checked`` / ``stale_after_days`` let prep
print a one-line "taxonomy may be stale" banner once a week.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ai_codescan.taxonomy.loader import _yaml_path, list_classes
from ai_codescan.user_config import _config_dir

# Match tag tokens directly. CodeQL .ql files use the comment block:
#   * @tags security
#   *       security/cwe/cwe-079
#   *       external/cwe/cwe-079
# Each tag is a slash-separated path; we capture any token starting with
# ``security/`` because that's the namespace our taxonomy cares about.
_TAG_TOKEN_RE = re.compile(r"\b(security/[A-Za-z0-9._/\-]+)")
_NAME_FROM_TAG = re.compile(r"security/cwe/cwe-0*([0-9]+)")
_LAST_CHECK_FILE_NAME = "taxonomy_last_check.txt"

_DEFAULT_STALE_DAYS = 7


def _codeql_pack_dirs() -> list[Path]:
    base = Path.home() / ".codeql" / "packages"
    if not base.is_dir():
        return []
    out: list[Path] = []
    for pack in base.iterdir():
        if not pack.is_dir():
            continue
        for ver in pack.iterdir():
            if ver.is_dir():
                out.append(ver)
    return out


def _collect_codeql_tags(roots: list[Path]) -> set[str]:
    tags: set[str] = set()
    for root in roots:
        for path in root.rglob("*.ql"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            tags.update(_TAG_TOKEN_RE.findall(text))
    return tags


def _known_tags() -> set[str]:
    out: set[str] = set()
    for klass in list_classes():
        out.update(klass.codeql_tags)
    return out


@dataclass(frozen=True, slots=True)
class TaxonomyDiff:
    missing_tags: list[str] = field(default_factory=list)
    suggested_stubs_yaml: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.missing_tags


def diff_against_installed_codeql() -> TaxonomyDiff:
    """Return tags present in installed CodeQL packs but missing from our YAML."""
    pack_roots = _codeql_pack_dirs()
    if not pack_roots:
        return TaxonomyDiff()
    found = _collect_codeql_tags(pack_roots)
    missing = sorted(found - _known_tags())
    if not missing:
        return TaxonomyDiff(missing_tags=[])

    stubs: list[str] = ["# Auto-generated stubs — review and rename before keeping.\n"]
    for tag in missing:
        m = _NAME_FROM_TAG.search(tag)
        if m:
            cwe_num = int(m.group(1))
            slug = f"cwe-{cwe_num}"
            stubs.append(
                f"{slug}:\n"
                f"  cwes: [CWE-{cwe_num}]\n"
                f"  codeql_tags: [{tag}]\n"
                f"  group: TODO\n\n"
            )
        else:
            slug = tag.replace("/", "-").replace(".", "-")
            stubs.append(
                f"{slug}:\n  cwes: []\n  codeql_tags: [{tag}]\n  group: TODO\n\n"
            )

    return TaxonomyDiff(missing_tags=missing, suggested_stubs_yaml="".join(stubs))


def apply_diff(diff: TaxonomyDiff) -> int:
    """Append suggested stubs to ``bug_classes.yaml`` (preserves the existing groups block).

    Returns the count of entries appended.
    """
    if diff.is_empty:
        return 0
    yaml_path = _yaml_path()
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    groups = raw.pop("groups", None)
    raw_text = yaml_path.read_text(encoding="utf-8")
    # Strip any pre-existing groups block before appending.
    if "\ngroups:\n" in raw_text:
        body, _, _ = raw_text.partition("\ngroups:\n")
        raw_text = body.rstrip() + "\n"
    appended = raw_text.rstrip() + "\n\n" + diff.suggested_stubs_yaml.rstrip() + "\n"
    if groups:
        appended += "\ngroups:\n" + yaml.safe_dump({"groups": groups}, default_flow_style=False)[
            len("groups:\n") :
        ]
    yaml_path.write_text(appended, encoding="utf-8")
    return len(diff.missing_tags)


# ---------------------------------------------------------------------------
# Stale-detection helpers
# ---------------------------------------------------------------------------


def _last_check_file() -> Path:
    return _config_dir() / _LAST_CHECK_FILE_NAME


def mark_taxonomy_checked() -> None:
    p = _last_check_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"), encoding="utf-8")


def days_since_last_check() -> int | None:
    p = _last_check_file()
    if not p.is_file():
        return None
    try:
        last = _dt.datetime.fromisoformat(p.read_text(encoding="utf-8").strip())
    except ValueError:
        return None
    if last.tzinfo is None:
        last = last.replace(tzinfo=_dt.UTC)
    delta = _dt.datetime.now(_dt.UTC) - last
    return int(delta.total_seconds() // 86400)


def is_stale(*, threshold_days: int = _DEFAULT_STALE_DAYS) -> bool:
    """Return True when more than ``threshold_days`` have passed since last check."""
    days = days_since_last_check()
    return days is None or days >= threshold_days


def maybe_run_periodic_check() -> TaxonomyDiff | None:
    """Run the diff if the last check is stale; cheap when CodeQL isn't installed."""
    if not is_stale():
        return None
    diff = diff_against_installed_codeql()
    mark_taxonomy_checked()
    return diff
