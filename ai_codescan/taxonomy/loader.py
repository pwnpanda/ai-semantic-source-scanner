"""Load and resolve the bug-class taxonomy."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

import yaml


class UnknownBugClassError(ValueError):
    """Raised when a user supplies a name that's not in the taxonomy."""


@dataclass(frozen=True, slots=True)
class BugClass:
    name: str
    cwes: list[str]
    codeql_tags: list[str]
    group: str | None
    aliases: list[str]
    needs_semantic: bool = False


def _yaml_path() -> Path:
    return Path(str(files("ai_codescan.taxonomy").joinpath("bug_classes.yaml")))


def _load_raw() -> dict:
    return yaml.safe_load(_yaml_path().read_text(encoding="utf-8")) or {}


def list_classes() -> list[BugClass]:
    raw = _load_raw()
    out: list[BugClass] = []
    for name, body in raw.items():
        if name == "groups" or not isinstance(body, dict):
            continue
        out.append(
            BugClass(
                name=name,
                cwes=list(body.get("cwes", [])),
                codeql_tags=list(body.get("codeql_tags", [])),
                group=body.get("group"),
                aliases=list(body.get("aliases", [])),
                needs_semantic=bool(body.get("needs_semantic", False)),
            )
        )
    return out


def _alias_index() -> dict[str, str]:
    idx: dict[str, str] = {}
    for klass in list_classes():
        idx[klass.name] = klass.name
        for a in klass.aliases:
            idx[a] = klass.name
    return idx


def _expand_group(name: str, raw_groups: dict) -> list[str]:
    members = raw_groups.get(name, [])
    out: list[str] = []
    for m in members:
        if m.startswith("@"):
            out.extend(_expand_group(m[1:], raw_groups))
        else:
            out.append(m)
    return out


def resolve_classes(tokens: list[str]) -> list[BugClass]:
    """Resolve user-supplied names/aliases/``@group`` tokens to a sorted ``BugClass`` list."""
    raw = _load_raw()
    raw_groups = raw.get("groups", {})
    aliases = _alias_index()
    by_name = {c.name: c for c in list_classes()}

    selected: set[str] = set()
    for raw_token in tokens:
        token = raw_token.strip()
        if not token:
            continue
        if token.startswith("@"):
            for member in _expand_group(token[1:], raw_groups):
                canonical = aliases.get(member)
                if canonical:
                    selected.add(canonical)
            continue
        if token in raw_groups:
            for member in _expand_group(token, raw_groups):
                canonical = aliases.get(member)
                if canonical:
                    selected.add(canonical)
            continue
        canonical = aliases.get(token)
        if not canonical:
            close = difflib.get_close_matches(token, list(aliases), n=1)
            hint = f" Did you mean '{close[0]}'?" if close else ""
            raise UnknownBugClassError(f"Unknown bug class '{token}'.{hint}")
        selected.add(canonical)
    return [by_name[n] for n in sorted(selected)]
