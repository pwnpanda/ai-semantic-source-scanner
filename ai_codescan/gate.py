"""Parse and mutate ``nominations.md``: HITL gate-1 logic."""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEADER = re.compile(
    r"^- \[(?P<state>[ x!])\] (?P<id>N-[\w-]+) \| "
    r"(?P<project>[^|]+) \| (?P<vector>[^|]+) \| "
    r"(?P<loc>[^|]+) \| rec: (?P<rec>high|med|low) \| y/n: ?(?P<decision>[yn]?)\s*$"
)

_STREAM_C_HEADER = "## Stream C"
_CANDIDATE_LINE = re.compile(r"^\s+Candidate:\s+`?(?P<id>[A-Za-z0-9_-]+)`?\s*$")


@dataclass(frozen=True, slots=True)
class Nomination:
    nomination_id: str
    state: str
    project: str
    vector: str
    loc: str
    rec: str
    decision: str
    line_idx: int
    raw_line: str
    candidate_id: str = ""


@dataclass(frozen=True, slots=True)
class StreamCExtension:
    nomination_id: str
    yaml_body: str


def parse_nominations(md: str) -> list[Nomination]:
    """Parse all `- [ ] N-XXX | ...` lines into ``Nomination`` records."""
    out: list[Nomination] = []
    lines = md.splitlines()
    for idx, line in enumerate(lines):
        m = _HEADER.match(line)
        if not m:
            continue
        candidate_id = ""
        for body_line in lines[idx + 1 :]:
            if _HEADER.match(body_line) or body_line.startswith("## "):
                break
            if candidate_match := _CANDIDATE_LINE.match(body_line):
                candidate_id = candidate_match.group("id")
                break
        out.append(
            Nomination(
                nomination_id=m.group("id"),
                state=m.group("state"),
                project=m.group("project").strip(),
                vector=m.group("vector").strip(),
                loc=m.group("loc").strip(),
                rec=m.group("rec"),
                decision=m.group("decision") or "",
                line_idx=idx,
                raw_line=line,
                candidate_id=candidate_id,
            )
        )
    return out


def apply_yes_to_all(md: str) -> str:
    """Append ``y`` to every nomination whose ``y/n:`` slot is empty."""
    new_lines: list[str] = []
    for line in md.splitlines():
        m = _HEADER.match(line)
        if not m or m.group("decision"):
            new_lines.append(line)
            continue
        new_lines.append(line.rstrip() + "y")
    return "\n".join(new_lines) + ("\n" if md.endswith("\n") else "")


def selected_extensions(md: str) -> list[StreamCExtension]:
    """Return YAML bodies of Stream C nominations marked ``y``."""
    items = parse_nominations(md)
    out: list[StreamCExtension] = []
    lines = md.splitlines()
    for nom in items:
        header_idx = max(
            (i for i, line in enumerate(lines[: nom.line_idx]) if line.startswith("## ")),
            default=-1,
        )
        if header_idx < 0:
            continue
        if not lines[header_idx].startswith(_STREAM_C_HEADER):
            continue
        if nom.decision != "y":
            continue
        yaml_lines: list[str] = []
        in_block = False
        for after in lines[nom.line_idx + 1 :]:
            if after.startswith("- [") and _HEADER.match(after):
                break
            if after.startswith("```yaml"):
                in_block = True
                continue
            if in_block:
                if after.startswith("```"):
                    break
                yaml_lines.append(after)
        out.append(
            StreamCExtension(nomination_id=nom.nomination_id, yaml_body="\n".join(yaml_lines))
        )
    return out
