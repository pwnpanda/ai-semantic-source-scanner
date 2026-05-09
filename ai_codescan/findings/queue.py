"""Generate and parse findings_queue.md."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_codescan.gate import parse_nominations

_QUEUE_LINE = re.compile(
    r"^- \[(?P<state>[ x!])\] (?P<id>N-[\w-]+) \| (?P<project>[^|]+) \| "
    r"(?P<vector>[^|]+) \| (?P<loc>[^|]+)\s*$"
)


@dataclass(frozen=True, slots=True)
class QueueItem:
    nomination_id: str
    project: str
    vector: str
    loc: str


def accepted_nominations_to_queue(nominations_md: str) -> list[QueueItem]:
    """Filter nominations whose ``y/n:`` slot is ``y`` and project to QueueItem."""
    return [
        QueueItem(
            nomination_id=n.nomination_id,
            project=n.project,
            vector=n.vector,
            loc=n.loc,
        )
        for n in parse_nominations(nominations_md)
        if n.decision == "y"
    ]


def render_queue(items: list[QueueItem]) -> str:
    """Render a list of queue items as the findings_queue.md body."""
    lines = ["# Findings queue", ""]
    for it in items:
        lines.append(f"- [ ] {it.nomination_id} | {it.project} | {it.vector} | {it.loc}")
    return "\n".join(lines) + "\n"


def parse_queue(md: str) -> list[QueueItem]:
    """Parse findings_queue.md back into QueueItems."""
    out: list[QueueItem] = []
    for line in md.splitlines():
        m = _QUEUE_LINE.match(line)
        if not m:
            continue
        out.append(
            QueueItem(
                nomination_id=m.group("id"),
                project=m.group("project").strip(),
                vector=m.group("vector").strip(),
                loc=m.group("loc").strip(),
            )
        )
    return out
