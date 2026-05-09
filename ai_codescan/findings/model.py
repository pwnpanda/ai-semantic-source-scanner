"""Finding dataclass + markdown frontmatter (de)serialisation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast, get_args

import yaml

Status = Literal["unverified", "verified", "rejected", "poc_inconclusive"]
_STATUS_VALUES: frozenset[str] = frozenset(get_args(Status))


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    nomination_id: str
    flow_id: str
    cwe: str | None
    status: Status
    title: str
    body: str


def render_finding(f: Finding) -> str:
    """Render a finding as a markdown document with YAML frontmatter."""
    front = {
        "finding_id": f.finding_id,
        "nomination_id": f.nomination_id,
        "flow_id": f.flow_id,
        "cwe": f.cwe or "",
        "status": f.status,
        "title": f.title,
    }
    yaml_block = yaml.safe_dump(front, sort_keys=True).strip()
    return f"---\n{yaml_block}\n---\n\n{f.body}"


def parse_finding(md: str) -> Finding:
    """Parse a finding from a markdown document with YAML frontmatter."""
    if not md.startswith("---\n"):
        raise ValueError("missing frontmatter")
    end = md.find("\n---\n", 4)
    if end == -1:
        raise ValueError("unterminated frontmatter")
    front_raw = md[4:end]
    body = md[end + 5 :].lstrip("\n")
    front = yaml.safe_load(front_raw) or {}
    cwe_raw = front.get("cwe")
    raw_status = str(front.get("status", "unverified"))
    if raw_status not in _STATUS_VALUES:
        raise ValueError(f"unknown status {raw_status!r}; expected one of {sorted(_STATUS_VALUES)}")
    status = cast(Status, raw_status)
    return Finding(
        finding_id=str(front.get("finding_id", "")),
        nomination_id=str(front.get("nomination_id", "")),
        flow_id=str(front.get("flow_id", "")),
        cwe=str(cwe_raw) if cwe_raw else None,
        status=status,
        title=str(front.get("title", "")),
        body=body,
    )
