"""Finding dataclass + markdown frontmatter (de)serialisation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast, get_args

import yaml

Status = Literal["unverified", "verified", "rejected", "poc_inconclusive"]
Exploitability = Literal["unknown", "demonstrated", "latent"]
_STATUS_VALUES: frozenset[str] = frozenset(get_args(Status))
_EXPLOITABILITY_VALUES: frozenset[str] = frozenset(get_args(Exploitability))


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    nomination_id: str
    flow_id: str
    cwe: str | None
    status: Status
    title: str
    body: str
    candidate_id: str = ""
    exploitability: Exploitability = "unknown"
    unmet_prerequisites: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if any(not isinstance(item, str) or not item.strip() for item in self.unmet_prerequisites):
            raise ValueError("unmet_prerequisites must contain non-empty strings")
        if self.exploitability == "latent" and not self.unmet_prerequisites:
            raise ValueError("a latent finding must record at least one unmet prerequisite")
        if self.exploitability != "latent" and self.unmet_prerequisites:
            raise ValueError("only a latent finding can record unmet prerequisites")


def render_finding(f: Finding) -> str:
    """Render a finding as a markdown document with YAML frontmatter."""
    front = {
        "finding_id": f.finding_id,
        "nomination_id": f.nomination_id,
        "flow_id": f.flow_id,
        "cwe": f.cwe or "",
        "status": f.status,
        "title": f.title,
        "candidate_id": f.candidate_id,
        "exploitability": f.exploitability,
        "unmet_prerequisites": list(f.unmet_prerequisites),
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
    try:
        loaded = yaml.safe_load(front_raw)
    except yaml.YAMLError as exc:
        raise ValueError("invalid YAML frontmatter") from exc
    if loaded is None:
        front = {}
    elif isinstance(loaded, dict):
        front = loaded
    else:
        raise ValueError("finding frontmatter must be a mapping")
    cwe_raw = front.get("cwe")
    raw_status = str(front.get("status", "unverified"))
    if raw_status not in _STATUS_VALUES:
        raise ValueError(f"unknown status {raw_status!r}; expected one of {sorted(_STATUS_VALUES)}")
    status = cast(Status, raw_status)
    raw_exploitability = str(front.get("exploitability", "unknown"))
    if raw_exploitability not in _EXPLOITABILITY_VALUES:
        raise ValueError(
            f"unknown exploitability {raw_exploitability!r}; "
            f"expected one of {sorted(_EXPLOITABILITY_VALUES)}"
        )
    exploitability = cast(Exploitability, raw_exploitability)
    raw_prerequisites = front.get("unmet_prerequisites") or []
    if not isinstance(raw_prerequisites, list) or not all(
        isinstance(item, str) for item in raw_prerequisites
    ):
        raise ValueError("unmet_prerequisites must be a list of strings")
    return Finding(
        finding_id=str(front.get("finding_id", "")),
        nomination_id=str(front.get("nomination_id", "")),
        flow_id=str(front.get("flow_id", "")),
        cwe=str(cwe_raw) if cwe_raw else None,
        status=status,
        title=str(front.get("title", "")),
        body=body,
        candidate_id=str(front.get("candidate_id", "")),
        exploitability=exploitability,
        unmet_prerequisites=tuple(item.strip() for item in raw_prerequisites if item.strip()),
    )
