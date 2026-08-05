"""Joern model extension via a sidecar JSON file.

Phase 5 closes the learning-loop asymmetry from Phase 3: model proposals that
should produce a *Joern* sink (custom HTTP clients, exotic ORM query methods,
framework-specific entry shapes) now have a path. Previously only Semgrep
rules could be auto-generated from proposals; Joern coverage required a
hand-edit to ``engines/joern_queries.sc``.

Phase 5.1 split this into a staged/promoted pair, mirroring Semgrep's
``rules.staged/`` vs ``rules/`` distinction:

- ``aics-joern-extension-packs.staged.json`` — proposed entries that are
  visible in bookkeeping but NOT loaded by Joern at scan time.
- ``aics-joern-extension-packs.json`` — promoted entries that ARE loaded
  by Joern at scan time (the Scala script reads only this file).

``apply_proposal_to_joern(..., staged=True)`` writes to the staged file by
default. ``promote_joern_extension(proposal_id, ...)`` moves an entry from
staged → promoted.

JSON schema (single object):

    {
      "sinks": [
        {
          "language": "python",                  // joern frontend language
          "cwe": "CWE-918",                       // CWE identifier
          "sink_class": "ssrf",                   // taxonomy class
          "pattern": "(?i)^(myfetch|api_call)$",  // Joern call-name regex
          "receiver_regex": "(?i).*\\\\bclient\\\\.",  // OPTIONAL receiver gate
          "proposal_id": "p-1",                   // provenance back to verdict
          "rationale": "..."                     // human-readable
        }
      ]
    }

Receiver regex is optional — when set, the Joern script restricts the call
to those whose ``code`` field matches. This lets a generated Joern model
catch exotic clients without over-matching e.g. ``dict.get``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ai_codescan.model_proposals import ModelProposal

log = logging.getLogger(__name__)

# CWE → Joern sink_class mapping for proposals that don't carry an explicit
# value. Mirrors the taxonomy buckets used inside `joern_queries.sc`. Adding
# a new CWE here means proposals of that shape can auto-route to a Joern
# sink rather than landing as pending custom rules.
_CWE_TO_SINK_CLASS: dict[str, str] = {
    "CWE-22": "fs.read",
    "CWE-78": "cmd.shell",
    "CWE-79": "html.write",
    "CWE-89": "sql.exec",
    "CWE-94": "code.exec",
    "CWE-502": "deser.unsafe",
    "CWE-532": "log.sensitive",
    "CWE-918": "ssrf",
    "CWE-639": "firestore.idor",
}


@dataclass(frozen=True, slots=True)
class JoernExtensionEntry:
    language: str
    cwe: str
    sink_class: str
    pattern: str
    receiver_regex: str = ""
    proposal_id: str = ""
    rationale: str = ""

    def key(self) -> tuple[str, str, str, str]:
        """Identity tuple for idempotency: same key = same entry."""
        return (self.language, self.cwe, self.sink_class, self.pattern)

    def to_jsonable(self) -> dict[str, Any]:
        record = asdict(self)
        # Drop empty optional fields so the on-disk file stays compact.
        if not record["receiver_regex"]:
            record.pop("receiver_regex")
        if not record["rationale"]:
            record.pop("rationale")
        return record


def _sink_class_for_proposal(proposal: ModelProposal) -> str:
    cwe = (proposal.cwe or "").upper()
    return _CWE_TO_SINK_CLASS.get(cwe, "unknown")


def _read_extension_file(path: Path) -> dict[str, Any]:
    """Load the JSON file defensively. Returns {} on missing / malformed."""
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("joern extensions file is not valid JSON: %s", path)
        return {}
    if not isinstance(payload, dict):
        log.warning("joern extensions file root must be an object: %s", path)
        return {}
    return payload


def load_joern_extensions(path: Path) -> list[JoernExtensionEntry]:
    """Parse the sink entries from the extension JSON. Empty on missing or
    malformed — Joern just skips the merge in that case."""
    payload = _read_extension_file(path)
    raw_sinks = payload.get("sinks", [])
    if not isinstance(raw_sinks, list):
        return []
    entries: list[JoernExtensionEntry] = []
    for raw in raw_sinks:
        if not isinstance(raw, dict):
            continue
        pattern = str(raw.get("pattern") or "")
        if not pattern:
            continue
        entries.append(
            JoernExtensionEntry(
                language=str(raw.get("language") or "").lower(),
                cwe=str(raw.get("cwe") or "").upper(),
                sink_class=str(raw.get("sink_class") or "unknown"),
                pattern=pattern,
                receiver_regex=str(raw.get("receiver_regex") or ""),
                proposal_id=str(raw.get("proposal_id") or ""),
                rationale=str(raw.get("rationale") or ""),
            )
        )
    return entries


def staged_path_for(extension_path: Path) -> Path:
    """Return the staged sibling path for a given promoted extension path.

    ``aics-joern-extension-packs.json`` → ``aics-joern-extension-packs.staged.json``.
    Promoted entries land in the input; staged entries live in the sibling
    that Joern does NOT read at scan time.
    """
    return extension_path.with_suffix(".staged.json")


def apply_proposal_to_joern(
    proposal: ModelProposal,
    *,
    extension_path: Path,
    staged: bool = True,
) -> JoernExtensionEntry:
    """Append a sink entry derived from `proposal` to the extension file.

    Phase 5.1: writes to ``staged_path_for(extension_path)`` by default
    (mirrors Semgrep's ``rules.staged/`` flow). Set ``staged=False`` to
    write directly to the promoted file Joern reads at scan time.

    Idempotent: re-applying the same proposal does not duplicate the entry.
    Raises ``ValueError`` when the proposal has an empty ``sink_pattern`` —
    Joern needs a concrete regex to match.
    """
    if not proposal.sink_pattern:
        raise ValueError(
            f"proposal {proposal.proposal_id} has empty sink_pattern; "
            "cannot generate a Joern sink without a concrete regex"
        )
    # ``receiver_regex`` is the canonical field for the Joern call-site
    # predicate. ``sanitizer_pattern`` keeps its Semgrep meaning (negative
    # pattern) and is never read here.
    receiver = proposal.receiver_regex
    entry = JoernExtensionEntry(
        language=(proposal.language or "").lower(),
        cwe=(proposal.cwe or "").upper(),
        sink_class=_sink_class_for_proposal(proposal),
        pattern=proposal.sink_pattern,
        receiver_regex=receiver,
        proposal_id=proposal.proposal_id,
        rationale=proposal.rationale,
    )
    target_path = staged_path_for(extension_path) if staged else extension_path
    target_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _read_extension_file(target_path)
    existing_raw = payload.get("sinks", [])
    existing: list[dict[str, Any]] = (
        [item for item in existing_raw if isinstance(item, dict)]
        if isinstance(existing_raw, list)
        else []
    )
    new_key = entry.key()
    # Deduplicate by key; re-apply with a different proposal_id is still
    # idempotent. We do refresh proposal_id/rationale so the latest verdict
    # gets credit.
    kept = [
        item
        for item in existing
        if (
            str(item.get("language") or "").lower(),
            str(item.get("cwe") or "").upper(),
            str(item.get("sink_class") or ""),
            str(item.get("pattern") or ""),
        )
        != new_key
    ]
    kept.append(entry.to_jsonable())
    payload["sinks"] = kept
    target_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return entry


def promote_joern_extension(
    proposal_id: str,
    *,
    extension_path: Path,
) -> JoernExtensionEntry | None:
    """Move a staged extension entry into the promoted file.

    The Joern script reads only the promoted file at scan time. Until this
    function runs, a staged entry is bookkeeping only — visible via
    `load_joern_extensions(staged_path_for(extension_path))` but invisible
    to Joern. Returns the moved entry, or None when no staged entry exists
    for the given proposal_id.
    """
    staged_path = staged_path_for(extension_path)
    staged_payload = _read_extension_file(staged_path)
    raw_sinks = staged_payload.get("sinks", [])
    if not isinstance(raw_sinks, list):
        return None
    moving: dict[str, Any] | None = None
    remaining: list[dict[str, Any]] = []
    for item in raw_sinks:
        if not isinstance(item, dict):
            continue
        if str(item.get("proposal_id") or "") == proposal_id and moving is None:
            moving = item
        else:
            remaining.append(item)
    if moving is None:
        return None
    # Write the remaining staged entries back.
    staged_payload["sinks"] = remaining
    staged_path.write_text(
        json.dumps(staged_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # Append the moving entry to the promoted file (dedupe by key).
    extension_path.parent.mkdir(parents=True, exist_ok=True)
    promoted_payload = _read_extension_file(extension_path)
    promoted_raw = promoted_payload.get("sinks", [])
    existing = (
        [item for item in promoted_raw if isinstance(item, dict)]
        if isinstance(promoted_raw, list)
        else []
    )
    moving_key = (
        str(moving.get("language") or "").lower(),
        str(moving.get("cwe") or "").upper(),
        str(moving.get("sink_class") or ""),
        str(moving.get("pattern") or ""),
    )
    kept = [
        item
        for item in existing
        if (
            str(item.get("language") or "").lower(),
            str(item.get("cwe") or "").upper(),
            str(item.get("sink_class") or ""),
            str(item.get("pattern") or ""),
        )
        != moving_key
    ]
    kept.append(moving)
    promoted_payload["sinks"] = kept
    extension_path.write_text(
        json.dumps(promoted_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return JoernExtensionEntry(
        language=str(moving.get("language") or "").lower(),
        cwe=str(moving.get("cwe") or "").upper(),
        sink_class=str(moving.get("sink_class") or "unknown"),
        pattern=str(moving.get("pattern") or ""),
        receiver_regex=str(moving.get("receiver_regex") or ""),
        proposal_id=str(moving.get("proposal_id") or ""),
        rationale=str(moving.get("rationale") or ""),
    )


def validate_extension_path(path: Path) -> Path | None:
    """Return the canonical absolute path when the file exists and parses,
    otherwise None. Callers pass the return value as the AICS_JOERN_EXTENSIONS
    env var so the Joern script knows where to look — None means "no
    extensions, skip the merge"."""
    if not path.is_file():
        return None
    payload = _read_extension_file(path)
    if not payload or not isinstance(payload.get("sinks"), list):
        return None
    return path.resolve()
