"""CodeQL data-extension sidecar (Phase 9).

Mirrors the Phase 5 Joern extension mechanism for CodeQL. The user-facing
shape is the same: a JSON sidecar in the repo cache that holds
``(language, cwe, sink_pattern, ...)`` entries. The translator emits
CodeQL data-extension YAML files at scan time so the CodeQL pack picks
up additional sinks without editing the pack source.

CodeQL data extensions are YAML files placed in a packs's extension dir.
Each extension declares one or more model rows for an "extensible" predicate
(e.g. `sinkModel` for a taint-tracking query). The format is well-documented;
this module produces minimal sink-model rows.

Architecture:

- ``aics-codeql-extension-packs.json`` lives in the repo cache (same dir
  as ``aics-joern-extension-packs.json``).
- When CodeQL runs, the prep step writes the corresponding YAML extension
  files into ``<repo_dir>/codeql-extensions/<language>/`` and points
  `codeql database analyze` at them via ``--additional-packs``.
- The CLI surface is parallel to the Joern one: ``apply --engine codeql``
  appends to the JSON; staged/promoted distinction is reused.

This is the scaffolding pass — the YAML emission is implemented and unit
tested, but the live integration with `codeql database analyze` is NOT
auto-wired yet because every CodeQL query suite expects a different
extension pack name and the surface to thread that through `engines/codeql.py`
is large. Documented as a manual run for now; users opt in by setting
``AICS_CODEQL_EXTENSIONS_DIR`` to point at the YAML dir and passing
``--additional-packs`` themselves.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from ai_codescan.model_proposals import ModelProposal

log = logging.getLogger(__name__)

# Map CWE → CodeQL "extensible predicate" name. Each language pack has its
# own predicate, e.g. python `sinkModel`, java `sinkModel`. We keep the
# mapping deliberately narrow — only the predicates that map cleanly to
# our taxonomy. Future CWEs require an entry here.
_CWE_TO_PREDICATE: dict[str, str] = {
    "CWE-89": "sinkModel",
    "CWE-78": "sinkModel",
    "CWE-79": "sinkModel",
    "CWE-22": "sinkModel",
    "CWE-918": "sinkModel",
    "CWE-94": "sinkModel",
    "CWE-502": "sinkModel",
    "CWE-532": "sinkModel",
}


@dataclass(frozen=True, slots=True)
class CodeqlExtensionEntry:
    language: str
    cwe: str
    package: str  # e.g. ``requests`` for Python, ``org.springframework`` for Java
    type_name: str  # e.g. ``Session`` or ``RestTemplate``
    method_name: str  # the sink method
    kind: str = "sink"  # codeql predicate kind
    proposal_id: str = ""
    rationale: str = ""

    def to_jsonable(self) -> dict[str, Any]:
        record = asdict(self)
        if not record["rationale"]:
            record.pop("rationale")
        return record


def _read_extension_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("codeql extensions file is not valid JSON: %s", path)
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def staged_path_for(extension_path: Path) -> Path:
    """Return the staged sibling path for a promoted CodeQL extension file.

    ``aics-codeql-extension-packs.json`` → ``aics-codeql-extension-packs.staged.json``.
    Mirrors the Joern staged/promoted split — promoted entries are read by
    the CodeQL data-extension renderer at scan time; staged entries are
    bookkeeping only.
    """
    return extension_path.with_suffix(".staged.json")


def _entry_key(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(item.get("language") or "").lower(),
        str(item.get("cwe") or "").upper(),
        str(item.get("package") or ""),
        str(item.get("type_name") or ""),
        str(item.get("method_name") or ""),
    )


def apply_proposal_to_codeql(
    proposal: ModelProposal,
    *,
    extension_path: Path,
    staged: bool = True,
) -> CodeqlExtensionEntry:
    """Append a CodeQL extension entry derived from `proposal`.

    The proposal's ``sink_pattern`` is used as the method name. The
    ``framework`` and ``language`` together pick a sensible package/type
    name; for cases where the proposal doesn't carry enough info, defaults
    are used and the entry is flagged for review in its rationale.

    When ``staged=True`` (default) the entry lands in the staged sibling
    file (mirrors Joern + Semgrep staging). The renderer reads only the
    promoted file when emitting YAML — staged entries stay invisible to
    `codeql database analyze` until promoted.
    """
    if not proposal.sink_pattern:
        raise ValueError(
            f"proposal {proposal.proposal_id} has empty sink_pattern; "
            "CodeQL needs a method name to model"
        )
    entry = CodeqlExtensionEntry(
        language=(proposal.language or "").lower(),
        cwe=(proposal.cwe or "").upper(),
        package=proposal.framework or "_unknown_",
        type_name=proposal.bug_class or "_AutoModel_",
        method_name=proposal.sink_pattern,
        proposal_id=proposal.proposal_id,
        rationale=proposal.rationale,
    )
    target_path = staged_path_for(extension_path) if staged else extension_path
    target_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _read_extension_file(target_path)
    raw_sinks = payload.get("sinks", [])
    existing: list[dict[str, Any]] = (
        [item for item in raw_sinks if isinstance(item, dict)]
        if isinstance(raw_sinks, list)
        else []
    )
    new_key = (entry.language, entry.cwe, entry.package, entry.type_name, entry.method_name)
    kept = [item for item in existing if _entry_key(item) != new_key]
    kept.append(entry.to_jsonable())
    payload["sinks"] = kept
    target_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return entry


def promote_codeql_extension(
    proposal_id: str,
    *,
    extension_path: Path,
) -> CodeqlExtensionEntry | None:
    """Move a staged CodeQL extension entry into the promoted file.

    Parallel to ``promote_joern_extension``. Returns the moved entry, or
    None when no staged entry matches the given proposal_id.
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
    staged_payload["sinks"] = remaining
    staged_path.write_text(
        json.dumps(staged_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    extension_path.parent.mkdir(parents=True, exist_ok=True)
    promoted_payload = _read_extension_file(extension_path)
    promoted_raw = promoted_payload.get("sinks", [])
    existing = (
        [item for item in promoted_raw if isinstance(item, dict)]
        if isinstance(promoted_raw, list)
        else []
    )
    moving_key = _entry_key(moving)
    kept = [item for item in existing if _entry_key(item) != moving_key]
    kept.append(moving)
    promoted_payload["sinks"] = kept
    extension_path.write_text(
        json.dumps(promoted_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return CodeqlExtensionEntry(
        language=str(moving.get("language") or "").lower(),
        cwe=str(moving.get("cwe") or "").upper(),
        package=str(moving.get("package") or "_unknown_"),
        type_name=str(moving.get("type_name") or "_AutoModel_"),
        method_name=str(moving.get("method_name") or ""),
        proposal_id=str(moving.get("proposal_id") or ""),
        rationale=str(moving.get("rationale") or ""),
    )


def render_codeql_yaml_extensions(
    extension_path: Path,
    *,
    out_dir: Path,
) -> list[Path]:
    """Emit per-language YAML data-extension files from the JSON sidecar.

    Each language gets its own ``<out_dir>/<language>/extension.yml`` with
    rows for the `sinkModel` (or whatever predicate the CWE maps to).
    Returns the list of written paths. Missing or empty input → empty list.
    """
    payload = _read_extension_file(extension_path)
    raw_sinks = payload.get("sinks", [])
    if not isinstance(raw_sinks, list):
        return []
    by_language: dict[str, list[dict[str, Any]]] = {}
    for item in raw_sinks:
        if not isinstance(item, dict):
            continue
        lang = str(item.get("language") or "").lower()
        if not lang:
            continue
        by_language.setdefault(lang, []).append(item)

    written: list[Path] = []
    for language, entries in by_language.items():
        lang_dir = out_dir / language
        lang_dir.mkdir(parents=True, exist_ok=True)
        rows: list[list[str | bool]] = []
        for e in entries:
            cwe = str(e.get("cwe") or "").upper()
            predicate = _CWE_TO_PREDICATE.get(cwe, "sinkModel")
            rows.append(
                [
                    str(e.get("package") or "_unknown_"),
                    str(e.get("type_name") or "_AutoModel_"),
                    True,  # subtypes
                    str(e.get("method_name") or ""),
                    "",  # signature (empty = match any signature)
                    "",  # ext
                    "Argument[0]",  # default sink input — arg 0
                    predicate,
                    "manual",  # source-kind tag
                ]
            )
        document = {
            "extensions": [
                {
                    "addsTo": {
                        "pack": f"codeql/{language}-all",
                        "extensible": "sinkModel",
                    },
                    "data": rows,
                }
            ]
        }
        target = lang_dir / "extension.yml"
        target.write_text(
            yaml.safe_dump(document, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
        # CodeQL recognises a directory as a model pack when it contains a
        # ``codeql-pack.yml`` declaring ``library: true`` + ``dataExtensions``.
        # Without this manifest, ``--model-packs <dir>`` is silently ignored
        # by recent CodeQL CLI versions, so the YAML rows never make it into
        # the analysis. Emit the manifest alongside the extension file.
        manifest = lang_dir / "codeql-pack.yml"
        manifest.write_text(
            yaml.safe_dump(
                {
                    "name": f"aics/codeql-extensions-{language}",
                    "version": "0.0.1",
                    "library": True,
                    "extensionTargets": {f"codeql/{language}-all": "*"},
                    "dataExtensions": ["extension.yml"],
                },
                sort_keys=False,
                default_flow_style=False,
            ),
            encoding="utf-8",
        )
        written.append(target)
    return written
