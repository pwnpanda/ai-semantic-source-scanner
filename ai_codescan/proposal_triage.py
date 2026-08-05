"""Auto-route model proposals to community Semgrep packs or custom rules.

Phase 3 single-command flow: when `ingest_miss_reviews` writes a proposal,
`triage_and_route` decides whether to:

1. **Enable a community Semgrep pack** for `(cwe, language)` pairs that match
   well-known stdlib patterns (e.g. `(CWE-89, python)` → `p/python.lang.security`).
   These are auto-applied — community packs ship with their own test fixtures
   so the paired-target gate is not enforced.
2. **Leave the proposal pending** for `model-proposals apply` (the custom
   per-repo rule generation path with the paired-target gate).

The mapping is deterministic. LLM-assisted routing (ask the model "is this a
stdlib pattern or repo-specific?") is the upgrade path when the deterministic
map proves wrong — see `memory/proposal-triage-llm-routing.md` for the design.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import duckdb

from ai_codescan.codeql_extensions import apply_proposal_to_codeql
from ai_codescan.joern_extensions import apply_proposal_to_joern
from ai_codescan.model_proposals import ModelProposal, record_proposal_decision

if TYPE_CHECKING:
    from collections.abc import Callable

_PACK_FILENAME = "aics-enabled-packs.json"
_JOERN_EXTENSIONS_FILENAME = "aics-joern-extension-packs.json"
_CODEQL_EXTENSIONS_FILENAME = "aics-codeql-extension-packs.json"

# Deterministic (cwe, language) → community pack mapping. Adding a pair here
# means proposals of that shape get auto-routed; removing means they stay
# pending for custom rule generation. Keep the map narrow — over-routing to
# packs imports their FP shape into the user's scan.
_PACK_MAP: dict[tuple[str, str], str] = {
    ("CWE-89", "python"): "p/python.lang.security.injection.sql",
    ("CWE-89", "javascript"): "p/javascript.lang.security.audit.sql-injection",
    ("CWE-78", "python"): "p/python.lang.security.audit.dangerous-system-call",
    ("CWE-78", "javascript"): "p/javascript.lang.security.audit.detect-child-process",
    ("CWE-79", "python"): "p/python.flask.security.xss",
    ("CWE-79", "javascript"): "p/javascript.express.security",
    ("CWE-918", "python"): "p/python.flask.security.audit.ssrf",
    ("CWE-22", "python"): "p/python.lang.security.audit.path-traversal",
    ("CWE-502", "python"): "p/python.lang.security.deserialization",
    ("CWE-94", "python"): "p/python.lang.security.audit.eval-detected",
}


def pack_for_proposal(proposal: ModelProposal) -> str | None:
    """Return the community Semgrep pack id for this proposal, or None.

    A None return means the proposal is repo-specific enough that a custom
    rule (via `apply_proposal_to_semgrep`) is the right answer.
    """
    cwe = (proposal.cwe or "").upper()
    language = (proposal.language or "").lower()
    return _PACK_MAP.get((cwe, language))


def enable_pack_for_repo(pack: str, *, repo_dir: Path) -> Path:
    """Append a pack id to the project-local enabled-packs registry.

    The registry is a JSON list at `<repo_dir>/aics-enabled-packs.json`.
    `run_semgrep` reads this file and passes each entry as `--config=<pack>`
    so the next scan picks up the new pack without further user action.
    Idempotent: re-enabling the same pack is a no-op.
    """
    repo_dir.mkdir(parents=True, exist_ok=True)
    registry = repo_dir / _PACK_FILENAME
    enabled: list[str]
    if registry.is_file():
        try:
            existing = json.loads(registry.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
        enabled = [str(item) for item in existing] if isinstance(existing, list) else []
    else:
        enabled = []
    if pack not in enabled:
        enabled.append(pack)
        enabled.sort()
        registry.write_text(json.dumps(enabled, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry


def enabled_packs(repo_dir: Path) -> list[str]:
    """Read the enabled-packs registry; returns [] when missing."""
    registry = repo_dir / _PACK_FILENAME
    if not registry.is_file():
        return []
    try:
        payload = json.loads(registry.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    return [str(item) for item in payload]


def triage_and_route(  # noqa: PLR0912, PLR0915 - three-engine routing dispatch
    proposals: list[ModelProposal],
    *,
    conn: duckdb.DuckDBPyConnection | None,
    repo_dir: Path,
    llm_route: Callable[[ModelProposal], str | None] | None = None,
) -> dict[str, int]:
    """For each proposal, auto-enable a community pack, write a Joern sink
    extension, or mark the proposal pending for a custom Semgrep rule.

    Routing priority:

    1. If ``proposal.target_engine == "joern"`` AND a ``sink_pattern`` is set
       → write a Joern extension entry (Phase 5 path).
    2. Else if ``(cwe, language)`` maps to a known community Semgrep pack
       → enable the pack in the repo registry.
    3. Else → leave the proposal ``pending`` for ``model-proposals apply``.

    Returns ``{"routed_to_pack": N, "routed_to_joern": M,
    "routed_to_codeql": L, "pending_custom_rule": K}``.
    """
    routed_to_pack = 0
    routed_to_joern = 0
    routed_to_codeql = 0
    pending_custom_rule = 0
    now = datetime.now(tz=UTC).isoformat()
    for proposal in proposals:
        if (proposal.target_engine or "").lower() == "codeql" and proposal.sink_pattern:
            # Phase 10: CodeQL pack extension auto-routing. Mirrors the
            # Joern branch — the entry lands in the staged sibling so the
            # user runs `model-proposals promote <id> --engine codeql`
            # (or re-applies with `--promote`) once reviewed.
            codeql_path = repo_dir / _CODEQL_EXTENSIONS_FILENAME
            try:
                codeql_entry = apply_proposal_to_codeql(
                    proposal,
                    extension_path=codeql_path,
                    staged=True,
                )
            except ValueError:
                pending_custom_rule += 1
                if conn is not None:
                    record_proposal_decision(
                        conn,
                        proposal_id=proposal.proposal_id,
                        decision="pending",
                        engine="codeql",
                    )
                continue
            routed_to_codeql += 1
            codeql_staged = codeql_path.with_suffix(".staged.json")
            if conn is not None:
                record_proposal_decision(
                    conn,
                    proposal_id=proposal.proposal_id,
                    decision="pending",  # staged, awaiting promote
                    engine=f"codeql-extension-staged:{codeql_entry.language}",
                    eval_positive=proposal.eval_positive,
                    eval_negative=proposal.eval_negative,
                    applied_path=str(codeql_staged),
                )
            continue
        if (proposal.target_engine or "").lower() == "joern" and proposal.sink_pattern:
            # Phase 5.1: auto-routed Joern proposals land in the .staged
            # file. The user runs `model-proposals promote <id> --engine
            # joern` once they've reviewed the rule. This keeps the
            # single-command UX without auto-applying un-vetted LLM
            # output to scans.
            extension_path = repo_dir / _JOERN_EXTENSIONS_FILENAME
            try:
                entry = apply_proposal_to_joern(
                    proposal,
                    extension_path=extension_path,
                    staged=True,
                )
            except ValueError:
                # Empty sink_pattern (defensive — already guarded above).
                pending_custom_rule += 1
                if conn is not None:
                    record_proposal_decision(
                        conn,
                        proposal_id=proposal.proposal_id,
                        decision="pending",
                        engine="joern",
                    )
                continue
            routed_to_joern += 1
            staged_path = extension_path.with_suffix(".staged.json")
            if conn is not None:
                record_proposal_decision(
                    conn,
                    proposal_id=proposal.proposal_id,
                    decision="pending",  # staged, awaiting promote
                    engine=f"joern-extension-staged:{entry.sink_class}",
                    eval_positive=proposal.eval_positive,
                    eval_negative=proposal.eval_negative,
                    applied_path=str(staged_path),
                )
            continue
        pack = pack_for_proposal(proposal)
        # Phase 7: when the deterministic pack map returns None and an
        # LLM router is configured, ask the LLM. The LLM may return
        # ``pack:<id>``, ``custom-rule``, ``joern``, or None. Only the
        # ``pack:<id>`` answer changes routing here; the others are
        # passed through to the existing pending-custom-rule path
        # (which the user reviews via `model-proposals apply`).
        if pack is None and llm_route is not None:
            try:
                hint = llm_route(proposal)
            except Exception:  # noqa: BLE001 - LLM failures must not break triage
                hint = None
            if hint and hint.startswith("pack:") and len(hint) > len("pack:"):
                pack = hint[len("pack:") :]
        if pack:
            applied_path = str(enable_pack_for_repo(pack, repo_dir=repo_dir))
            routed_to_pack += 1
            if conn is not None:
                record_proposal_decision(
                    conn,
                    proposal_id=proposal.proposal_id,
                    decision="applied",
                    engine=f"semgrep-pack:{pack}",
                    eval_positive=proposal.eval_positive,
                    eval_negative=proposal.eval_negative,
                    applied_path=applied_path,
                )
                # Touch `now` so the linter doesn't flag it as unused while
                # we keep the variable for future audit columns.
                _ = now
        else:
            pending_custom_rule += 1
            if conn is not None:
                record_proposal_decision(
                    conn,
                    proposal_id=proposal.proposal_id,
                    decision="pending",
                    engine="semgrep",
                    eval_positive=proposal.eval_positive,
                    eval_negative=proposal.eval_negative,
                )
    return {
        "routed_to_pack": routed_to_pack,
        "routed_to_joern": routed_to_joern,
        "routed_to_codeql": routed_to_codeql,
        "pending_custom_rule": pending_custom_rule,
    }
