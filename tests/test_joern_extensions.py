"""Tests for ai_codescan.joern_extensions — Phase 5 Joern model patching."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_codescan.joern_extensions import (
    JoernExtensionEntry,
    apply_proposal_to_joern,
    load_joern_extensions,
    promote_joern_extension,
    staged_path_for,
    validate_extension_path,
)
from ai_codescan.model_proposals import ModelProposal


def _proposal(
    *,
    cwe: str = "CWE-918",
    language: str = "python",
    pid: str = "p-ext",
    sink_pattern: str = "(?i)^(myfetch|api_call)$",
    receiver: str = "",
) -> ModelProposal:
    return ModelProposal(
        proposal_id=pid,
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe=cwe,
        language=language,
        framework="",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern=sink_pattern,
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="joern",
        eval_target="",
        rationale="Joern lacks model for custom HTTP client",
        source_path="",
        receiver_regex=receiver,
    )


def test_apply_proposal_defaults_to_staged(tmp_path: Path) -> None:
    """Phase 5.1: by default, apply_proposal_to_joern writes to the
    .staged.json sibling, NOT the promoted file Joern reads at scan time.
    Mirrors Semgrep's rules.staged/ flow."""
    ext_path = tmp_path / "aics-joern-extension-packs.json"
    entry = apply_proposal_to_joern(
        _proposal(pid="p-1"),
        extension_path=ext_path,
    )

    # Promoted file does NOT exist yet — staged is the default.
    assert not ext_path.is_file()
    staged = staged_path_for(ext_path)
    assert staged.is_file()
    payload = json.loads(staged.read_text(encoding="utf-8"))
    assert "sinks" in payload
    assert len(payload["sinks"]) == 1
    sink = payload["sinks"][0]
    assert sink["language"] == "python"
    assert sink["cwe"] == "CWE-918"
    assert sink["sink_class"] == "ssrf"
    assert sink["pattern"] == "(?i)^(myfetch|api_call)$"
    assert sink["proposal_id"] == "p-1"
    assert isinstance(entry, JoernExtensionEntry)


def test_apply_proposal_with_staged_false_writes_promoted(tmp_path: Path) -> None:
    """staged=False writes directly to the promoted file Joern reads."""
    ext_path = tmp_path / "aics-joern-extension-packs.json"
    apply_proposal_to_joern(_proposal(pid="p-prom"), extension_path=ext_path, staged=False)
    assert ext_path.is_file()
    assert not staged_path_for(ext_path).is_file()


def test_apply_proposal_is_idempotent(tmp_path: Path) -> None:
    """Re-applying the same proposal does not duplicate the sink entry —
    matched by (language, cwe, sink_class, pattern)."""
    ext_path = tmp_path / "ext.json"
    apply_proposal_to_joern(_proposal(pid="p-1"), extension_path=ext_path, staged=False)
    apply_proposal_to_joern(_proposal(pid="p-1"), extension_path=ext_path, staged=False)
    payload = json.loads(ext_path.read_text(encoding="utf-8"))
    assert len(payload["sinks"]) == 1


def test_apply_proposal_appends_distinct_entry(tmp_path: Path) -> None:
    """Different (cwe, pattern) tuples → distinct entries in the same file."""
    ext_path = tmp_path / "ext.json"
    apply_proposal_to_joern(
        _proposal(pid="p-1", cwe="CWE-918", sink_pattern="(?i)^(myfetch)$"),
        extension_path=ext_path,
        staged=False,
    )
    apply_proposal_to_joern(
        _proposal(pid="p-2", cwe="CWE-89", sink_pattern="(?i)^(unsafe_query)$"),
        extension_path=ext_path,
        staged=False,
    )
    payload = json.loads(ext_path.read_text(encoding="utf-8"))
    assert len(payload["sinks"]) == 2


def test_apply_proposal_refuses_empty_sink_pattern(tmp_path: Path) -> None:
    """A proposal without a sink_pattern cannot generate a Joern sink — Joern
    needs a concrete regex to match. The CLI surface enforces this; the
    Python layer also raises to make the failure mode loud."""
    bad = _proposal(pid="p-empty", sink_pattern="")
    with pytest.raises(ValueError, match="sink_pattern"):
        apply_proposal_to_joern(bad, extension_path=tmp_path / "ext.json", staged=False)


def test_promote_moves_staged_entry_to_promoted(tmp_path: Path) -> None:
    """Phase 5.1: promote_joern_extension moves an entry from the staged
    file to the promoted file. Joern reads only the promoted file."""
    ext_path = tmp_path / "ext.json"
    apply_proposal_to_joern(_proposal(pid="p-promote-me"), extension_path=ext_path)
    assert staged_path_for(ext_path).is_file()
    assert not ext_path.is_file()

    moved = promote_joern_extension("p-promote-me", extension_path=ext_path)

    assert moved is not None
    assert moved.proposal_id == "p-promote-me"
    # Staged file now has no entries.
    staged_payload = json.loads(staged_path_for(ext_path).read_text(encoding="utf-8"))
    assert staged_payload["sinks"] == []
    # Promoted file has the moved entry.
    promoted_payload = json.loads(ext_path.read_text(encoding="utf-8"))
    assert len(promoted_payload["sinks"]) == 1
    assert promoted_payload["sinks"][0]["proposal_id"] == "p-promote-me"


def test_promote_returns_none_for_unknown_proposal(tmp_path: Path) -> None:
    """Promoting a proposal id that isn't in staged is a no-op (returns None)."""
    ext_path = tmp_path / "ext.json"
    assert promote_joern_extension("does-not-exist", extension_path=ext_path) is None


def test_load_joern_extensions_returns_empty_when_missing(tmp_path: Path) -> None:
    assert load_joern_extensions(tmp_path / "nope.json") == []


def test_load_joern_extensions_handles_malformed_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    # Malformed file logs and returns empty rather than crashing — Joern
    # scans should never fail because the extension file is corrupted.
    assert load_joern_extensions(bad) == []


def test_load_joern_extensions_round_trip(tmp_path: Path) -> None:
    ext_path = tmp_path / "ext.json"
    apply_proposal_to_joern(_proposal(pid="p-rt"), extension_path=ext_path, staged=False)
    loaded = load_joern_extensions(ext_path)
    assert len(loaded) == 1
    assert loaded[0].cwe == "CWE-918"
    assert loaded[0].pattern == "(?i)^(myfetch|api_call)$"


def test_apply_proposal_uses_receiver_regex_and_ignores_sanitizer(tmp_path: Path) -> None:
    """receiver_regex is the sole source for the Joern receiver predicate.
    sanitizer_pattern keeps its Semgrep meaning and is never read here —
    the pre-5.1 fallback was removed in Phase 14 (no legacy proposals exist)."""
    ext_path = tmp_path / "ext.json"
    proposal_new = ModelProposal(
        proposal_id="p-new",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="(?i)^(myfetch)$",
        sanitizer_pattern="should-be-ignored",
        vulnerable_example="",
        safe_example="",
        target_engine="joern",
        eval_target="",
        rationale="",
        source_path="",
        receiver_regex="canonical",
    )
    entry = apply_proposal_to_joern(proposal_new, extension_path=ext_path)
    assert entry.receiver_regex == "canonical"

    # A proposal carrying only sanitizer_pattern (no receiver_regex) yields
    # an entry with an EMPTY receiver_regex — sanitizer_pattern is not a
    # fallback source for the Joern receiver predicate any more.
    proposal_sanitizer_only = ModelProposal(
        proposal_id="p-sani",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="(?i)^(myfetch_other)$",
        sanitizer_pattern="not-a-receiver",
        vulnerable_example="",
        safe_example="",
        target_engine="joern",
        eval_target="",
        rationale="",
        source_path="",
    )
    entry = apply_proposal_to_joern(proposal_sanitizer_only, extension_path=ext_path)
    assert entry.receiver_regex == ""


def test_validate_extension_path_returns_canonical_path(tmp_path: Path) -> None:
    """The Joern script reads the JSON via an absolute path passed in the
    AICS_JOERN_EXTENSIONS env var. validate_extension_path checks the file
    is well-formed and returns the absolute resolved path so the env var
    can be set deterministically. Missing file returns None — Joern just
    skips the merge."""
    # validate_extension_path checks the PROMOTED file (what Joern reads).
    apply_proposal_to_joern(
        _proposal(pid="p-v"), extension_path=tmp_path / "ext.json", staged=False
    )
    resolved = validate_extension_path(tmp_path / "ext.json")
    assert resolved is not None
    assert resolved.is_absolute()
    assert validate_extension_path(tmp_path / "nope.json") is None
