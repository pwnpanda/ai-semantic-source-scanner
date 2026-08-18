"""Tests for model proposal artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest
import yaml
from typer.testing import CliRunner

from ai_codescan.cli import app
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.model_proposals import (
    ModelProposal,
    _bug_class_for_cwe,
    accept_model_proposal,
    apply_proposal_to_semgrep,
    list_model_proposals,
    proposal_decision_counts,
    proposals_from_verdicts,
    record_proposal_decision,
    write_model_proposals,
)

runner = CliRunner()


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [
        ("CWE-93", "crlf-injection"),
        ("CWE-532", "sensitive-logging"),
        ("CWE-611", "xxe"),
    ],
)
def test_semantic_hotspot_cwes_map_to_existing_bug_classes(cwe: str, expected: str) -> None:
    assert _bug_class_for_cwe(cwe) == expected


def _proposal() -> ModelProposal:
    return ModelProposal(
        proposal_id="proposal-test",
        nomination_id="N-001",
        finding_id="F-001",
        verdict="needs-model-extension",
        cwe="CWE-639",
        language="csharp",
        framework="aspnet",
        bug_class="bola",
        source_pattern="route id",
        sink_pattern="db lookup",
        sanitizer_pattern="owner check",
        vulnerable_example="",
        safe_example="",
        target_engine="heuristic",
        eval_target="",
        rationale="missing BOLA model",
        source_path="findings/F-001.md",
    )


def test_proposals_from_needs_model_extension_verdicts(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO review_verdicts
          (
            nomination_id, finding_id, flow_id, candidate_id, verdict, status,
            confidence, cwe, title, evidence_json, reviewer, source_path
          )
        VALUES
          (
            'N-001', 'F-001', '', 'N-001', 'needs-model-extension', 'unverified',
            'medium', 'CWE-639', 'BOLA model gap', '[]', 'deep_analyzer',
            'findings/F-001.md'
          )
        """
    )

    proposals = proposals_from_verdicts(conn, language="csharp", framework="aspnet")

    assert len(proposals) == 1
    assert proposals[0].nomination_id == "N-001"
    assert proposals[0].bug_class == "bola"
    assert proposals[0].language == "csharp"


def test_proposals_from_verdicts_filters_out_stale_nominations(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    for nomination_id in ("B-miss-current", "B-miss-stale"):
        conn.execute(
            """
            INSERT INTO review_verdicts
              (
                nomination_id, finding_id, flow_id, candidate_id, verdict, status,
                confidence, cwe, title, evidence_json, reviewer, source_path
              )
            VALUES
              (?, ?, '', ?, 'needs-model-extension', 'unverified',
               'medium', 'CWE-639', 'model gap', '[]', 'miss_reviewer', ?)
            """,
            [
                nomination_id,
                nomination_id.replace("B-", "F-"),
                nomination_id,
                f"findings/{nomination_id}.md",
            ],
        )

    proposals = proposals_from_verdicts(
        conn,
        nomination_ids=frozenset({"B-miss-current"}),
    )

    assert [proposal.nomination_id for proposal in proposals] == ["B-miss-current"]


def test_proposals_from_verdicts_preserves_review_proposal_details(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO review_verdicts
          (
            nomination_id, finding_id, flow_id, candidate_id, verdict, status,
            confidence, cwe, title, evidence_json, reviewer, source_path
          )
        VALUES
          (
            'B-miss-current', 'F-miss-current', '', 'B-miss-current',
            'needs-model-extension', 'unverified', 'medium', 'CWE-639',
            'model gap', '[]', 'miss_reviewer', 'findings/F-miss-current.md'
          )
        """
    )

    [proposal] = proposals_from_verdicts(
        conn,
        nomination_ids=frozenset({"B-miss-current"}),
        proposal_details={
            "B-miss-current": {
                "language": "kotlin",
                "framework": "spring",
                "source_pattern": "route parameter",
                "sink_pattern": "repository lookup",
                "sanitizer_pattern": "ownership check",
                "vulnerable_example": "lookup(id)",
                "safe_example": "lookupOwned(id, principal)",
                "target_engine": "joern",
                "eval_target": "eval-targets/kotlin-bola",
                "eval_positive": "eval-targets/kotlin-bola",
                "eval_negative": "eval-targets/kotlin-bola-safe",
                "receiver_regex": "Repository",
            }
        },
    )

    assert proposal.language == "kotlin"
    assert proposal.framework == "spring"
    assert proposal.source_pattern == "route parameter"
    assert proposal.sink_pattern == "repository lookup"
    assert proposal.sanitizer_pattern == "ownership check"
    assert proposal.vulnerable_example == "lookup(id)"
    assert proposal.safe_example == "lookupOwned(id, principal)"
    assert proposal.target_engine == "joern"
    assert proposal.eval_target == "eval-targets/kotlin-bola"
    assert proposal.eval_positive == "eval-targets/kotlin-bola"
    assert proposal.eval_negative == "eval-targets/kotlin-bola-safe"
    assert proposal.receiver_regex == "Repository"


@pytest.mark.parametrize(
    ("cwe", "expected_bug_class"),
    [
        ("CWE-90", "ldap-injection"),
        ("CWE-93", "crlf-injection"),
        ("CWE-532", "sensitive-logging"),
        ("CWE-601", "open-redirect"),
        ("CWE-611", "xxe"),
        ("CWE-643", "xpath-injection"),
        ("CWE-943", "nosqli"),
        ("CWE-1321", "prototype-pollution"),
        ("CWE-1333", "redos"),
        ("CWE-1336", "ssti"),
    ],
)
def test_proposals_map_new_engine_cwes_to_taxonomy(
    tmp_path: Path,
    cwe: str,
    expected_bug_class: str,
) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        """
        INSERT INTO review_verdicts
          (
            nomination_id, finding_id, flow_id, candidate_id, verdict, status,
            confidence, cwe, title, evidence_json, reviewer, source_path
          )
        VALUES
          (
            'N-new', 'F-new', '', 'N-new', 'needs-model-extension', 'unverified',
            'medium', ?, 'model gap', '[]', 'miss_reviewer', 'findings/F-new.md'
          )
        """,
        [cwe],
    )

    proposals = proposals_from_verdicts(conn)

    assert proposals[0].bug_class == expected_bug_class


def test_write_list_and_accept_model_proposal(tmp_path: Path) -> None:
    proposals_dir = tmp_path / "model_proposals"
    [path] = write_model_proposals([_proposal()], proposals_dir=proposals_dir)
    eval_target = tmp_path / "eval-target"
    eval_target.mkdir()

    proposals = list_model_proposals(proposals_dir)
    accepted = accept_model_proposal(proposals[0], eval_target=eval_target)

    assert path.is_file()
    assert proposals[0].proposal_id == "proposal-test"
    assert accepted["dry_run"] is True
    assert accepted["accepted"] is False


def test_apply_proposal_to_semgrep_writes_staged_yaml(tmp_path: Path) -> None:
    """Phase 3: a proposal renders into a Semgrep YAML rule under
    `.semgrep/rules.staged/` (dry-run gate — staged, not active)."""

    proposal = ModelProposal(
        proposal_id="proposal-ssrf-001",
        nomination_id="N-001",
        finding_id="F-001",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="flask",
        bug_class="ssrf",
        source_pattern="requests.get($URL)",
        sink_pattern="requests.get($URL)",
        sanitizer_pattern="if $HOST in ALLOWED_HOSTS:",
        vulnerable_example="requests.get(request.args['url'])",
        safe_example="if urlparse(url).hostname in ALLOWED_HOSTS:\n    requests.get(url)",
        target_engine="semgrep",
        eval_target="eval-targets/python-flask-ssrf",
        rationale="Joern misses Flask SSRF when wrapped in helper",
        source_path="findings/F-001.md",
    )

    rule_path = apply_proposal_to_semgrep(proposal, rules_root=tmp_path / ".semgrep")

    assert rule_path.is_file()
    assert rule_path.parent.name == "rules.staged"  # staged dir, not active
    parsed = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    assert "rules" in parsed and len(parsed["rules"]) == 1
    rule = parsed["rules"][0]
    assert rule["id"].startswith("aics-cwe-918-")
    assert rule["metadata"]["proposal_id"] == "proposal-ssrf-001"
    assert rule["metadata"]["cwe"] == "CWE-918"
    assert rule["metadata"]["stage"] == "staged"
    assert rule["languages"] == ["python"]
    # Sink pattern flows into the Semgrep `pattern` field.
    assert rule["pattern"] == "requests.get($URL)"


def test_accept_refuses_without_paired_eval_targets(tmp_path: Path) -> None:
    """Phase 3 paired-target gate (Invariant 5): apply refuses unless the
    proposal has BOTH a positive and a negative eval target linked."""
    pos = tmp_path / "positive"
    pos.mkdir()
    proposal = _proposal()  # no eval targets linked

    with pytest.raises(ValueError, match="positive AND negative"):
        accept_model_proposal(
            proposal,
            eval_target=pos,  # legacy single-target compat
            dry_run=False,
            require_paired_targets=True,
        )


def test_accept_succeeds_when_paired_targets_present(tmp_path: Path) -> None:
    """Paired-target gate passes when proposal carries both."""
    pos = tmp_path / "positive"
    pos.mkdir()
    neg = tmp_path / "negative"
    neg.mkdir()
    proposal = _proposal()
    paired = ModelProposal(
        proposal_id=proposal.proposal_id,
        nomination_id=proposal.nomination_id,
        finding_id=proposal.finding_id,
        verdict=proposal.verdict,
        cwe=proposal.cwe,
        language=proposal.language,
        framework=proposal.framework,
        bug_class=proposal.bug_class,
        source_pattern=proposal.source_pattern,
        sink_pattern=proposal.sink_pattern,
        sanitizer_pattern=proposal.sanitizer_pattern,
        vulnerable_example=proposal.vulnerable_example,
        safe_example=proposal.safe_example,
        target_engine=proposal.target_engine,
        eval_target=proposal.eval_target,
        eval_positive=str(pos),
        eval_negative=str(neg),
        rationale=proposal.rationale,
        source_path=proposal.source_path,
    )

    result = accept_model_proposal(
        paired,
        eval_target=pos,
        dry_run=True,
        require_paired_targets=True,
    )

    assert result["accepted"] is False  # dry-run
    assert result["dry_run"] is True
    assert result["eval_positive"] == str(pos)
    assert result["eval_negative"] == str(neg)


def test_record_and_count_proposal_decisions(tmp_path: Path) -> None:
    """Phase 3 bookkeeping: proposal_decisions table survives runs and groups by status."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    record_proposal_decision(conn, proposal_id="p1", decision="pending")
    record_proposal_decision(conn, proposal_id="p2", decision="applied", engine="semgrep")
    record_proposal_decision(conn, proposal_id="p3", decision="rejected")
    # Re-recording p2 must replace, not append (PK constraint).
    record_proposal_decision(conn, proposal_id="p2", decision="rejected")

    counts = proposal_decision_counts(conn)
    assert counts == {"pending": 1, "applied": 0, "rejected": 2}


def test_record_proposal_decision_rejects_unknown_status(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    with pytest.raises(ValueError, match="pending|applied|rejected"):
        record_proposal_decision(conn, proposal_id="p1", decision="maybe")


def test_apply_proposal_to_semgrep_emits_placeholder_when_pattern_empty(tmp_path: Path) -> None:
    """A proposal with no sink_pattern still renders, but the pattern field
    carries a TODO so a human (or follow-up LLM pass) refines before promotion."""

    proposal = ModelProposal(
        proposal_id="proposal-todo",
        nomination_id="N-001",
        finding_id="F-001",
        verdict="needs-model-extension",
        cwe="CWE-639",
        language="python",
        framework="flask",
        bug_class="bola",
        source_pattern="",
        sink_pattern="",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="semgrep",
        eval_target="eval-targets/python-flask-authz-missing",
        rationale="needs human refinement",
        source_path="",
    )

    rule_path = apply_proposal_to_semgrep(proposal, rules_root=tmp_path / ".semgrep")

    parsed = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    rule = parsed["rules"][0]
    assert "TODO" in str(rule["pattern"])


def test_model_proposals_cli_apply_engine_joern_writes_extension(tmp_path: Path) -> None:
    """Phase 5: `model-proposals apply --engine joern` writes a sink entry
    into aics-joern-extension-packs.json in the repo cache and records
    the decision as engine=joern-extension:<class>."""
    cache = tmp_path / "cache"
    repo_dir = cache / "repo-1"
    run_dir = repo_dir / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    proposal = ModelProposal(
        proposal_id="proposal-joern",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="flask",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="(?i)^(my_custom_fetch)$",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="joern",
        eval_target="",
        rationale="custom HTTP wrapper not in default Joern model",
        source_path="",
        eval_positive=str(tmp_path / "pos"),
        eval_negative=str(tmp_path / "neg"),
    )
    (tmp_path / "pos").mkdir()
    (tmp_path / "neg").mkdir()
    write_model_proposals([proposal], proposals_dir=proposals_dir)
    # Pre-seed the DuckDB so the CLI records the decision.
    repo_dir.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(repo_dir / "index.duckdb"))
    apply_schema(conn)
    conn.close()

    applied = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "apply",
            "proposal-joern",
            "--repo-id",
            "repo-1",
            "--engine",
            "joern",
        ],
    )

    assert applied.exit_code == 0, applied.output
    # Phase 5.1: apply --engine joern defaults to STAGED. The promoted file
    # is empty; the .staged.json sibling has the entry.
    promoted_path = repo_dir / "aics-joern-extension-packs.json"
    staged_path = repo_dir / "aics-joern-extension-packs.staged.json"
    assert not promoted_path.is_file()
    assert staged_path.is_file()
    payload = json.loads(staged_path.read_text(encoding="utf-8"))
    assert payload["sinks"][0]["pattern"] == "(?i)^(my_custom_fetch)$"
    # Decision recorded with the joern-extension prefix.
    conn = duckdb.connect(str(repo_dir / "index.duckdb"), read_only=True)
    try:
        row = conn.execute(
            "SELECT engine, applied_path FROM proposal_decisions "
            "WHERE proposal_id = 'proposal-joern'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0].startswith("joern-extension:")
    assert row[1] == str(staged_path)


def test_model_proposals_cli_promote_moves_staged_to_active(tmp_path: Path) -> None:
    """Phase 5.1: `model-proposals promote --engine joern` moves a staged
    Joern extension entry into the active file Joern reads."""
    cache = tmp_path / "cache"
    repo_dir = cache / "repo-1"
    run_dir = repo_dir / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    proposal = ModelProposal(
        proposal_id="proposal-prom",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="(?i)^(promote_fetch)$",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="joern",
        eval_target="",
        rationale="",
        source_path="",
        eval_positive=str(tmp_path / "pos"),
        eval_negative=str(tmp_path / "neg"),
    )
    (tmp_path / "pos").mkdir()
    (tmp_path / "neg").mkdir()
    write_model_proposals([proposal], proposals_dir=proposals_dir)
    repo_dir.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(repo_dir / "index.duckdb"))
    apply_schema(conn)
    conn.close()

    # 1. apply --engine joern lands the rule in the staged file.
    apply_result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "apply",
            "proposal-prom",
            "--repo-id",
            "repo-1",
            "--engine",
            "joern",
        ],
    )
    assert apply_result.exit_code == 0
    staged_path = repo_dir / "aics-joern-extension-packs.staged.json"
    promoted_path = repo_dir / "aics-joern-extension-packs.json"
    assert staged_path.is_file()
    assert not promoted_path.is_file()

    # 2. promote moves it.
    promote_result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "promote",
            "proposal-prom",
            "--repo-id",
            "repo-1",
            "--engine",
            "joern",
        ],
    )
    assert promote_result.exit_code == 0, promote_result.output
    assert promoted_path.is_file()
    promoted = json.loads(promoted_path.read_text(encoding="utf-8"))
    assert len(promoted["sinks"]) == 1
    assert promoted["sinks"][0]["pattern"] == "(?i)^(promote_fetch)$"
    staged = json.loads(staged_path.read_text(encoding="utf-8"))
    assert staged["sinks"] == []


def test_model_proposals_cli_promote_all_bulk_moves_every_staged(tmp_path: Path) -> None:
    """`model-proposals promote --all --engine joern` bulk-promotes every
    staged extension. Skips entries without a proposal_id (defensive)."""
    cache = tmp_path / "cache"
    repo_dir = cache / "repo-1"
    run_dir = repo_dir / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    proposals = [
        ModelProposal(
            proposal_id=f"p-bulk-{i}",
            nomination_id="N-1",
            finding_id="F-1",
            verdict="needs-model-extension",
            cwe="CWE-918",
            language="python",
            framework="",
            bug_class="ssrf",
            source_pattern="",
            sink_pattern=f"(?i)^(bulk_{i})$",
            sanitizer_pattern="",
            vulnerable_example="",
            safe_example="",
            target_engine="joern",
            eval_target="",
            rationale="",
            source_path="",
            eval_positive=str(tmp_path / "pos"),
            eval_negative=str(tmp_path / "neg"),
        )
        for i in range(3)
    ]
    (tmp_path / "pos").mkdir()
    (tmp_path / "neg").mkdir()
    write_model_proposals(proposals, proposals_dir=proposals_dir)
    repo_dir.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(repo_dir / "index.duckdb"))
    apply_schema(conn)
    conn.close()
    for p in proposals:
        runner.invoke(
            app,
            [
                "--cache-dir",
                str(cache),
                "model-proposals",
                "apply",
                p.proposal_id,
                "--repo-id",
                "repo-1",
                "--engine",
                "joern",
            ],
        )

    promoted_result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "promote",
            "--repo-id",
            "repo-1",
            "--engine",
            "joern",
            "--all",
        ],
    )

    assert promoted_result.exit_code == 0, promoted_result.output
    assert "promoted 3 Joern extension(s)" in promoted_result.output
    promoted_path = repo_dir / "aics-joern-extension-packs.json"
    staged_path = repo_dir / "aics-joern-extension-packs.staged.json"
    promoted = json.loads(promoted_path.read_text(encoding="utf-8"))
    staged = json.loads(staged_path.read_text(encoding="utf-8"))
    assert len(promoted["sinks"]) == 3
    assert staged["sinks"] == []


def test_model_proposals_cli_clone_creates_sibling_with_new_engine(tmp_path: Path) -> None:
    """Phase 5.1: `model-proposals clone --engine joern` forks a Semgrep
    proposal into a Joern-targeting sibling so both engines can carry
    coverage from the same miss-review verdict — without a 'both' mode."""
    cache = tmp_path / "cache"
    run_dir = cache / "repo-1" / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    semgrep_proposal = ModelProposal(
        proposal_id="proposal-orig",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="flask",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="(?i)^(orig_fetch)$",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="semgrep",
        eval_target="",
        rationale="original Semgrep proposal",
        source_path="",
        eval_positive="",
        eval_negative="",
        receiver_regex="",
    )
    write_model_proposals([semgrep_proposal], proposals_dir=proposals_dir)

    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "clone",
            "proposal-orig",
            "--repo-id",
            "repo-1",
            "--engine",
            "joern",
        ],
    )

    assert result.exit_code == 0, result.output
    cloned_path = proposals_dir / "proposal-orig-joern.json"
    assert cloned_path.is_file()
    payload = json.loads(cloned_path.read_text(encoding="utf-8"))
    assert payload["target_engine"] == "joern"
    assert payload["proposal_id"] == "proposal-orig-joern"
    assert payload["sink_pattern"] == "(?i)^(orig_fetch)$"
    assert "clone of proposal-orig" in payload["rationale"]


def test_model_proposals_cli_link_targets_then_apply(tmp_path: Path) -> None:
    """End-to-end Phase 3 CLI flow: link both eval targets, then `apply` writes
    the Semgrep rule into rules.staged/."""
    cache = tmp_path / "cache"
    run_dir = cache / "repo-1" / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    write_model_proposals([_proposal()], proposals_dir=proposals_dir)
    positive = tmp_path / "positive-target"
    positive.mkdir()
    negative = tmp_path / "negative-target"
    negative.mkdir()
    rules_root = tmp_path / ".semgrep"

    linked = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "link-targets",
            "proposal-test",
            "--repo-id",
            "repo-1",
            "--positive",
            str(positive),
            "--negative",
            str(negative),
        ],
    )
    applied = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "apply",
            "proposal-test",
            "--repo-id",
            "repo-1",
            "--rules-root",
            str(rules_root),
        ],
    )

    assert linked.exit_code == 0, linked.stdout + linked.stderr
    assert applied.exit_code == 0, applied.stdout + applied.stderr
    # rule landed in rules.staged/ by default.
    staged = rules_root / "rules.staged"
    assert any(staged.glob("aics-cwe-639-*.yml")), list(staged.iterdir())


def test_model_proposals_apply_refuses_without_paired_targets(tmp_path: Path) -> None:
    """`apply` refuses if link-targets hasn't been called first."""
    cache = tmp_path / "cache"
    run_dir = cache / "repo-1" / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    write_model_proposals([_proposal()], proposals_dir=proposals_dir)
    rules_root = tmp_path / ".semgrep"

    result = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "apply",
            "proposal-test",
            "--repo-id",
            "repo-1",
            "--rules-root",
            str(rules_root),
        ],
    )

    assert result.exit_code == 1
    assert "paired-target gate" in result.output.lower()
    assert not rules_root.exists()


def test_model_proposals_cli_list_and_accept(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    run_dir = cache / "repo-1" / "runs" / "run-1"
    proposals_dir = run_dir / "model_proposals"
    write_model_proposals([_proposal()], proposals_dir=proposals_dir)
    eval_target = tmp_path / "eval-target"
    eval_target.mkdir()

    listed = runner.invoke(
        app,
        ["--cache-dir", str(cache), "model-proposals", "list", "--repo-id", "repo-1"],
    )
    accepted = runner.invoke(
        app,
        [
            "--cache-dir",
            str(cache),
            "model-proposals",
            "accept",
            "proposal-test",
            "--repo-id",
            "repo-1",
            "--eval-target",
            str(eval_target),
        ],
    )

    assert listed.exit_code == 0
    assert "proposal-test" in listed.stdout
    assert accepted.exit_code == 0
    assert json.loads(accepted.stdout)["proposal_id"] == "proposal-test"
