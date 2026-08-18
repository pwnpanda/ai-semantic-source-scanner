"""Tests for ai_codescan.proposal_triage — auto-routing model proposals."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.engines import semgrep as semgrep_mod
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.model_proposals import ModelProposal
from ai_codescan.proposal_triage import (
    enable_pack_for_repo,
    enabled_packs,
    pack_for_proposal,
    triage_and_route,
)


def _proposal(*, cwe: str = "CWE-89", language: str = "python", pid: str = "p-1") -> ModelProposal:
    return ModelProposal(
        proposal_id=pid,
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe=cwe,
        language=language,
        framework="",
        bug_class="",
        source_pattern="",
        sink_pattern="",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="semgrep",
        eval_target="",
        rationale="",
        source_path="",
    )


def test_pack_for_proposal_routes_known_combinations() -> None:
    assert pack_for_proposal(_proposal(cwe="CWE-89", language="python")) is not None
    assert pack_for_proposal(_proposal(cwe="CWE-79", language="javascript")) is not None
    # Unmapped (CWE, language) → None means "custom rule, not a pack".
    assert pack_for_proposal(_proposal(cwe="CWE-639", language="python")) is None
    assert pack_for_proposal(_proposal(cwe="CWE-89", language="csharp")) is None


def test_enable_pack_for_repo_is_idempotent(tmp_path: Path) -> None:
    """Re-enabling the same pack must not duplicate it (file is a JSON set)."""
    enable_pack_for_repo("p/python.lang.security.injection.sql", repo_dir=tmp_path)
    enable_pack_for_repo("p/python.lang.security.injection.sql", repo_dir=tmp_path)
    enable_pack_for_repo("p/python.flask.security.audit.ssrf", repo_dir=tmp_path)
    assert enabled_packs(tmp_path) == [
        "p/python.flask.security.audit.ssrf",
        "p/python.lang.security.injection.sql",
    ]


def test_enabled_packs_returns_empty_when_registry_missing(tmp_path: Path) -> None:
    assert enabled_packs(tmp_path) == []


def test_enabled_packs_returns_empty_when_registry_malformed(tmp_path: Path) -> None:
    (tmp_path / "aics-enabled-packs.json").write_text("not json", encoding="utf-8")
    assert enabled_packs(tmp_path) == []


def test_triage_and_route_auto_enables_pack_for_routable_cwe(tmp_path: Path) -> None:
    """A (CWE-89, python) proposal lands as `applied` in proposal_decisions
    with the pack id recorded, and the pack appears in the enabled-packs
    registry — single-command flow."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    result = triage_and_route(
        [_proposal(cwe="CWE-89", language="python", pid="p-sqli")],
        conn=conn,
        repo_dir=tmp_path,
    )

    assert result == {
        "routed_to_pack": 1,
        "routed_to_joern": 0,
        "routed_to_codeql": 0,
        "pending_custom_rule": 0,
    }
    assert "p/python.lang.security.injection.sql" in enabled_packs(tmp_path)
    decision = conn.execute(
        "SELECT decision, engine FROM proposal_decisions WHERE proposal_id = 'p-sqli'"
    ).fetchone()
    assert decision == ("applied", "semgrep-pack:p/python.lang.security.injection.sql")


def test_triage_and_route_leaves_unmapped_proposal_pending(tmp_path: Path) -> None:
    """(CWE-639, python) BOLA has no community pack — stays `pending`."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    result = triage_and_route(
        [_proposal(cwe="CWE-639", language="python", pid="p-bola")],
        conn=conn,
        repo_dir=tmp_path,
    )

    assert result == {
        "routed_to_pack": 0,
        "routed_to_joern": 0,
        "routed_to_codeql": 0,
        "pending_custom_rule": 1,
    }
    assert enabled_packs(tmp_path) == []  # nothing auto-enabled
    # No Joern extension file written either — proposal had no sink_pattern.
    assert not (tmp_path / "aics-joern-extension-packs.json").is_file()
    decision = conn.execute(
        "SELECT decision FROM proposal_decisions WHERE proposal_id = 'p-bola'"
    ).fetchone()
    assert decision == ("pending",)


def test_triage_routes_joern_target_engine_to_extensions(tmp_path: Path) -> None:
    """Phase 5: a proposal with target_engine='joern' AND a sink_pattern is
    routed to apply_proposal_to_joern. proposal_decisions records engine
    with the joern-extension prefix and applied_path points at the JSON."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    proposal = ModelProposal(
        proposal_id="p-joern-ssrf",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-918",
        language="python",
        framework="",
        bug_class="ssrf",
        source_pattern="",
        sink_pattern="(?i)^(apiv2_fetch)$",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="joern",
        eval_target="",
        rationale="custom HTTP client wrapper",
        source_path="",
    )

    result = triage_and_route([proposal], conn=conn, repo_dir=tmp_path)

    assert result == {
        "routed_to_pack": 0,
        "routed_to_joern": 1,
        "routed_to_codeql": 0,
        "pending_custom_rule": 0,
    }
    # Phase 5.1: auto-routed Joern proposals land in the .staged file;
    # promoted file is empty until the user runs `model-proposals promote`.
    promoted_path = tmp_path / "aics-joern-extension-packs.json"
    staged_path = tmp_path / "aics-joern-extension-packs.staged.json"
    assert not promoted_path.is_file()
    assert staged_path.is_file()
    decision = conn.execute(
        "SELECT decision, engine, applied_path FROM proposal_decisions "
        "WHERE proposal_id = 'p-joern-ssrf'"
    ).fetchone()
    assert decision is not None
    assert decision[0] == "pending"  # staged → not yet active
    assert decision[1].startswith("joern-extension-staged:")
    assert decision[2] == str(staged_path)


def test_triage_joern_proposal_without_sink_pattern_falls_back_to_pending(tmp_path: Path) -> None:
    """When target_engine='joern' but sink_pattern is empty, routing falls
    through to the Semgrep-or-pending path (Joern can't generate a sink
    without a concrete pattern)."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    proposal = ModelProposal(
        proposal_id="p-joern-empty",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-639",  # not in _PACK_MAP either
        language="python",
        framework="",
        bug_class="bola",
        source_pattern="",
        sink_pattern="",  # empty — joern path can't use this
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="joern",
        eval_target="",
        rationale="",
        source_path="",
    )

    result = triage_and_route([proposal], conn=conn, repo_dir=tmp_path)

    assert result == {
        "routed_to_pack": 0,
        "routed_to_joern": 0,
        "routed_to_codeql": 0,
        "pending_custom_rule": 1,
    }
    assert not (tmp_path / "aics-joern-extension-packs.json").is_file()
    assert not (tmp_path / "aics-joern-extension-packs.staged.json").is_file()


def test_triage_routes_codeql_target_engine_to_extensions(tmp_path: Path) -> None:
    """Phase 10: a proposal with target_engine='codeql' AND a sink_pattern
    is routed to apply_proposal_to_codeql (staged). proposal_decisions
    records engine with the codeql-extension-staged prefix and
    applied_path points at the staged JSON file."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    proposal = ModelProposal(
        proposal_id="p-codeql-sqli",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-89",
        language="java",
        framework="org.springframework.jdbc",
        bug_class="JdbcTemplate",
        source_pattern="",
        sink_pattern="queryForObject",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="codeql",
        eval_target="",
        rationale="custom JdbcTemplate wrapper",
        source_path="",
    )

    result = triage_and_route([proposal], conn=conn, repo_dir=tmp_path)

    assert result == {
        "routed_to_pack": 0,
        "routed_to_joern": 0,
        "routed_to_codeql": 1,
        "pending_custom_rule": 0,
    }
    promoted_path = tmp_path / "aics-codeql-extension-packs.json"
    staged_path = tmp_path / "aics-codeql-extension-packs.staged.json"
    assert not promoted_path.is_file()
    assert staged_path.is_file()
    decision = conn.execute(
        "SELECT decision, engine, applied_path FROM proposal_decisions "
        "WHERE proposal_id = 'p-codeql-sqli'"
    ).fetchone()
    assert decision is not None
    assert decision[0] == "pending"  # staged → awaiting promote
    assert decision[1].startswith("codeql-extension-staged:")
    assert decision[2] == str(staged_path)


def test_triage_codeql_proposal_without_sink_pattern_falls_back_to_pending(
    tmp_path: Path,
) -> None:
    """target_engine='codeql' with empty sink_pattern falls through to the
    Semgrep-or-pending path — CodeQL can't model an empty method name."""
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    proposal = ModelProposal(
        proposal_id="p-codeql-empty",
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe="CWE-639",  # not in _PACK_MAP either
        language="java",
        framework="",
        bug_class="",
        source_pattern="",
        sink_pattern="",
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="codeql",
        eval_target="",
        rationale="",
        source_path="",
    )

    result = triage_and_route([proposal], conn=conn, repo_dir=tmp_path)

    assert result == {
        "routed_to_pack": 0,
        "routed_to_joern": 0,
        "routed_to_codeql": 0,
        "pending_custom_rule": 1,
    }
    assert not (tmp_path / "aics-codeql-extension-packs.json").is_file()
    assert not (tmp_path / "aics-codeql-extension-packs.staged.json").is_file()


def test_triage_and_route_handles_mixed_batch(tmp_path: Path) -> None:
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)

    result = triage_and_route(
        [
            _proposal(cwe="CWE-89", language="python", pid="p1"),
            _proposal(cwe="CWE-639", language="python", pid="p2"),
            _proposal(cwe="CWE-79", language="javascript", pid="p3"),
        ],
        conn=conn,
        repo_dir=tmp_path,
    )

    assert result["routed_to_pack"] == 2
    assert result["routed_to_joern"] == 0
    assert result["pending_custom_rule"] == 1
    rows = conn.execute(
        "SELECT proposal_id, decision FROM proposal_decisions ORDER BY proposal_id"
    ).fetchall()
    assert rows == [("p1", "applied"), ("p2", "pending"), ("p3", "applied")]


def test_run_semgrep_picks_up_enabled_packs(tmp_path: Path, monkeypatch) -> None:
    """When aics-enabled-packs.json exists in cache_dir, run_semgrep
    appends each pack as --config=<pack>."""
    enable_pack_for_repo("p/python.lang.security.injection.sql", repo_dir=tmp_path)
    captured: dict[str, list[str]] = {}

    def fake_subprocess_run(cmd, **_kw):
        captured["cmd"] = list(cmd)
        output_index = cmd.index("--output") + 1
        Path(cmd[output_index]).write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")

        class _R:
            returncode = 0
            stdout = b""
            stderr = b""

        return _R()

    monkeypatch.setattr(semgrep_mod, "is_available", lambda: True)
    monkeypatch.setattr(semgrep_mod.subprocess, "run", fake_subprocess_run)

    project_root = tmp_path / "src"
    project_root.mkdir()
    semgrep_mod.run_semgrep(project_root, cache_dir=tmp_path, project_id="x")

    pack_args = [a for a in captured["cmd"] if a == "--config=p/python.lang.security.injection.sql"]
    assert pack_args, f"pack not propagated: {captured['cmd']}"


def test_run_semgrep_loads_promoted_rules_but_not_staged_rules(
    tmp_path: Path,
    monkeypatch,
) -> None:
    active = tmp_path / ".semgrep" / "rules"
    staged = tmp_path / ".semgrep" / "rules.staged"
    active.mkdir(parents=True)
    staged.mkdir(parents=True)
    (active / "promoted.yml").write_text("rules: []\n", encoding="utf-8")
    (staged / "unapproved.yml").write_text("rules: []\n", encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def fake_subprocess_run(cmd, **_kw):
        captured["cmd"] = list(cmd)
        output_index = cmd.index("--output") + 1
        Path(cmd[output_index]).write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")

        class _Result:
            returncode = 0
            stdout = b""
            stderr = b""

        return _Result()

    monkeypatch.setattr(semgrep_mod, "is_available", lambda: True)
    monkeypatch.setattr(semgrep_mod.subprocess, "run", fake_subprocess_run)
    project_root = tmp_path / "src"
    project_root.mkdir()

    semgrep_mod.run_semgrep(project_root, cache_dir=tmp_path, project_id="custom")

    assert f"--config={active}" in captured["cmd"]
    assert f"--config={staged}" not in captured["cmd"]


def test_run_semgrep_failure_cannot_reuse_stale_sarif(
    tmp_path: Path,
    monkeypatch,
) -> None:
    stale = tmp_path / "semgrep" / "project.sarif"
    stale.parent.mkdir()
    stale.write_text('{"version":"2.1.0","runs":[{"results":[{}]}]}', encoding="utf-8")

    class _Failed:
        returncode = 2
        stdout = b""
        stderr = b"invalid rule"

    monkeypatch.setattr(semgrep_mod, "is_available", lambda: True)
    monkeypatch.setattr(semgrep_mod.subprocess, "run", lambda *_args, **_kwargs: _Failed())
    project_root = tmp_path / "src"
    project_root.mkdir()

    with pytest.raises(RuntimeError, match="invalid rule"):
        semgrep_mod.run_semgrep(project_root, cache_dir=tmp_path, project_id="project")

    assert not stale.exists()


def test_pack_registry_file_is_valid_json_list(tmp_path: Path) -> None:
    enable_pack_for_repo("p/x", repo_dir=tmp_path)
    raw = (tmp_path / "aics-enabled-packs.json").read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert parsed == ["p/x"]
