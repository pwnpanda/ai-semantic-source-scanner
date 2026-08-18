"""Regression tests for model/source-aware per-item LLM completion markers."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_codescan.storage_taint import parse_resolver_proposals

SKILLS_ROOT = Path(__file__).resolve().parents[1] / "ai_codescan" / "skills"


def _run_loop(
    skill: str,
    *,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    skill_dir = SKILLS_ROOT / skill
    complete_env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "AI_CODESCAN_LLM_RETRIES": "1",
        "AI_CODESCAN_LLM_RETRY_DELAY": "0",
        **env,
    }
    return subprocess.run(
        ["bash", str(skill_dir / "scripts" / "loop.sh")],
        env=complete_env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _write_analyzer_stub(path: Path, attempts: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cat - >/dev/null\n"
        f'printf \'%s\\n\' "$AICS_LLM_CONTEXT" >> "{attempts}"\n'
        "printf '%s\\n' '<<<AI_CODESCAN_FINDING:STATUS=unverified>>>'\n"
        "printf '%s\\n' 'status: unverified'\n"
        "printf '%s\\n' 'title: reviewed'\n"
        "printf '%s\\n' '<<<AI_CODESCAN_FINDING:END>>>'\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_analyzer_marker_binds_model_and_evidence(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    bundle_dir = run_dir / "bundles"
    bundle_dir.mkdir(parents=True)
    (run_dir / "findings_queue.md").write_text(
        "- [ ] N-001 | api | authz | source.kt:1 | rec: high | y/n: y\n",
        encoding="utf-8",
    )
    bundle = bundle_dir / "N-001.json"
    bundle.write_text('{"evidence":"first"}\n', encoding="utf-8")
    attempts = tmp_path / "analyzer-attempts"
    stub = tmp_path / "analyzer.sh"
    _write_analyzer_stub(stub, attempts)
    base_env = {
        "AI_CODESCAN_RUN_DIR": str(run_dir),
        "AI_CODESCAN_SKILL_DIR": str(SKILLS_ROOT / "deep_analyzer"),
        "AI_CODESCAN_LLM_CMD": str(stub),
        "AI_CODESCAN_LLM_CONTEXT": "claude:opus:source-v1",
    }

    first = _run_loop("deep_analyzer", env=base_env)
    assert first.returncode == 0, first.stderr
    unchanged = _run_loop("deep_analyzer", env=base_env)
    assert unchanged.returncode == 0, unchanged.stderr
    codex_env = {**base_env, "AI_CODESCAN_LLM_CONTEXT": "codex:gpt-5.6:source-v1"}
    changed_model = _run_loop("deep_analyzer", env=codex_env)
    assert changed_model.returncode == 0, changed_model.stderr
    bundle.write_text('{"evidence":"second"}\n', encoding="utf-8")
    changed_evidence = _run_loop("deep_analyzer", env=codex_env)
    assert changed_evidence.returncode == 0, changed_evidence.stderr

    assert attempts.read_text(encoding="utf-8").splitlines() == [
        "claude:opus:source-v1",
        "codex:gpt-5.6:source-v1",
        "codex:gpt-5.6:source-v1",
    ]


def _write_validator_stub(path: Path, attempts: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cat - >/dev/null\n"
        f'printf \'%s\\n\' "$AICS_LLM_CONTEXT" >> "{attempts}"\n'
        "printf '%s\\n' '<<<AI_CODESCAN_POC:EXT=py>>>'\n"
        "printf '%s\\n' 'print(\"BENIGN\")'\n"
        "printf '%s\\n' '<<<AI_CODESCAN_POC:END>>>'\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_validator_marker_binds_model_and_finding(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    findings_dir = run_dir / "findings"
    findings_dir.mkdir(parents=True)
    finding = findings_dir / "F-001.md"
    finding.write_text("status: unverified\ntitle: first\n", encoding="utf-8")
    attempts = tmp_path / "validator-attempts"
    stub = tmp_path / "validator.sh"
    _write_validator_stub(stub, attempts)
    base_env = {
        "AI_CODESCAN_RUN_DIR": str(run_dir),
        "AI_CODESCAN_SKILL_DIR": str(SKILLS_ROOT / "validator"),
        "AI_CODESCAN_LLM_CMD": str(stub),
        "AI_CODESCAN_LLM_CONTEXT": "claude:opus:source-v1",
    }

    first = _run_loop("validator", env=base_env)
    assert first.returncode == 0, first.stderr
    unchanged = _run_loop("validator", env=base_env)
    assert unchanged.returncode == 0, unchanged.stderr
    codex_env = {**base_env, "AI_CODESCAN_LLM_CONTEXT": "codex:gpt-5.6:source-v1"}
    changed_model = _run_loop("validator", env=codex_env)
    assert changed_model.returncode == 0, changed_model.stderr
    finding.write_text("status: unverified\ntitle: second\n", encoding="utf-8")
    changed_finding = _run_loop("validator", env=codex_env)
    assert changed_finding.returncode == 0, changed_finding.stderr

    assert attempts.read_text(encoding="utf-8").splitlines() == [
        "claude:opus:source-v1",
        "codex:gpt-5.6:source-v1",
        "codex:gpt-5.6:source-v1",
    ]


def _write_resolver_stub(path: Path, attempts: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cat - >/dev/null\n"
        f'printf \'%s\\n\' "$AICS_LLM_CONTEXT" >> "{attempts}"\n'
        'printf \'{"call_id":"S-1","storage_id":"cache:%s",\' '
        '"$AICS_LLM_CONTEXT" >> "$AICS_RUN_DIR/storage_resolver/proposals.jsonl"\n'
        'printf \'%s\\n\' \'"kind":"cache_key","confidence":0.9}\' '
        '>> "$AICS_RUN_DIR/storage_resolver/proposals.jsonl"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_storage_resolver_marker_binds_model_and_queue_input(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    resolver_dir = run_dir / "storage_resolver"
    inputs_dir = run_dir / "inputs"
    resolver_dir.mkdir(parents=True)
    inputs_dir.mkdir()
    queue = resolver_dir / "queue.jsonl"
    queue.write_text(json.dumps({"call_id": "S-1", "code_snippet": "cache.set(a)"}) + "\n")
    (inputs_dir / "repo.md").write_text("# Repo\n", encoding="utf-8")
    attempts = tmp_path / "resolver-attempts"
    stub = tmp_path / "resolver.sh"
    _write_resolver_stub(stub, attempts)
    base_env = {
        "AICS_RUN_DIR": str(run_dir),
        "AICS_SKILL_DIR": str(SKILLS_ROOT / "storage_taint_resolver"),
        "AICS_LLM_CMD": str(stub),
        "AICS_LLM_CONTEXT": "claude-opus",
    }

    first = _run_loop("storage_taint_resolver", env=base_env)
    assert first.returncode == 0, first.stderr
    unchanged = _run_loop("storage_taint_resolver", env=base_env)
    assert unchanged.returncode == 0, unchanged.stderr
    codex_env = {**base_env, "AICS_LLM_CONTEXT": "codex-gpt-5.6"}
    changed_model = _run_loop("storage_taint_resolver", env=codex_env)
    assert changed_model.returncode == 0, changed_model.stderr
    queue.write_text(json.dumps({"call_id": "S-1", "code_snippet": "cache.set(b)"}) + "\n")
    changed_input = _run_loop("storage_taint_resolver", env=codex_env)
    assert changed_input.returncode == 0, changed_input.stderr

    assert attempts.read_text(encoding="utf-8").splitlines() == [
        "claude-opus",
        "codex-gpt-5.6",
        "codex-gpt-5.6",
    ]
    assert parse_resolver_proposals(run_dir) == [
        {
            "call_id": "S-1",
            "storage_id": "cache:codex-gpt-5.6",
            "kind": "cache_key",
            "confidence": 0.9,
        }
    ]
