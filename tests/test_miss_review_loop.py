"""Behavior tests for resumable miss-review shell execution."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_codescan.llm import LLMConfig
from ai_codescan.review_cache import build_review_cache_key, read_review_cache_key

SKILL_DIR = Path(__file__).resolve().parents[1] / "ai_codescan" / "skills" / "miss_reviewer"
LOOP_SH = SKILL_DIR / "scripts" / "loop.sh"


def _candidate(candidate_id: str, evidence: str, llm: LLMConfig) -> dict[str, str]:
    key = build_review_cache_key(evidence, llm)
    return {
        "id": candidate_id,
        "review_evidence_fingerprint": key.evidence_fingerprint,
        "review_fingerprint": key.review_fingerprint,
        "review_model": key.model,
        "review_provider": key.provider,
    }


def _write_marker(path: Path, *, evidence: str, llm: LLMConfig) -> None:
    key = build_review_cache_key(evidence, llm)
    path.write_text(json.dumps(key.to_jsonable()), encoding="utf-8")


def _write_stub(path: Path, *, run_dir: Path, attempts: Path, allow_second: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cat - >/dev/null\n"
        f'if [[ -f "{run_dir / ".done-miss-review" / "B-miss-1"}" ]]; then '
        "candidate=B-miss-2; else candidate=B-miss-1; fi\n"
        f'printf \'%s\\n\' "$candidate" >> "{attempts}"\n'
        f'if [[ "$candidate" == B-miss-2 && ! -f "{allow_second}" ]]; then exit 1; fi\n'
        "printf '%s\\n' '<<<AI_CODESCAN_MISS_REVIEW>>>'\n"
        'printf \'{"candidate_id":"%s","classification":"false-positive",\' '
        '"$candidate"\n'
        'printf \'%s\\n\' \'"confidence":"high","rationale":"reviewed",\'\n'
        "printf '%s\\n' '\"evidence\":[],\"proposal\":{}}'\n"
        "printf '%s\\n' '<<<AI_CODESCAN_MISS_REVIEW:END>>>'\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_loop(run_dir: Path, stub: Path) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "AI_CODESCAN_RUN_DIR": str(run_dir),
        "AI_CODESCAN_SKILL_DIR": str(SKILL_DIR),
        "AI_CODESCAN_LLM_CMD": str(stub),
        "AI_CODESCAN_LLM_RETRIES": "1",
        "AI_CODESCAN_LLM_RETRY_DELAY": "0",
        "AI_CODESCAN_MISS_QUEUE": str(run_dir / "miss_review_queue.jsonl"),
        "AI_CODESCAN_MISS_REVIEW_DIR": str(run_dir / "miss_reviews"),
    }
    return subprocess.run(
        ["bash", str(LOOP_SH)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_provider_change_and_partial_failure_retry_are_cache_safe(tmp_path: Path) -> None:
    run_dir = tmp_path / "repo"
    review_dir = run_dir / "miss_reviews"
    done_dir = run_dir / ".done-miss-review"
    review_dir.mkdir(parents=True)
    done_dir.mkdir()
    claude = LLMConfig(provider="claude", model="opus")
    codex = LLMConfig(provider="codex", model="gpt-5.6-codex")
    candidates = [
        _candidate("B-miss-1", "evidence-1", codex),
        _candidate("B-miss-2", "evidence-2", codex),
    ]
    (run_dir / "miss_review_queue.jsonl").write_text(
        "".join(json.dumps(candidate) + "\n" for candidate in candidates),
        encoding="utf-8",
    )
    stale_review = review_dir / "B-miss-2.json"
    stale_review.write_text('{"candidate_id":"B-miss-2","rationale":"claude"}', encoding="utf-8")
    _write_marker(done_dir / "B-miss-2", evidence="evidence-2", llm=claude)
    attempts = tmp_path / "attempts"
    allow_second = tmp_path / "allow-second"
    stub = tmp_path / "llm.sh"
    _write_stub(stub, run_dir=run_dir, attempts=attempts, allow_second=allow_second)

    first = _run_loop(run_dir, stub)
    assert first.returncode != 0
    assert (review_dir / "B-miss-1.json").is_file()
    assert read_review_cache_key(done_dir / "B-miss-1") is not None
    assert not stale_review.exists()
    assert not (done_dir / "B-miss-2").exists()

    allow_second.touch()
    second = _run_loop(run_dir, stub)
    assert second.returncode == 0, second.stderr
    assert attempts.read_text(encoding="utf-8").splitlines() == [
        "B-miss-1",
        "B-miss-2",
        "B-miss-2",
    ]
    assert (review_dir / "B-miss-2.json").is_file()
    marker = read_review_cache_key(done_dir / "B-miss-2")
    assert marker is not None
    assert marker.provider == "codex"
    assert marker.model == "gpt-5.6-codex"
