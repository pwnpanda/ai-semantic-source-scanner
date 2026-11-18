"""Tests for deep-analyzer queue sharding."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1] / "ai_codescan" / "skills" / "deep_analyzer"
LOOP_SH = SKILL_DIR / "scripts" / "loop.sh"


def _write_stub_llm(path: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cat - >/dev/null\n"
        "cat <<'BLOCK'\n"
        "<<<AI_CODESCAN_FINDING:STATUS=unverified>>>\n"
        "---\n"
        "finding_id: F-model-value\n"
        "nomination_id: N-model-value\n"
        "flow_id: ''\n"
        "cwe: CWE-000\n"
        "status: unverified\n"
        "title: test finding\n"
        "---\n"
        "Body.\n"
        "<<<AI_CODESCAN_FINDING:END>>>\n"
        "BLOCK\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_workers_process_disjoint_queue_shards(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    bundles = run_dir / "bundles"
    bundles.mkdir(parents=True)
    (run_dir / "findings_queue.md").write_text(
        "# Findings queue\n\n"
        "- [ ] N-001 | project | authz | src/a.ts:1 | candidate: A-one\n"
        "- [ ] N-002 | project | xss | src/b.ts:2 | candidate: A-two\n",
        encoding="utf-8",
    )
    for nomination_id in ("N-001", "N-002"):
        (bundles / f"{nomination_id}.json").write_text("{}\n", encoding="utf-8")
    stub = tmp_path / "stub_llm.sh"
    _write_stub_llm(stub)
    base_env = {
        "PATH": os.environ["PATH"],
        "AI_CODESCAN_RUN_DIR": str(run_dir),
        "AI_CODESCAN_SKILL_DIR": str(SKILL_DIR),
        "AI_CODESCAN_LLM_CMD": str(stub),
        "AI_CODESCAN_WORKER_COUNT": "2",
    }

    for worker_index in ("0", "1"):
        result = subprocess.run(
            ["bash", str(LOOP_SH)],
            env={**base_env, "AI_CODESCAN_WORKER_INDEX": worker_index},
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

    markers = {
        path.name for path in (run_dir / ".done-analyze").iterdir() if path.suffix != ".stdout"
    }
    assert markers == {"N-001", "N-002"}
    assert "candidate_id: A-one" in (run_dir / "findings" / "F-001.md").read_text()
    assert "candidate_id: A-two" in (run_dir / "findings" / "F-002.md").read_text()
