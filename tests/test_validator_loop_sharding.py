"""Tests for validator queue sharding."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1] / "ai_codescan" / "skills" / "validator"
LOOP_SH = SKILL_DIR / "scripts" / "loop.sh"


def _write_stub_llm(path: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cat - >/dev/null\n"
        "cat <<'BLOCK'\n"
        "<<<AI_CODESCAN_POC:EXT=py>>>\n"
        "print('observation only')\n"
        "<<<AI_CODESCAN_POC:END>>>\n"
        "BLOCK\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_workers_process_disjoint_finding_shards(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    findings = run_dir / "findings"
    slices = run_dir / "slices"
    inputs = run_dir / "inputs"
    findings.mkdir(parents=True)
    slices.mkdir()
    inputs.mkdir()
    (inputs / "repo.md").write_text("# Repo\n", encoding="utf-8")
    for number in ("001", "002"):
        (findings / f"F-{number}.md").write_text(
            "status: unverified\ntitle: test finding\n",
            encoding="utf-8",
        )
        (slices / f"N-{number}.json").write_text("{}\n", encoding="utf-8")
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
        path.name for path in (run_dir / ".done-validate").iterdir() if path.suffix != ".stdout"
    }
    assert markers == {"F-001", "F-002"}
