"""Tests for the wide-nominator loop script's nomination ingest.

Drives the real ``skills/wide_nominator/scripts/loop.sh`` with a stub LLM so
the shipped bash/python ingest path is what gets exercised.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1] / "ai_codescan" / "skills" / "wide_nominator"
LOOP_SH = SKILL_DIR / "scripts" / "loop.sh"

_ID_LINE = re.compile(r"^- \[[ xX]\]\s*(N-\d+)\s*\|", re.MULTILINE)


def _write_stub_llm(path: Path, *, block: str) -> None:
    """Stub LLM: drains the prompt on stdin, prints a fixed nomination block."""
    path.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\ncat - >/dev/null\n"
        f"cat <<'BLOCK'\n{block}\nBLOCK\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_loop(run_dir: Path, stub: Path) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "AI_CODESCAN_RUN_DIR": str(run_dir),
        "AI_CODESCAN_SKILL_DIR": str(SKILL_DIR),
        "AI_CODESCAN_LLM_CMD": str(stub),
        "AI_CODESCAN_SOURCE_ROOT": str(run_dir / "source"),
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
def test_colliding_nomination_ids_are_renumbered(tmp_path: Path) -> None:
    """Every iteration is a fresh LLM call that guesses ``N-001``.

    The harness owns the id: three colliding blocks must land as three
    distinct nominations, not collapse into one.
    """
    run_dir = tmp_path / "run"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "inputs" / "repo.md").write_text("# Repo\n", encoding="utf-8")
    (run_dir / "queue.jsonl").write_text(
        '{"id": "A-one"}\n{"id": "A-two"}\n{"id": "A-three"}\n',
        encoding="utf-8",
    )
    stub = tmp_path / "stub_llm.sh"
    _write_stub_llm(
        stub,
        block=(
            "<<<AI_CODESCAN_NOMINATION:STREAM=A>>>\n"
            "- [ ] N-001 | proj | some-vector | src/a.ts:1 | rec: high | y/n:\n"
            "    Summary: a candidate\n"
            "<<<AI_CODESCAN_NOMINATION:END>>>"
        ),
    )

    result = _run_loop(run_dir, stub)
    assert result.returncode == 0, result.stderr

    ids = _ID_LINE.findall((run_dir / "nominations.md").read_text(encoding="utf-8"))
    assert len(ids) == 3, f"expected 3 nomination lines, got {ids}"
    assert sorted(ids) == ["N-001", "N-002", "N-003"]


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_nomination_body_is_preserved_when_renumbering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "queue.jsonl").write_text('{"id": "A-only"}\n', encoding="utf-8")
    stub = tmp_path / "stub_llm.sh"
    _write_stub_llm(
        stub,
        block=(
            "<<<AI_CODESCAN_NOMINATION:STREAM=B>>>\n"
            "- [ ] N-042 | dp-web | open-redirect | server.js:45 | rec: med | y/n:\n"
            "    Summary: redirect built from the Host header\n"
            "    Heuristic: reflected header reaches res.redirect\n"
            "<<<AI_CODESCAN_NOMINATION:END>>>"
        ),
    )

    result = _run_loop(run_dir, stub)
    assert result.returncode == 0, result.stderr

    body = (run_dir / "nominations.md").read_text(encoding="utf-8")
    assert "- [ ] N-001 | dp-web | open-redirect | server.js:45 | rec: med | y/n:" in body
    assert "Summary: redirect built from the Host header" in body
    assert "Heuristic: reflected header reaches res.redirect" in body
    # Stream B block must land under the Stream B header, not Stream A.
    stream_b_at = body.index("## Stream B")
    stream_c_at = body.index("## Stream C")
    assert stream_b_at < body.index("open-redirect") < stream_c_at
