"""The nominator loop must survive a transient LLM failure.

Provider rate limits surface as a non-zero exit from the CLI. Without a retry
the loop marks the item failed and moves on, so one throttle burns every
remaining candidate in a long queue.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1] / "ai_codescan" / "skills" / "wide_nominator"
LOOP_SH = SKILL_DIR / "scripts" / "loop.sh"

_ID_LINE = re.compile(r"^- \[[ xX]\]\s*(N-\d+)\s*\|", re.MULTILINE)

_BLOCK = (
    "<<<AI_CODESCAN_NOMINATION:STREAM=A>>>\n"
    "- [ ] N-001 | proj | vector | src/a.ts:1 | rec: high | y/n:\n"
    "    Summary: a candidate\n"
    "<<<AI_CODESCAN_NOMINATION:END>>>"
)


def _make_run_dir(tmp_path: Path, *, candidates: int) -> Path:
    run_dir = tmp_path / "run"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "queue.jsonl").write_text(
        "".join(f'{{"id": "A-{i}"}}\n' for i in range(candidates)),
        encoding="utf-8",
    )
    return run_dir


def _run_loop(run_dir: Path, stub: Path) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "AI_CODESCAN_RUN_DIR": str(run_dir),
        "AI_CODESCAN_SKILL_DIR": str(SKILL_DIR),
        "AI_CODESCAN_LLM_CMD": str(stub),
        "AI_CODESCAN_SOURCE_ROOT": str(run_dir / "source"),
        "AI_CODESCAN_LLM_RETRY_DELAY": "0",
        "AI_CODESCAN_LLM_RETRIES": "3",
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
def test_transient_llm_failure_is_retried(tmp_path: Path) -> None:
    """First call exits non-zero (throttled), second succeeds."""
    run_dir = _make_run_dir(tmp_path, candidates=1)
    counter = tmp_path / "calls"
    counter.write_text("", encoding="utf-8")
    stub = tmp_path / "flaky_llm.sh"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "cat - >/dev/null\n"
        f'printf x >> "{counter}"\n'
        f'if [[ "$(wc -c < "{counter}")" -lt 2 ]]; then exit 1; fi\n'
        f"cat <<'BLOCK'\n{_BLOCK}\nBLOCK\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)

    result = _run_loop(run_dir, stub)
    assert result.returncode == 0, result.stderr

    ids = _ID_LINE.findall((run_dir / "nominations.md").read_text(encoding="utf-8"))
    assert ids == ["N-001"], f"transient failure lost the candidate: {result.stderr}"
    assert counter.read_text(encoding="utf-8") == "xx", "expected exactly one retry"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")
def test_persistent_llm_failure_gives_up_without_killing_the_loop(tmp_path: Path) -> None:
    """A candidate whose every attempt fails is skipped, not fatal."""
    run_dir = _make_run_dir(tmp_path, candidates=1)
    stub = tmp_path / "dead_llm.sh"
    stub.write_text("#!/usr/bin/env bash\ncat - >/dev/null\nexit 1\n", encoding="utf-8")
    stub.chmod(0o755)

    result = _run_loop(run_dir, stub)
    assert result.returncode == 0, result.stderr
    assert "FAIL (llm error)" in result.stderr
    ids = _ID_LINE.findall((run_dir / "nominations.md").read_text(encoding="utf-8"))
    assert ids == []


ALL_LOOPS = sorted(
    (Path(__file__).resolve().parents[1] / "ai_codescan" / "skills").glob("*/scripts/loop.sh")
)


def test_every_skill_loop_retries_a_throttled_llm() -> None:
    """Each skill drives its own loop; a retry in only some of them is a gap.

    The first pass patched three of six, so a throttle during miss-review still
    burned that queue. Assert the property across every loop instead.
    """
    assert ALL_LOOPS, "no skill loops found"
    missing = [
        p.parent.parent.name
        for p in ALL_LOOPS
        if "_LLM_RETRIES" not in p.read_text(encoding="utf-8")
    ]
    assert not missing, f"skill loops with no LLM retry: {missing}"
