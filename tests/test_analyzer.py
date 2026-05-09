"""Tests for ai_codescan.analyzer (orchestrator surface)."""

from pathlib import Path

import duckdb
import pytest

from ai_codescan.analyzer import run_analyzer
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.runs.state import load_or_create


def _seed(conn: duckdb.DuckDBPyConnection, file: str) -> None:
    conn.execute("INSERT INTO files VALUES (?, 'sha', 'ts', 'p', 100)", [file])
    conn.execute(
        "INSERT INTO taint_sources VALUES ('T1', NULL, 'http.body', 'name', ?)",
        [f"{file}:2"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES "
        "('K1', NULL, 'sql.exec', 'pg', 'template-literal', '[]')"
    )
    steps = f'[["{file}", 2, 2], ["{file}", 5, 5]]'
    conn.execute(
        "INSERT INTO flows VALUES "
        "('F1', 'T1', 'K1', 'CWE-89', 'codeql', ?, '/sarif', 'definite')",
        [steps],
    )


def test_run_analyzer_writes_queue_and_slices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "source"
    src_dir.mkdir()
    src_file = src_dir / "x.ts"
    src_file.write_text(
        "// 1\nconst id = req.body.name\n// 3\n// 4\nawait db.query(`x ${id}`)\n"
    )

    db = repo_dir / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed(conn, str(src_file))
    conn.close()

    state = load_or_create(
        repo_dir, engine="codeql", temperature=0.0, target_bug_classes=["sqli"]
    )
    (state.run_dir / "nominations.md").write_text(
        "# Nominations\n\n## Stream A\n\n"
        "- [ ] N-001 | api | sqli | "
        + str(src_file)
        + " | rec: high | y/n: y\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("PATH", "/nonexistent")
    queue_path = run_analyzer(state, repo_dir=repo_dir, db_path=db)
    assert queue_path.is_file()
    queue_text = queue_path.read_text(encoding="utf-8")
    assert "N-001" in queue_text
    slice_file = state.run_dir / "slices" / "N-001.json"
    assert slice_file.is_file()
    findings_dir = state.run_dir / "findings"
    assert findings_dir.is_dir()
