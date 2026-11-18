"""Tests for standalone exploit gadget discovery and linking."""

import json
from pathlib import Path

import duckdb
import pytest

from ai_codescan.gadgets import analyze_gadgets, render_gadget_report, write_gadget_artifacts
from ai_codescan.index.duckdb_schema import apply_schema


def _seed_file(
    conn: duckdb.DuckDBPyConnection,
    source_root: Path,
    *,
    name: str,
    text: str,
    project_id: str = "app",
) -> Path:
    path = source_root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    conn.execute(
        "INSERT INTO files VALUES (?, 'sha', 'javascript', ?, ?)",
        [str(path), project_id, len(text)],
    )
    return path


def _seed_prototype_pollution_flow(
    conn: duckdb.DuckDBPyConnection,
    path: Path,
    *,
    flow_id: str = "proto-flow",
) -> None:
    conn.execute(
        "INSERT INTO symbols VALUES ('sink-symbol', 'merge', 'function', ?, 1, 5, NULL, 'merge')",
        [str(path)],
    )
    conn.execute(
        "INSERT INTO taint_sources VALUES ('source', NULL, 'http.body', 'body', ?)",
        [f"{path}:1"],
    )
    conn.execute(
        "INSERT INTO taint_sinks VALUES "
        "('sink', 'sink-symbol', 'proto.pollute', 'merge', 'unknown', '[]')"
    )
    conn.execute(
        "INSERT INTO flows VALUES (?, 'source', 'sink', 'CWE-1321', 'joern', ?, '', 'likely')",
        [flow_id, json.dumps([[str(path), 1, 1]])],
    )


def test_unpaired_authorization_gadget_remains_visible(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_file(
        conn,
        source_root,
        name="auth.js",
        text="const access = {};\nif (access.isAdmin) { grantAccess(); }\n",
    )
    run_dir = tmp_path / "run"

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=run_dir)
    paths = write_gadget_artifacts(analysis, output_dir=run_dir)

    assert len(analysis.candidates) == 1
    assert analysis.links == ()
    assert "unpaired" in paths[2].read_text(encoding="utf-8")
    assert paths[0].read_text(encoding="utf-8").strip()
    conn.close()


def test_prototype_pollution_flow_links_authorization_gadget(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    path = _seed_file(
        conn,
        source_root,
        name="server.js",
        text=(
            "const access = {};\n"
            "merge(settings, req.body);\n"
            "if (access.isAdmin) { grantAccess(); }\n"
        ),
    )
    _seed_prototype_pollution_flow(conn, path)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "candidate_registry.jsonl").write_text(
        json.dumps({"candidate_id": "A-proto-flow", "fid": "proto-flow"}) + "\n",
        encoding="utf-8",
    )

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=run_dir)

    assert len(analysis.links) == 1
    assert analysis.links[0].candidate_id == "A-proto-flow"
    assert analysis.links[0].relationship == "bypass"
    assert "linked" in render_gadget_report(analysis)
    conn.close()


def test_own_property_guard_is_not_a_gadget(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_file(
        conn,
        source_root,
        name="safe.js",
        text=(
            "const access = {};\n"
            'if (Object.hasOwn(access, "isAdmin") && access.isAdmin) { grantAccess(); }\n'
        ),
    )

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    assert analysis.candidates == ()
    conn.close()


def test_gadget_does_not_link_across_files_without_execution_evidence(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    flow_path = _seed_file(
        conn,
        source_root,
        name="api/merge.js",
        text="merge(settings, req.body);\n",
        project_id="api",
    )
    _seed_file(
        conn,
        source_root,
        name="worker/auth.js",
        text="const access = {};\nif (access.isAdmin) { grantAccess(); }\n",
        project_id="worker",
    )
    _seed_prototype_pollution_flow(conn, flow_path)

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    assert len(analysis.candidates) == 1
    assert analysis.links == ()
    conn.close()


def test_child_process_command_gadget_links_to_prototype_pollution(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    path = _seed_file(
        conn,
        source_root,
        name="worker.js",
        text=(
            'const { spawn } = require("node:child_process");\n'
            "const job = {};\n"
            "merge(settings, req.body);\n"
            "spawn(job.command, job.args || []);\n"
        ),
    )
    _seed_prototype_pollution_flow(conn, path)

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    candidates = [
        candidate
        for candidate in analysis.candidates
        if candidate.gadget_class == "inherited-child-process-command"
    ]
    assert len(candidates) == 1
    assert candidates[0].capability == "command-execution"
    assert len(analysis.links) == 1
    assert analysis.links[0].relationship == "impact-amplifier"
    conn.close()


def test_safe_child_process_commands_are_not_gadgets(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_file(
        conn,
        source_root,
        name="safe-worker.js",
        text=(
            'import { spawn } from "node:child_process";\n'
            "const job = Object.create(null);\n"
            "spawn(job.command, job.args || []);\n"
        ),
    )
    _seed_file(
        conn,
        source_root,
        name="owned-command-worker.js",
        text=(
            'const { spawn } = require("node:child_process");\n'
            "const job = {};\n"
            'job.command = "convert";\n'
            "spawn(job.command, job.args || []);\n"
        ),
    )

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    assert analysis.candidates == ()
    conn.close()


def test_filesystem_path_gadget_links_to_prototype_pollution(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    path = _seed_file(
        conn,
        source_root,
        name="download.js",
        text=(
            'const { readFileSync } = require("node:fs");\n'
            "const request = {};\n"
            "merge(settings, req.body);\n"
            'const body = readFileSync(request.path, "utf8");\n'
        ),
    )
    _seed_prototype_pollution_flow(conn, path)

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    candidates = [
        candidate
        for candidate in analysis.candidates
        if candidate.gadget_class == "inherited-filesystem-path"
    ]
    assert len(candidates) == 1
    assert candidates[0].capability == "arbitrary-file-read"
    assert len(analysis.links) == 1
    assert analysis.links[0].relationship == "impact-amplifier"
    conn.close()


def test_safe_filesystem_paths_are_not_gadgets(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    _seed_file(
        conn,
        source_root,
        name="safe-download.js",
        text=(
            'import { readFileSync } from "node:fs";\n'
            "const request = Object.create(null);\n"
            'readFileSync(request.path, "utf8");\n'
        ),
    )
    _seed_file(
        conn,
        source_root,
        name="owned-path-download.js",
        text=(
            'const fs = require("node:fs");\n'
            "const request = {};\n"
            'request.path = "/srv/public/index.html";\n'
            'fs.readFileSync(request.path, "utf8");\n'
        ),
    )

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    assert analysis.candidates == ()
    conn.close()


@pytest.mark.parametrize(
    ("target_name", "expected_count"),
    (("express-proto-pollution", 1), ("express-proto-pollution-safe", 0)),
)
def test_prototype_pollution_eval_targets_cover_gadget_shapes(
    tmp_path: Path,
    target_name: str,
    expected_count: int,
) -> None:
    source_root = Path(__file__).resolve().parents[1] / "eval-targets" / target_name
    source_file = source_root / "server.js"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO files VALUES (?, 'sha', 'javascript', 'app', ?)",
        [str(source_file), source_file.stat().st_size],
    )

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    assert len(analysis.candidates) == expected_count
    conn.close()


@pytest.mark.parametrize(
    ("target_name", "expected_count"),
    (("node-proto-child-process-gadget", 1), ("node-proto-child-process-gadget-safe", 0)),
)
def test_child_process_gadget_eval_targets(
    tmp_path: Path,
    target_name: str,
    expected_count: int,
) -> None:
    source_root = Path(__file__).resolve().parents[1] / "eval-targets" / target_name
    source_file = source_root / "server.js"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO files VALUES (?, 'sha', 'javascript', 'app', ?)",
        [str(source_file), source_file.stat().st_size],
    )

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    assert len(analysis.candidates) == expected_count
    conn.close()


@pytest.mark.parametrize(
    ("target_name", "expected_count"),
    (("node-proto-file-read-gadget", 1), ("node-proto-file-read-gadget-safe", 0)),
)
def test_file_read_gadget_eval_targets(
    tmp_path: Path,
    target_name: str,
    expected_count: int,
) -> None:
    source_root = Path(__file__).resolve().parents[1] / "eval-targets" / target_name
    source_file = source_root / "server.js"
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO files VALUES (?, 'sha', 'javascript', 'app', ?)",
        [str(source_file), source_file.stat().st_size],
    )

    analysis = analyze_gadgets(conn, source_root=source_root, run_dir=tmp_path / "run")

    assert len(analysis.candidates) == expected_count
    conn.close()
