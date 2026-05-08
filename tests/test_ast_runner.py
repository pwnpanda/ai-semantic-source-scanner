"""Tests for ai_codescan.ast.runner."""

from pathlib import Path

import pytest

from ai_codescan.ast.runner import AstJob, run_jobs


@pytest.mark.integration
def test_run_jobs_yields_records_for_typescript(tmp_path: Path) -> None:
    src = tmp_path / "x.ts"
    src.write_text("export function greet(n: string) { console.log(n); }\ngreet('hi');\n")
    jobs = [AstJob(kind="ts", project_root=tmp_path, files=[src])]
    records = list(run_jobs(jobs))
    kinds = [r["type"] for r in records]
    assert "file" in kinds
    assert any(r["type"] == "symbol" and r["name"] == "greet" for r in records)
    assert any(r["type"] == "xref" and r["kind"] == "call" for r in records)


@pytest.mark.integration
def test_run_jobs_handles_html(tmp_path: Path) -> None:
    page = tmp_path / "p.html"
    page.write_text(
        "<!doctype html><body><button onclick='x()'>b</button>"
        "<script>console.log(1)</script></body>"
    )
    jobs = [AstJob(kind="html", project_root=tmp_path, files=[page])]
    records = list(run_jobs(jobs))
    assert any(r["type"] == "html_handler" for r in records)
    assert any(r["type"] == "html_script" for r in records)
