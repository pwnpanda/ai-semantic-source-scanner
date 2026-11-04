"""Tests for ai_codescan.ast.runner."""

import logging
from pathlib import Path

import pytest

from ai_codescan.ast import runner as runner_mod
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


def test_perl_jobs_skipped_when_ppi_missing(tmp_path, monkeypatch, caplog) -> None:
    """A repo carrying .pl files must still prep on a host without PPI.

    The Perl worker is an optional dependency; when it is unavailable the
    Perl jobs are dropped with a warning instead of failing the whole scan.
    """
    monkeypatch.setattr(runner_mod, "perl_worker_available", lambda: False)

    script = tmp_path / "helper.pl"
    script.write_text("sub main { print 'hi'; }\n", encoding="utf-8")
    job = runner_mod.AstJob(kind="perl", project_root=tmp_path, files=[script])

    with caplog.at_level(logging.WARNING):
        records = list(runner_mod.run_jobs([job]))

    assert records == []
    assert any("perl AST worker unavailable" in m for m in caplog.messages)


def test_perl_and_node_jobs_are_routed_to_their_own_workers(tmp_path, monkeypatch) -> None:
    """run_jobs partitions by language and merges both streams."""
    seen: list[list[str]] = []

    def fake_worker(argv, job_list):
        seen.append([argv[0], *[j.kind for j in job_list]])
        for job in job_list:
            yield {"type": "file", "file": str(job.files[0]), "lang": job.kind}

    monkeypatch.setattr(runner_mod, "_run_worker", fake_worker)
    monkeypatch.setattr(runner_mod, "perl_worker_available", lambda: True)

    pl = tmp_path / "a.pl"
    js = tmp_path / "b.js"
    pl.write_text("1;\n", encoding="utf-8")
    js.write_text("1;\n", encoding="utf-8")

    records = list(
        runner_mod.run_jobs(
            [
                runner_mod.AstJob(kind="ts", project_root=tmp_path, files=[js]),
                runner_mod.AstJob(kind="perl", project_root=tmp_path, files=[pl]),
            ]
        )
    )

    assert seen == [["node", "ts"], ["perl", "perl"]]
    assert {r["lang"] for r in records} == {"ts", "perl"}
