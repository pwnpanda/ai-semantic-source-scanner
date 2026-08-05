"""Tests for structured analyzer review verdict persistence."""

from __future__ import annotations

from pathlib import Path

import duckdb

from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.review_verdicts import parse_review_verdict, sync_review_verdicts


def test_parse_review_verdict_reads_structured_frontmatter(tmp_path: Path) -> None:
    finding = tmp_path / "F-001.md"
    finding.write_text(
        """---
finding_id: F-001
nomination_id: N-001
flow_id: flow-1
candidate_id: N-001
cwe: CWE-89
status: unverified
analysis_verdict: true-positive
confidence: high
title: SQL injection in user lookup
evidence:
  - Program.cs:19
---

body
""",
        encoding="utf-8",
    )

    verdict = parse_review_verdict(finding)

    assert verdict is not None
    assert verdict.nomination_id == "N-001"
    assert verdict.verdict == "true-positive"
    assert verdict.confidence == "high"
    assert verdict.evidence == ["Program.cs:19"]


def test_parse_review_verdict_falls_back_from_finding_status(tmp_path: Path) -> None:
    finding = tmp_path / "F-002.md"
    finding.write_text(
        """---
status: rejected
title: Not exploitable
---

body
""",
        encoding="utf-8",
    )

    verdict = parse_review_verdict(finding)

    assert verdict is not None
    assert verdict.nomination_id == "N-002"
    assert verdict.verdict == "false-positive"


def test_sync_review_verdicts_persists_rows(tmp_path: Path) -> None:
    db = tmp_path / "index.duckdb"
    conn = duckdb.connect(str(db))
    apply_schema(conn)
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "F-003.md").write_text(
        """---
finding_id: F-003
nomination_id: N-003
flow_id: flow-3
cwe: CWE-22
status: unverified
analysis_verdict: needs-model-extension
confidence: medium
title: Path traversal model gap
---

body
""",
        encoding="utf-8",
    )

    synced = sync_review_verdicts(conn, findings)

    assert len(synced) == 1
    row = conn.execute(
        """
        SELECT nomination_id, finding_id, flow_id, verdict, confidence, cwe, title
        FROM review_verdicts
        """
    ).fetchone()
    assert row == (
        "N-003",
        "F-003",
        "flow-3",
        "needs-model-extension",
        "medium",
        "CWE-22",
        "Path traversal model gap",
    )
