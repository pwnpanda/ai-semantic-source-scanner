"""Tests for ai_codescan.gate."""

from pathlib import Path

from ai_codescan.gate import (
    apply_yes_to_all,
    parse_nominations,
    selected_extensions,
)


def test_parse_extracts_y_n_state(fixtures_dir: Path) -> None:
    md = (fixtures_dir / "nominations-sample.md").read_text()
    items = parse_nominations(md)
    by_id = {i.nomination_id: i for i in items}
    assert by_id["N-001"].decision == ""
    assert by_id["N-002"].decision == "y"
    assert by_id["N-003"].decision == "n"
    assert by_id["N-004"].decision == ""


def test_apply_yes_to_all_only_fills_unanswered(fixtures_dir: Path) -> None:
    md = (fixtures_dir / "nominations-sample.md").read_text()
    out = apply_yes_to_all(md)
    items = parse_nominations(out)
    assert all(i.decision in {"y", "n"} for i in items)
    by_id = {i.nomination_id: i for i in items}
    assert by_id["N-002"].decision == "y"
    assert by_id["N-003"].decision == "n"
    assert by_id["N-001"].decision == "y"
    assert by_id["N-004"].decision == "y"


def test_selected_extensions_returns_stream_c_yes(fixtures_dir: Path) -> None:
    md = (fixtures_dir / "nominations-sample.md").read_text()
    md = apply_yes_to_all(md)
    exts = selected_extensions(md)
    assert exts and exts[0].nomination_id == "N-004"
    assert "bullmq" in exts[0].yaml_body
