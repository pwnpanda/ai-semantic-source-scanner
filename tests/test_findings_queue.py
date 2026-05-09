"""Tests for ai_codescan.findings.queue."""

from ai_codescan.findings.queue import (
    QueueItem,
    accepted_nominations_to_queue,
    parse_queue,
    render_queue,
)


def test_accepted_nominations_round_trip() -> None:
    md = (
        "# Nominations\n\n"
        "## Stream A — Pre-traced\n\n"
        "- [ ] N-001 | api | sqli | src/x.ts:42 | rec: high | y/n: y\n"
        "    Summary: SQL injection.\n"
        "    Flows: F-1\n\n"
        "- [ ] N-002 | api | xss | src/y.ts:10 | rec: med | y/n: n\n"
        "    Summary: false positive.\n\n"
        "## Stream B — AI-discovered\n\n"
        "- [ ] N-003 | api | idor | src/z.ts:7 | rec: med | y/n: y\n"
        "    Summary: IDOR.\n"
    )
    items = accepted_nominations_to_queue(md)
    assert [i.nomination_id for i in items] == ["N-001", "N-003"]
    assert items[0].vector == "sqli"
    assert items[1].vector == "idor"


def test_render_then_parse() -> None:
    items = [QueueItem(nomination_id="N-001", project="api", vector="sqli", loc="x.ts:42")]
    md = render_queue(items)
    parsed = parse_queue(md)
    assert parsed == items
