"""Tests for SCIP range compatibility in prep."""

import pytest

from ai_codescan.prep import _scip_occurrence_line_range
from ai_codescan.third_party import scip_pb2


def test_scip_occurrence_line_range_reads_typed_single_line() -> None:
    occurrence = scip_pb2.Occurrence(
        single_line_range=scip_pb2.SingleLineRange(
            line=4,
            start_character=2,
            end_character=7,
        )
    )

    assert _scip_occurrence_line_range(occurrence) == (5, 5)


def test_scip_occurrence_line_range_reads_typed_multi_line() -> None:
    occurrence = scip_pb2.Occurrence(
        multi_line_range=scip_pb2.MultiLineRange(
            start_line=4,
            start_character=2,
            end_line=8,
            end_character=7,
        )
    )

    assert _scip_occurrence_line_range(occurrence) == (5, 9)


@pytest.mark.parametrize(
    ("legacy_range", "expected"),
    [
        ([4, 2, 7], (5, 5)),
        ([4, 2, 8, 7], (5, 9)),
        ([], None),
        ([4, 2], None),
    ],
)
def test_scip_occurrence_line_range_reads_legacy_ranges(
    legacy_range: list[int],
    expected: tuple[int, int] | None,
) -> None:
    occurrence = scip_pb2.Occurrence(range=legacy_range)

    assert _scip_occurrence_line_range(occurrence) == expected
