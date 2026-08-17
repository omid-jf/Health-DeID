from __future__ import annotations

import pytest

from health_deid.core.ids import build_deterministic_id


def test_build_deterministic_id_is_stable() -> None:
    first = build_deterministic_id(
        "span",
        record_id="record-001",
        stage="detection",
        index=1,
    )
    second = build_deterministic_id(
        "span",
        record_id="record-001",
        stage="detection",
        index=1,
    )

    assert first == second
    assert first.startswith("span_")
    assert "record-001" not in first
    assert len(first) == len("span_") + 24


def test_build_deterministic_id_changes_with_identity_components() -> None:
    ids = {
        build_deterministic_id("span", record_id="record-001", stage="detection", index=1),
        build_deterministic_id("span", record_id="record-002", stage="detection", index=1),
        build_deterministic_id("span", record_id="record-001", stage="rules", index=1),
        build_deterministic_id("span", record_id="record-001", stage="detection", index=2),
    }

    assert len(ids) == 4


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"prefix": " ", "record_id": "record-001", "stage": "detection", "index": 1},
            "prefix cannot be empty",
        ),
        (
            {"prefix": "span", "record_id": " ", "stage": "detection", "index": 1},
            "record_id cannot be empty",
        ),
        (
            {"prefix": "span", "record_id": "record-001", "stage": " ", "index": 1},
            "stage cannot be empty",
        ),
        (
            {"prefix": "span", "record_id": "record-001", "stage": "detection", "index": 0},
            "index must be at least 1",
        ),
    ],
)
def test_build_deterministic_id_rejects_invalid_components(
    kwargs: dict,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        build_deterministic_id(**kwargs)
