from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import cast

import polars as pl
import pytest

from health_deid.models.input import InputFormat
from health_deid.pipeline.input import preview_input_file


def test_preview_parquet_returns_schema_counts_and_bounded_json_sample(tmp_path: Path) -> None:
    path = tmp_path / "records.parquet"
    pl.DataFrame(
        {
            "record_id": ["N001", "N002", "N003"],
            "event_date": [date(2026, 1, 1), date(2026, 1, 2), date(2026, 1, 3)],
            "text": ["one", "two", "three"],
        }
    ).write_parquet(path)

    preview = preview_input_file(path, "parquet", sample_size=2)

    assert preview.path == path.resolve()
    assert preview.format == "parquet"
    assert preview.total_records == 3
    assert [(column.name, column.dtype) for column in preview.columns] == [
        ("record_id", "String"),
        ("event_date", "Date"),
        ("text", "String"),
    ]
    assert preview.sample_records == [
        {"record_id": "N001", "event_date": "2026-01-01", "text": "one"},
        {"record_id": "N002", "event_date": "2026-01-02", "text": "two"},
    ]


def test_preview_jsonl_uses_lazy_json_scanner(tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    path.write_text(
        '{"record_id":"N001","text":"one"}\n{"record_id":"N002","text":"two"}\n',
        encoding="utf-8",
    )

    preview = preview_input_file(path, "jsonl", sample_size=1)

    assert preview.total_records == 2
    assert preview.sample_records == [{"record_id": "N001", "text": "one"}]


@pytest.mark.parametrize("sample_size", [0, 101])
def test_preview_rejects_out_of_range_sample_size(tmp_path: Path, sample_size: int) -> None:
    with pytest.raises(ValueError, match="between 1 and 100"):
        preview_input_file(tmp_path / "unused.parquet", "parquet", sample_size=sample_size)


def test_preview_rejects_unsupported_format(tmp_path: Path) -> None:
    path = tmp_path / "records.parquet"
    pl.DataFrame({"record_id": ["N001"]}).write_parquet(path)

    with pytest.raises(ValueError, match="Unsupported input format: csv"):
        preview_input_file(path, cast(InputFormat, "csv"))
