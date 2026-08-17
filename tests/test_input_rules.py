from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast

import polars as pl
import pytest
from pydantic import ValidationError

from health_deid.backends.contracts import PhiValidator
from health_deid.backends.rules import (
    RedactionRule,
    RulesFile,
    find_rule_candidates,
    load_rules_file,
)
from health_deid.core.ids import build_content_id
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.config import InputConfig, PipelineConfig, RulesConfig
from health_deid.models.input import InputFormat
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.detection import _configured_rules
from health_deid.pipeline.input import (
    build_input_import_summary,
    json_compatible_object,
    normalize_input_frame,
    normalize_input_records,
    normalized_records_to_frame,
    read_input_source,
    scan_input_source,
)


def _input_config(path: Path, *, metadata: bool = True) -> InputConfig:
    return InputConfig.model_validate(
        {
            "path": path,
            "format": "parquet",
            "record_id_column": "rid",
            "entity_id": {"source": "column", "column": "eid"},
            "text_column": "text",
            "metadata_columns": ["event_date"] if metadata else [],
            "structured_phi_columns": {"event_date": "DATE"} if metadata else {},
        }
    )


def _pipeline_config(path: Path, output_dir: Path) -> PipelineConfig:
    return PipelineConfig.model_validate(
        {
            "run": {"name": "  Demo / run  ", "output_dir": output_dir},
            "input": _input_config(path).model_dump(mode="python"),
        }
    )


def _raw_frame() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "rid": [" a ", "b", "c"],
            "eid": [" e ", "f", "g"],
            "text": ["FranÃ§ois", None, "   "],
            "event_date": [date(2025, 1, 1), None, date(2025, 1, 3)],
        }
    )


def test_normalization_covers_audits_exclusions_metadata_and_frame_views(tmp_path: Path) -> None:
    config = _input_config(tmp_path / "input.parquet")
    records = normalize_input_records(_raw_frame(), config)

    assert [(item.record_id, item.entity_id) for item in records] == [
        ("a", "e"),
        ("b", "f"),
        ("c", "g"),
    ]
    assert records[0].raw_source_text == "FranÃ§ois"
    assert records[0].source_text == "François"
    assert records[0].text_normalization.changed
    assert records[0].metadata == {"event_date": "2025-01-01"}
    assert records[1].status == "excluded"
    assert records[1].exclusion is not None
    assert records[1].text_normalization.raw_sha256 is None
    assert records[2].status == "excluded"

    public = normalized_records_to_frame(records, include_raw_source_text=False)
    private = normalized_records_to_frame(records, include_raw_source_text=True)
    assert "raw_source_text" not in public.columns
    assert "raw_source_text" in private.columns
    assert private.get_column("stage_errors").to_list()[0] == []
    assert len(private.get_column("stage_errors").to_list()[1]) == 1

    context = RunContext.from_config(
        _pipeline_config(tmp_path / "input.parquet", tmp_path / "runs"),
        timestamp=datetime(2025, 1, 2, 3, 4, 5),
    )
    normalized = normalize_input_frame(_raw_frame(), context)
    assert normalized.height == 3
    assert context.run_id == "20250102T030405_Demo-run"
    assert context.created_at.tzinfo is UTC


def test_normalization_rejects_invalid_rows_and_supports_empty_metadata(tmp_path: Path) -> None:
    config = _input_config(tmp_path / "input.parquet")
    empty = pl.DataFrame(
        schema={"rid": pl.String, "eid": pl.String, "text": pl.String, "event_date": pl.Date}
    )
    with pytest.raises(ValueError, match="at least one"):
        normalize_input_records(empty, config)

    with pytest.raises(ValueError, match="missing required columns: event_date"):
        normalize_input_records(_raw_frame().drop("event_date"), config)

    null_id = _raw_frame().with_columns(pl.lit(None).alias("rid"))
    with pytest.raises(ValueError, match="null or blank record"):
        normalize_input_records(null_id, config)

    blank_entity = _raw_frame().with_columns(pl.lit(" ").alias("eid"))
    with pytest.raises(ValueError, match="null or blank entity"):
        normalize_input_records(blank_entity, config)

    duplicate = _raw_frame().with_columns(pl.Series("rid", ["same", " same ", "other"]))
    with pytest.raises(ValueError, match="must be unique"):
        normalize_input_records(duplicate, config)

    no_metadata = _input_config(tmp_path / "input.parquet", metadata=False)
    records = normalize_input_records(_raw_frame().drop("event_date"), no_metadata)
    assert [item.metadata for item in records] == [{}, {}, {}]


def test_import_summary_and_json_conversion_are_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "notes.parquet"
    frame = _raw_frame()
    frame.write_parquet(source)
    config = _input_config(source)
    records = normalize_input_records(frame, config)
    imported_at = datetime(2025, 1, 1, tzinfo=UTC)

    summary = build_input_import_summary(config, records, imported_at=imported_at)

    assert summary.source_name == "notes.parquet"
    assert summary.source_path == source.resolve()
    assert summary.source_size_bytes == source.stat().st_size
    assert summary.record_count == 3
    assert summary.active_count == 1
    assert summary.excluded_count == 2
    assert summary.normalized_count == 1
    assert summary.imported_at == imported_at
    assert len(summary.source_sha256) == 64
    assert json_compatible_object({"day": date(2025, 2, 3), "blob": b"x"}) == {
        "day": "2025-02-03",
        "blob": "eA==",
    }


def test_input_readers_cover_formats_path_validation_and_bad_format(tmp_path: Path) -> None:
    parquet = tmp_path / "records.parquet"
    jsonl = tmp_path / "records.jsonl"
    pl.DataFrame({"rid": ["1"], "text": ["note"]}).write_parquet(parquet)
    jsonl.write_text('{"rid":"1","text":"note"}\n', encoding="utf-8")

    assert read_input_source(parquet, "parquet").height == 1
    assert read_input_source(jsonl, "jsonl").height == 1
    assert scan_input_source(parquet, "parquet").collect().height == 1
    assert scan_input_source(jsonl, "jsonl").collect().height == 1

    with pytest.raises(FileNotFoundError):
        read_input_source(tmp_path / "missing.parquet", "parquet")
    with pytest.raises(ValueError, match="not a file"):
        read_input_source(tmp_path, "parquet")
    with pytest.raises(ValueError, match="Unsupported input format: csv"):
        read_input_source(parquet, cast(InputFormat, "csv"))
    with pytest.raises(ValueError, match="Unsupported input format: csv"):
        scan_input_source(parquet, cast(InputFormat, "csv"))


def test_rule_loading_validation_and_candidate_semantics(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"
    with pytest.raises(FileNotFoundError):
        load_rules_file(missing)
    with pytest.raises(ValueError, match="not a file"):
        load_rules_file(tmp_path)

    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_rules_file(empty)

    sequence = tmp_path / "sequence.yaml"
    sequence.write_text("- bad", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping/object"):
        load_rules_file(sequence)

    valid = tmp_path / "rules.yaml"
    valid.write_text(
        "rules:\n"
        "  - id: hospital\n"
        "    name: Hospital marker\n"
        "    category: LOCATION\n"
        "    pattern: hospital\n"
        "    ignore_case: true\n"
        "  - id: empty-match\n"
        "    name: Zero width\n"
        "    category: OTHER_ID\n"
        "    pattern: '^'\n",
        encoding="utf-8",
    )
    rules = load_rules_file(valid)
    configured_rules, source_name = _configured_rules(RulesConfig(enabled=True, rules_path=valid))
    assert configured_rules == rules
    assert source_name == str(valid)

    candidates = find_rule_candidates("HOSPITAL and hospital", rules)
    assert [item.text for item in candidates] == ["HOSPITAL", "hospital"]
    assert [item.backend_span_id for item in candidates] == ["hospital:1", "hospital:2"]
    assert candidates[0].category is PhiCategory.LOCATION
    assert candidates[0].native_payload == {
        "rule_id": "hospital",
        "rule_name": "Hospital marker",
    }


@pytest.mark.parametrize("field", ["id", "name", "pattern"])
def test_rule_fields_cannot_be_blank(field: str) -> None:
    payload = {
        "id": "rule",
        "name": "Rule",
        "category": "NAME",
        "pattern": "name",
    }
    payload[field] = " "
    with pytest.raises(ValidationError, match="cannot be empty"):
        RedactionRule.model_validate(payload)


def test_rule_regex_and_unique_id_contracts() -> None:
    with pytest.raises(ValidationError, match="Invalid rule regex"):
        RedactionRule(id="bad", name="Bad", category=PhiCategory.NAME, pattern="[")
    exact = RedactionRule(
        id="literal",
        name="Literal",
        category=PhiCategory.NAME,
        type="exact",
        pattern="[",
    )
    assert exact.pattern == "["
    rule = RedactionRule(id="same", name="One", category=PhiCategory.NAME, pattern="x")
    with pytest.raises(ValidationError, match="must be unique"):
        RulesFile(rules=[rule, rule.model_copy(update={"name": "Two"})])


def test_small_contract_edges_are_explicit() -> None:
    with pytest.raises(ValueError, match="prefix cannot be empty"):
        build_content_id(" ", "value")
    with pytest.raises(NotImplementedError):
        PhiValidator.validate(
            cast(PhiValidator, object()), original_text="a", deidentified_text="b"
        )
