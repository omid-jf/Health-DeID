from __future__ import annotations

from math import ceil
from pathlib import Path

import pytest

from health_deid.backends.bedrock import (
    detection_input_characters,
    safeguard_input_characters,
)
from health_deid.models.config import PipelineConfig
from health_deid.pipeline.input import normalize_input_records, read_input_file
from health_deid.pipeline.precheck import estimate_cost, precheck_config


def _config(path: Path, **overrides: object) -> PipelineConfig:
    payload: dict[str, object] = {
        "run": {"output_dir": path.parent / "runs"},
        "input": {
            "path": path,
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "record_id"},
            "text_column": "text",
        },
        "detection": {"enabled": False},
    }
    payload.update(overrides)
    return PipelineConfig.model_validate(payload)


def test_precheck_checks_input_without_calling_backends(tmp_path: Path) -> None:
    source = tmp_path / "records.jsonl"
    source.write_text('{"record_id":"N001","text":"No PHI."}\n', encoding="utf-8")

    result = precheck_config(_config(source))

    assert result.ok
    assert result.record_count == 1
    assert result.errors == ()
    assert any(issue.code == "record_id_used_as_entity_id" for issue in result.issues)
    assert result.cost_estimate is not None
    assert result.cost_estimate.active_record_count == 1
    assert result.cost_estimate.estimated_total_cost_usd == 0.0
    assert result.as_dict()["cost_estimate"] == result.cost_estimate.as_dict()


def test_precheck_reports_missing_input(tmp_path: Path) -> None:
    source = tmp_path / "missing.jsonl"
    config = _config(
        source,
        detection={
            "enabled": True,
            "detectors": [
                {
                    "backend": "aws_bedrock",
                    "model_id": "us.anthropic.claude-sonnet-4-6",
                }
            ],
        },
    )

    result = precheck_config(config)

    assert not result.ok
    assert {issue.code for issue in result.errors} == {"input_unreadable"}
    assert result.as_dict()["ok"] is False


def test_cost_estimate_models_all_enabled_backends_and_excludes_blank_records(
    tmp_path: Path,
) -> None:
    source = tmp_path / "priced.jsonl"
    long_text = "A" * 201
    source.write_text(
        "\n".join(
            (
                '{"record_id":"N001","patient_id":"P1","text":"' + long_text + '","site":"north"}',
                '{"record_id":"N002","patient_id":"P2","text":"Hi","site":"south"}',
                '{"record_id":"N003","patient_id":"P3","text":" ","site":"west"}',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    config = _config(
        source,
        input={
            "path": source,
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "column", "column": "patient_id"},
            "text_column": "text",
            "metadata_columns": ["site"],
            "structured_phi_columns": {"site": "LOCATION"},
        },
        detection={
            "enabled": True,
            "detectors": [
                {
                    "backend": "aws_comprehend_medical",
                    "cost_per_100_characters_usd": 0.01,
                },
                {
                    "backend": "aws_bedrock",
                    "model_id": "us.anthropic.claude-sonnet-4-6",
                    "input_cost_per_million_tokens": 1.0,
                    "output_cost_per_million_tokens": 2.0,
                },
            ],
        },
        validation={
            "enabled": True,
            "input_cost_per_million_tokens": 3.0,
            "output_cost_per_million_tokens": 4.0,
        },
        review={"enabled": True},
    )
    records = normalize_input_records(read_input_file(config.input), config.input)

    estimate = estimate_cost(config, records)

    assert estimate.active_record_count == 2
    assert [item.backend_id for item in estimate.backends] == [
        "comprehend_medical",
        "sonnet_4_6",
        "validator",
    ]
    comprehend, detector, validator = estimate.backends
    assert comprehend.request_count == 2
    assert comprehend.input_characters == 203
    assert comprehend.billable_100_character_units == 4
    assert comprehend.estimated_input_cost_usd == pytest.approx(0.04)
    assert comprehend.estimated_output_cost_usd == 0.0

    detector_characters = [
        detection_input_characters(long_text),
        detection_input_characters("Hi"),
    ]
    detector_tokens = sum(ceil(characters / 4) for characters in detector_characters)
    assert detector.request_count == 2
    assert detector.input_characters == sum(detector_characters)
    assert detector.estimated_input_tokens == detector_tokens
    assert detector.estimated_output_tokens == 16_384
    assert detector.estimated_total_tokens == detector_tokens + 16_384
    assert detector.maximum_output_tokens_per_request == 8_192
    assert detector.estimated_input_cost_usd == pytest.approx(detector_tokens / 1_000_000)
    assert detector.estimated_output_cost_usd == pytest.approx(32_768 / 1_000_000)

    validation_characters = [
        safeguard_input_characters(
            original_text=text,
            deidentified_text=text,
        )
        for text in (long_text, "Hi")
    ]
    validation_tokens = sum(ceil(characters / 4) for characters in validation_characters)
    assert validator.request_count == 2
    assert validator.input_characters == sum(validation_characters)
    assert validator.estimated_input_tokens == validation_tokens
    assert validator.estimated_output_tokens == 8_192
    assert validator.estimated_total_tokens == validation_tokens + 8_192
    assert validator.maximum_output_tokens_per_request == 4_096
    assert validator.estimated_input_cost_usd == pytest.approx(validation_tokens * 3 / 1_000_000)
    assert validator.estimated_output_cost_usd == pytest.approx(32_768 / 1_000_000)

    expected_input = 0.04 + detector_tokens / 1_000_000 + validation_tokens * 3 / 1_000_000
    expected_output = 32_768 / 1_000_000 + 32_768 / 1_000_000
    assert estimate.estimated_input_cost_usd == pytest.approx(expected_input)
    assert estimate.estimated_output_cost_usd == pytest.approx(expected_output)
    assert estimate.estimated_total_cost_usd == pytest.approx(expected_input + expected_output)
    payload = estimate.as_dict()
    assert payload["pricing_complete"] is True
    assert len(payload["backends"]) == 3
    assert payload["notes"]


def test_cost_estimate_marks_missing_prices_and_invalid_input(tmp_path: Path) -> None:
    source = tmp_path / "unpriced.jsonl"
    source.write_text('{"record_id":"N001","text":"Note"}\n', encoding="utf-8")
    config = _config(
        source,
        detection={
            "enabled": True,
            "detectors": [{"backend": "aws_comprehend_medical"}],
        },
    )
    records = normalize_input_records(read_input_file(config.input), config.input)

    estimate = estimate_cost(config, records)

    assert not estimate.pricing_complete
    assert estimate.estimated_input_cost_usd is None
    assert estimate.estimated_output_cost_usd == 0.0
    assert estimate.estimated_total_cost_usd is None

    duplicate = tmp_path / "duplicate.jsonl"
    duplicate.write_text(
        '{"record_id":"same","text":"One"}\n{"record_id":"same","text":"Two"}\n',
        encoding="utf-8",
    )
    result = precheck_config(_config(duplicate))
    assert not result.ok
    assert any(issue.code == "input_invalid" for issue in result.errors)
    assert result.cost_estimate is None
