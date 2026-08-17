from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.config import PipelineConfig, load_config
from health_deid.models.policy import TransformationPolicy


def _base_config() -> dict[str, object]:
    return {
        "config_version": 1,
        "run": {"name": "sample-run", "output_dir": "runs"},
        "input": {
            "path": "data/notes.parquet",
            "format": "parquet",
            "record_id_column": "note_id",
            "entity_id": {"source": "record_id"},
            "text_column": "text",
            "metadata_columns": ["note_date", "note_type"],
            "structured_phi_columns": {"note_date": "DATE"},
        },
        "detection": {
            "detectors": [
                {
                    "backend": "aws_comprehend_medical",
                    "region_name": "us-east-1",
                    "min_confidence": 0.25,
                },
                {
                    "backend": "aws_bedrock",
                    "model_id": "us.anthropic.claude-sonnet-4-6",
                },
            ]
        },
    }


def _write_config(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def test_load_valid_initial_config_and_defaults(tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, _base_config()))

    assert config.config_version == 1
    assert config.run.name == "sample-run"
    assert config.input.record_id_column == "note_id"
    assert config.input.entity_id.source == "record_id"
    assert config.input.structured_phi_columns == {"note_date": PhiCategory.DATE}
    assert [item.name for item in config.detection.detectors] == [
        "comprehend_medical",
        "sonnet_4_6",
    ]
    assert config.detection.enabled
    assert config.detection.execution.workers == 2
    assert config.validation.model_id == "openai.gpt-oss-safeguard-120b"
    assert not config.rules.enabled
    assert not config.review.enabled
    assert config.policy == TransformationPolicy()


def test_config_accepts_bedrock_and_embedded_replacement_settings() -> None:
    payload = _base_config()
    payload["detection"] = {
        "detectors": [{"backend": "aws_bedrock", "model_id": "us.anthropic.claude-sonnet-4-6"}]
    }
    policy = TransformationPolicy().model_dump(mode="json")
    policy["categories"]["NAME"] = {
        "action": "surrogate",
        "surrogate": {
            "method": "custom_list",
            "consistency": "entity",
            "values": [" Test Person ", "Second Person"],
            "secret_reference": "env:NAME_KEY",
        },
    }
    payload["policy"] = policy

    config = PipelineConfig.model_validate(payload)

    assert config.detection.detectors[0].backend == "aws_bedrock"
    assert config.policy.categories[PhiCategory.NAME].surrogate.values[0] == "Test Person"
    assert config.policy.categories[PhiCategory.NAME].action == "surrogate"


def test_adaptive_reasoning_is_limited_to_sonnet_46() -> None:
    payload = _base_config()
    payload["detection"] = {
        "detectors": [
            {
                "backend": "aws_bedrock",
                "model_id": "anthropic.claude-sonnet-4-5-v1:0",
                "reasoning_effort": "medium",
            }
        ]
    }

    with pytest.raises(ValidationError, match="us.anthropic.claude-sonnet-4-6"):
        PipelineConfig.model_validate(payload)

    payload["detection"]["detectors"][0]["model_id"] = "us.anthropic.claude-sonnet-4-6"
    config = PipelineConfig.model_validate(payload)
    assert config.detection.detectors[0].reasoning_effort == "medium"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda p: p["input"].update(record_id_column="text"), "different"),
        (lambda p: p["input"].update(metadata_columns=["text"]), "cannot repeat"),
        (lambda p: p["input"].update(metadata_columns=["x", "x"]), "duplicates"),
        (
            lambda p: p["input"].update(entity_id={"source": "column", "column": "note_id"}),
            "source='record_id'",
        ),
        (
            lambda p: p["input"].update(entity_id={"source": "column", "column": "text"}),
            "entity_id column",
        ),
        (
            lambda p: p["input"].update(structured_phi_columns={"missing": "DATE"}),
            "must also appear",
        ),
        (
            lambda p: p["input"].update(
                metadata_columns=["note_date", "note_type", "raw_note_date"]
            ),
            "collide with input columns",
        ),
    ],
)
def test_input_mapping_contracts(mutation, message: str) -> None:
    payload = _base_config()
    mutation(payload)
    with pytest.raises(ValidationError, match=message):
        PipelineConfig.model_validate(payload)


@pytest.mark.parametrize(
    "value",
    [
        {"workers": 0},
        {"workers": 9},
    ],
)
def test_execution_bounds_are_consistent(value: dict[str, object]) -> None:
    payload = _base_config()
    payload["detection"]["execution"] = value
    with pytest.raises(ValidationError):
        PipelineConfig.model_validate(payload)


def test_detectors_are_fixed_unique_backends() -> None:
    payload = _base_config()
    payload["detection"] = {
        "detectors": [
            {"backend": "aws_bedrock", "model_id": "us.anthropic.claude-sonnet-4-6"},
            {"backend": "aws_bedrock", "model_id": "us.anthropic.claude-sonnet-4-6"},
        ]
    }
    with pytest.raises(ValidationError, match="only once"):
        PipelineConfig.model_validate(payload)

    payload["detection"] = {"enabled": True, "detectors": []}
    with pytest.raises(ValidationError, match="at least one"):
        PipelineConfig.model_validate(payload)

    payload = _base_config()
    del payload["detection"]
    config = PipelineConfig.model_validate(payload)
    assert not config.detection.enabled
    assert config.detection.detectors == []


def test_rules_review_validation_and_token_tier_contracts() -> None:
    payload = _base_config()
    payload["rules"] = {"enabled": True}
    with pytest.raises(ValidationError, match="rules_path"):
        PipelineConfig.model_validate(payload)

    payload = _base_config()
    payload["review"] = {"enabled": True}
    with pytest.raises(ValidationError, match="review_scope='all'"):
        PipelineConfig.model_validate(payload)

    payload["review"] = {"enabled": True, "review_scope": "all"}
    assert PipelineConfig.model_validate(payload).review.enabled

    payload = _base_config()
    payload["validation"] = {"enabled": True}
    with pytest.raises(ValidationError, match="requires human review"):
        PipelineConfig.model_validate(payload)

    payload["review"] = {"enabled": True}
    payload["validation"] = {"enabled": True, "model_id": "unsupported-model"}
    with pytest.raises(ValidationError):
        PipelineConfig.model_validate(payload)

    payload = _base_config()
    payload["rules"] = {
        "enabled": False,
        "embedded": {
            "rules": [
                {
                    "id": "unused",
                    "name": "Unused",
                    "category": "NAME",
                    "type": "exact",
                    "pattern": "Alice",
                }
            ]
        },
    }
    with pytest.raises(ValidationError, match="enabled=true"):
        PipelineConfig.model_validate(payload)


def test_load_config_rejects_bad_files_and_top_level_values(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml")
    with pytest.raises(ValueError, match="not a file"):
        load_config(tmp_path)
    with pytest.raises(ValueError, match="empty"):
        load_config(_write_config(tmp_path, None))
    with pytest.raises(ValueError, match="mapping/object"):
        load_config(_write_config(tmp_path, ["bad"]))
