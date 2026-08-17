"""Validated, versioned configuration models shared by the API, CLI, and UI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Final, Literal

import yaml
from pydantic import Field, Tag, TypeAdapter, field_validator, model_validator

from health_deid.backends.rules import RulesFile
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.common import StrictModel
from health_deid.models.input import EntityIdConfig, EntityIdSource, InputFormat
from health_deid.models.policy import TransformationPolicy

SAFEGUARD_MODEL_ID: Final = "openai.gpt-oss-safeguard-120b"
SAFEGUARD_MAX_OUTPUT_TOKENS = 16_384
SONNET_MODEL_ID: Final = "us.anthropic.claude-sonnet-4-6"
COMPREHEND_MAXIMUM_BYTES = 19_000
COMPREHEND_OVERLAP_CHARACTERS = 256
SONNET_MAX_OUTPUT_TOKENS = 8_192
VALIDATION_OUTPUT_TOKEN_TIERS = (4_096, 8_192, SAFEGUARD_MAX_OUTPUT_TOKENS)


class RunConfig(StrictModel):
    """Naming, output location, and optional parent lineage for one run."""

    name: str | None = None
    output_dir: Path = Path("runs")
    parent_run_id: str | None = None

    @field_validator("name", "parent_run_id")
    @classmethod
    def empty_optional_text_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class InputConfig(StrictModel):
    """Input file format, identity columns, clinical text, and structured PHI mappings."""

    kind: Literal["text_records"] = "text_records"
    path: Path
    format: InputFormat
    record_id_column: str
    entity_id: EntityIdConfig
    text_column: str
    metadata_columns: list[str] = Field(default_factory=list)
    structured_phi_columns: dict[str, PhiCategory] = Field(default_factory=dict)
    text_normalization: Literal["ftfy_default"] = "ftfy_default"

    @field_validator("record_id_column", "text_column")
    @classmethod
    def validate_required_column_names(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Column names cannot be empty.")
        return value

    @field_validator("metadata_columns")
    @classmethod
    def validate_metadata_columns(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value for value in cleaned):
            raise ValueError("Metadata column names cannot be empty.")
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("metadata_columns cannot contain duplicates.")
        return cleaned

    @model_validator(mode="after")
    def validate_column_mappings(self) -> InputConfig:
        core = {self.record_id_column, self.text_column}
        repeated = core.intersection(self.metadata_columns)
        if repeated:
            raise ValueError(
                "metadata_columns cannot repeat record_id_column or text_column: "
                + ", ".join(sorted(repeated))
            )
        if self.record_id_column == self.text_column:
            raise ValueError("record_id_column and text_column must be different columns.")
        if self.entity_id.source is EntityIdSource.COLUMN:
            assert self.entity_id.column is not None
            if self.entity_id.column == self.record_id_column:
                raise ValueError(
                    "Use entity_id.source='record_id' when entity identity comes from "
                    "record_id_column."
                )
            if self.entity_id.column == self.text_column:
                raise ValueError("The entity_id column and text_column must be different columns.")
        unknown_structured = set(self.structured_phi_columns).difference(self.metadata_columns)
        if unknown_structured:
            raise ValueError(
                "structured_phi_columns must also appear in metadata_columns: "
                + ", ".join(sorted(unknown_structured))
            )
        raw_names = {f"raw_{column}" for column in self.structured_phi_columns}
        raw_collisions = raw_names.intersection(self.metadata_columns)
        if raw_collisions:
            raise ValueError(
                "Structured fields cannot generate raw export names that collide with input "
                "columns: " + ", ".join(sorted(raw_collisions))
            )
        return self


class ExecutionConfig(StrictModel):
    """The only execution setting that materially affects a local research run."""

    workers: int = Field(default=2, ge=1, le=8)


class AwsComprehendDetectorConfig(StrictModel):
    """AWS Comprehend Medical detector settings and reporting price estimate."""

    backend: Literal["aws_comprehend_medical"] = "aws_comprehend_medical"
    region_name: str | None = None
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    cost_per_100_characters_usd: float | None = Field(default=None, ge=0.0)

    @property
    def name(self) -> str:
        return "comprehend_medical"

    @property
    def maximum_bytes(self) -> int:
        return COMPREHEND_MAXIMUM_BYTES

    @property
    def overlap_characters(self) -> int:
        return COMPREHEND_OVERLAP_CHARACTERS


class BedrockLlmDetectorConfig(StrictModel):
    """Amazon Bedrock detector settings for the supported Sonnet model."""

    backend: Literal["aws_bedrock"] = "aws_bedrock"
    model_id: Literal["us.anthropic.claude-sonnet-4-6"] = SONNET_MODEL_ID
    region_name: str | None = None
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning_effort: Literal["none", "low", "medium", "high"] = "none"
    input_cost_per_million_tokens: float | None = Field(default=None, ge=0.0)
    output_cost_per_million_tokens: float | None = Field(default=None, ge=0.0)

    @property
    def name(self) -> str:
        return "sonnet_4_6"

    @property
    def max_output_tokens(self) -> int:
        return SONNET_MAX_OUTPUT_TOKENS


DetectorConfig = Annotated[
    Annotated[AwsComprehendDetectorConfig, Tag("aws_comprehend_medical")]
    | Annotated[BedrockLlmDetectorConfig, Tag("aws_bedrock")],
    Field(discriminator="backend"),
]


class DetectionConfig(StrictModel):
    """Enabled PHI detector backends and their shared request controls."""

    enabled: bool = False
    detectors: list[DetectorConfig] = Field(default_factory=list)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)

    @model_validator(mode="before")
    @classmethod
    def infer_enabled_from_detectors(cls, value: Any) -> Any:
        if not isinstance(value, dict) or "enabled" in value:
            return value
        return {**value, "enabled": bool(value.get("detectors"))}

    @model_validator(mode="after")
    def validate_detectors(self) -> DetectionConfig:
        backends = [detector.backend for detector in self.detectors]
        if len(backends) != len(set(backends)):
            raise ValueError("Each detector can be configured only once.")
        if self.enabled and not self.detectors:
            raise ValueError("Enabled detection requires at least one enabled detector.")

        return self


class RulesConfig(StrictModel):
    """Optional deterministic rules supplied by path or embedded snapshot."""

    enabled: bool = False
    rules_path: Path | None = None
    embedded: RulesFile | None = None

    @model_validator(mode="after")
    def validate_rule_source(self) -> RulesConfig:
        sources = int(self.rules_path is not None) + int(self.embedded is not None)
        if self.enabled and sources != 1:
            raise ValueError(
                "Exactly one of rules.rules_path or rules.embedded is required "
                "when rules.enabled=true."
            )
        if not self.enabled and sources:
            raise ValueError("Rule sources require rules.enabled=true.")
        return self


class ValidationConfig(StrictModel):
    """Automated residual-PHI validation settings and adaptive token tiers."""

    enabled: bool = False
    backend: Literal["aws_bedrock_safeguard"] = "aws_bedrock_safeguard"
    model_id: Literal["openai.gpt-oss-safeguard-120b"] = SAFEGUARD_MODEL_ID
    region_name: str | None = None
    input_cost_per_million_tokens: float | None = Field(default=None, ge=0.0)
    output_cost_per_million_tokens: float | None = Field(default=None, ge=0.0)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)

    @property
    def output_token_tiers(self) -> tuple[int, ...]:
        return VALIDATION_OUTPUT_TOKEN_TIERS


class ReviewConfig(StrictModel):
    """Human-review enablement and queue scope."""

    enabled: bool = False
    review_scope: Literal["effective_validation_failures", "all"] = "effective_validation_failures"


class PipelineConfig(StrictModel):
    """Complete versioned configuration for one de-identification run."""

    config_version: Literal[1] = 1
    run: RunConfig = Field(default_factory=RunConfig)
    input: InputConfig
    policy: TransformationPolicy = Field(default_factory=TransformationPolicy)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    review: ReviewConfig = Field(default_factory=ReviewConfig)

    @model_validator(mode="after")
    def validate_pipeline_contract(self) -> PipelineConfig:
        if self.validation.enabled and not self.review.enabled:
            raise ValueError("Automated validation requires human review of validator concerns.")
        if (
            self.review.enabled
            and not self.validation.enabled
            and self.review.review_scope != "all"
        ):
            raise ValueError("Review without automated validation requires review_scope='all'.")
        return self


_CONFIG_ADAPTER = TypeAdapter(PipelineConfig)


def load_config(config_path: str | Path) -> PipelineConfig:
    """Load and validate a versioned pipeline configuration from YAML."""

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Config path is not a file: {path}")
    with path.open("r", encoding="utf-8") as file:
        raw_config: Any = yaml.safe_load(file)
    if raw_config is None:
        raise ValueError(f"Config file is empty: {path}")
    if not isinstance(raw_config, dict):
        raise ValueError("Top-level YAML config must be a mapping/object.")
    return _CONFIG_ADAPTER.validate_python(raw_config)
