from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

from health_deid.models.common import StrictModel

PipelineStatus = Literal["active", "needs_review", "excluded", "error"]
InputFormat = Literal["parquet", "jsonl"]
NonBlankId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class EntityIdSource(StrEnum):
    """How import resolves a stable entity identifier across related records."""

    COLUMN = "column"
    RECORD_ID = "record_id"


class EntityIdConfig(StrictModel):
    """Explicit entity identity mapping."""

    source: EntityIdSource
    column: str | None = None

    @field_validator("column")
    @classmethod
    def normalize_column(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("entity_id column cannot be blank.")
        return value

    @model_validator(mode="after")
    def validate_source_and_column(self) -> EntityIdConfig:
        if self.source is EntityIdSource.COLUMN and self.column is None:
            raise ValueError("entity_id column is required when source='column'.")
        if self.source is EntityIdSource.RECORD_ID and self.column is not None:
            raise ValueError("entity_id column must be omitted when source='record_id'.")
        return self

    def source_column(self, *, record_id_column: str) -> str:
        if self.source is EntityIdSource.RECORD_ID:
            return record_id_column
        assert self.column is not None
        return self.column


class StageError(StrictModel):
    stage: str
    code: str
    message: str

    @field_validator("stage", "code", "message")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Stage error fields cannot be empty.")

        return value


class TextNormalizationAudit(StrictModel):
    """Reproducibility metadata for one normalized source-text value."""

    normalizer: Literal["ftfy.fix_text"] = "ftfy.fix_text"
    normalizer_version: str
    changed: bool
    raw_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    normalized_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class NormalizedInputRecord(StrictModel):
    """Canonical record persisted by the transactional input stage."""

    source_index: int = Field(ge=0)
    record_id: NonBlankId
    entity_id: NonBlankId
    raw_source_text: str | None
    source_text: str | None
    text_normalization: TextNormalizationAudit
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    status: Literal["active", "excluded"]
    exclusion: StageError | None = None


class InputColumnPreview(StrictModel):
    """One source column exposed before the user selects input mappings."""

    name: str
    dtype: str


class InputPreview(StrictModel):
    """Bounded, JSON-compatible preview of an input file."""

    path: Path
    format: InputFormat
    total_records: int = Field(ge=0)
    columns: list[InputColumnPreview]
    sample_records: list[dict[str, JsonValue]]


class InputImportSummary(StrictModel):
    """Immutable provenance and counts for a completed transactional import."""

    source_name: str
    source_path: Path | None = None
    source_format: InputFormat
    source_size_bytes: int = Field(ge=0)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_count: int = Field(ge=1)
    active_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)
    normalized_count: int = Field(ge=0)
    imported_at: AwareDatetime

    @field_validator("source_name")
    @classmethod
    def validate_source_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("source_name cannot be blank.")
        return value
