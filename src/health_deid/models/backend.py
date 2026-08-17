from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.common import StrictModel


class DetectionCandidate(StrictModel):
    backend_span_id: str | None = None
    category: PhiCategory
    native_category: str
    subtype: str | None = None
    text: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_group_id: str | None = None
    native_payload: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("native_category", "text")
    @classmethod
    def nonempty_text(cls, value: str) -> str:
        if not value:
            raise ValueError("Detection candidate text fields cannot be empty.")
        return value

    @model_validator(mode="after")
    def validate_offsets(self) -> DetectionCandidate:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char.")
        if len(self.text) != self.end_char - self.start_char:
            raise ValueError("Candidate text length must match its offsets.")
        return self


class BackendUsage(StrictModel):
    request_count: int = Field(default=1, ge=0)
    input_chars: int = Field(ge=0)
    input_bytes: int = Field(ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    latency_ms: float = Field(ge=0.0)
    input_cost_usd: float | None = Field(default=None, ge=0.0)
    output_cost_usd: float | None = Field(default=None, ge=0.0)
    cost_usd: float | None = Field(default=None, ge=0.0)


class DetectionResult(StrictModel):
    candidates: list[DetectionCandidate] = Field(default_factory=list)
    raw_output: dict[str, Any]
    usage: BackendUsage
    model_version: str | None = None
    stop_reason: str | None = None


class ValidationFinding(StrictModel):
    finding_id: str | None = None
    category: PhiCategory
    evidence: str | None = None
    rationale: str
    rule_ids: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] | None = None
    source: str
    ignored_by_policy: bool = False

    @field_validator("finding_id", "evidence", "rationale", "source")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Validation finding text fields cannot be empty.")
        return value


class ValidationUsage(StrictModel):
    request_count: int = Field(default=1, ge=0)
    input_chars: int = Field(ge=0)
    input_bytes: int = Field(ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    latency_ms: float = Field(ge=0.0)
    input_cost_usd: float | None = Field(default=None, ge=0.0)
    output_cost_usd: float | None = Field(default=None, ge=0.0)
    cost_usd: float | None = Field(default=None, ge=0.0)


class ValidationResult(StrictModel):
    findings: list[ValidationFinding] = Field(default_factory=list)
    rationale: str
    raw_output: dict[str, Any]
    usage: ValidationUsage
    stop_reason: str | None = None

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Validation rationale cannot be empty.")
        return value

    @property
    def raw_violation(self) -> bool:
        return bool(self.findings)

    @property
    def effective_violation(self) -> bool:
        return any(not finding.ignored_by_policy for finding in self.findings)
