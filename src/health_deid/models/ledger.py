from __future__ import annotations

from typing import Any, Literal

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.common import StrictModel
from health_deid.models.policy import ConsistencyScope, TransformationAction

type StageName = Literal[
    "input",
    "detection",
    "transformation",
    "validation",
    "review",
    "finalization",
    "export",
]

STAGE_NAMES: tuple[StageName, ...] = (
    "input",
    "detection",
    "transformation",
    "validation",
    "review",
    "finalization",
    "export",
)

type RunStatus = Literal[
    "initialized",
    "running",
    "awaiting_review",
    "completed",
    "completed_with_errors",
    "blocked",
    "failed",
]
type RunStageStatus = Literal[
    "pending",
    "running",
    "completed",
    "completed_with_errors",
    "blocked",
    "failed",
    "skipped",
]
type RecordStageStatus = Literal[
    "pending",
    "running",
    "succeeded",
    "retry_pending",
    "retry_exhausted",
    "permanent_error",
    "blocked",
    "review_pending",
    "excluded",
    "skipped",
]
type RecordStatus = Literal[
    "processing",
    "awaiting_review",
    "reviewed",
    "excluded",
    "ready",
    "failed",
]
type ProcessingErrorStage = StageName | Literal["run"]


class BackendAttempt(StrictModel):
    attempt_id: str
    record_id: str | None = None
    stage_name: StageName
    backend_kind: Literal["detector", "validator"]
    backend_name: str
    backend_version: str | None = None
    attempt_number: int = Field(ge=1)
    chunk_index: int | None = Field(default=None, ge=0)
    status: Literal[
        "running",
        "succeeded",
        "retryable_error",
        "permanent_error",
        "truncated",
        "cancelled",
    ]
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    request_metadata: dict[str, JsonValue] | None = None
    raw_response: str | None = None
    usage: dict[str, JsonValue] | None = None
    error_class: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    retryable: bool | None = None

    @field_validator("attempt_id", "backend_name")
    @classmethod
    def nonblank_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Attempt identifiers and backend names cannot be blank.")
        return value


class Finding(StrictModel):
    finding_id: str
    record_id: str
    source_kind: Literal["aws", "llm", "rule", "review"]
    source_name: str
    source_version: str | None = None
    backend_type: str | None = None
    category: PhiCategory
    detector_subtype: str | None = None
    exact_text: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    backend_attempt_id: str | None = None
    source_group_id: str | None = None
    status: Literal["detected", "active", "retained", "rejected", "superseded"] = "detected"
    created_at: AwareDatetime

    @field_validator("finding_id", "record_id", "source_name", "exact_text")
    @classmethod
    def nonblank_text(cls, value: str) -> str:
        if not value:
            raise ValueError("Finding text fields cannot be empty.")
        return value

    @model_validator(mode="after")
    def validate_offsets(self) -> Finding:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char.")
        if len(self.exact_text) != self.end_char - self.start_char:
            raise ValueError("exact_text length must match its offsets.")
        return self


class SpanGroup(StrictModel):
    group_id: str
    record_id: str
    category: PhiCategory
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    finding_ids: list[str] = Field(min_length=1)
    resolution_status: Literal["resolved", "ambiguous", "rejected", "superseded"] = "resolved"

    @model_validator(mode="after")
    def validate_offsets(self) -> SpanGroup:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char.")
        return self


class TransformEvent(StrictModel):
    event_id: str
    record_id: str
    group_id: str
    plan_revision: int = Field(ge=1)
    action: TransformationAction
    strategy: str | None = None
    category: PhiCategory
    original_text: str
    replacement_text: str | None = None
    input_start_char: int = Field(ge=0)
    input_end_char: int = Field(gt=0)
    surrogate_assignment_id: str | None = None
    status: Literal["planned", "rendered", "stale", "rejected"] = "planned"

    @model_validator(mode="after")
    def validate_offsets(self) -> TransformEvent:
        if self.input_end_char <= self.input_start_char:
            raise ValueError("input_end_char must be greater than input_start_char.")
        if len(self.original_text) != self.input_end_char - self.input_start_char:
            raise ValueError("original_text length must match its input offsets.")
        return self


class Rendering(StrictModel):
    rendering_id: str
    record_id: str
    plan_revision: int = Field(ge=1)
    kind: Literal["preview", "draft", "final"]
    rendered_text: str
    text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    is_stale: bool = False
    created_at: AwareDatetime


class RecordState(StrictModel):
    record_id: str
    entity_id: str
    source_index: int = Field(ge=0)
    normalized_text: str | None
    metadata: dict[str, Any]
    status: RecordStatus
    stage_states: dict[StageName, RecordStageStatus]


class SurrogateAssignment(StrictModel):
    assignment_id: str
    method: Literal["faker", "custom_list"]
    pool_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    category: PhiCategory
    consistency: ConsistencyScope
    container_key_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_key_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    surrogate_value: str
    created_at: AwareDatetime


class ProcessingError(StrictModel):
    error_id: str
    record_id: str | None = None
    stage_name: StageName
    backend_attempt_id: str | None = None
    error_class: str
    error_code: str
    message: str
    retryable: bool
    resolved: bool = False
    created_at: AwareDatetime
    resolved_at: AwareDatetime | None = None


class ResolutionRevision(StrictModel):
    record_id: str
    revision: int = Field(ge=1)
    resolver_version: str
    findings_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    groups: list[SpanGroup]
    created_at: AwareDatetime


class TransformationPlan(StrictModel):
    record_id: str
    revision: int = Field(ge=1)
    resolution_revision: int = Field(ge=1)
    policy_revision: int = Field(ge=1)
    purpose: Literal["draft", "final"]
    events: list[TransformEvent]
    status: Literal["active", "stale"] = "active"
    created_at: AwareDatetime


class RenderingEvent(StrictModel):
    rendering_event_id: str
    rendering_id: str
    event_id: str
    category: PhiCategory
    replacement_text: str
    output_start_char: int = Field(ge=0)
    output_end_char: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_offsets(self) -> RenderingEvent:
        if self.output_end_char < self.output_start_char:
            raise ValueError("output_end_char cannot be smaller than output_start_char.")
        if len(self.replacement_text) != self.output_end_char - self.output_start_char:
            raise ValueError("replacement_text length must match its output offsets.")
        return self


class RenderedText(StrictModel):
    text: str
    events: list[RenderingEvent]
