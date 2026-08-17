from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.common import StrictModel

ReviewDisposition = Literal[
    "approved_unchanged",
    "corrected",
    "excluded",
]
ValidationFindingOutcome = Literal[
    "confirmed",
    "rejected",
    "partially_confirmed",
]
SpanOperation = Literal["add", "remove", "modify"]


class ReviewSpan(StrictModel):
    category: PhiCategory
    text: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)

    @field_validator("text")
    @classmethod
    def nonempty_text(cls, value: str) -> str:
        if not value:
            raise ValueError("Review span text cannot be empty.")
        return value

    @model_validator(mode="after")
    def validate_offsets(self) -> ReviewSpan:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char.")
        if len(self.text) != self.end_char - self.start_char:
            raise ValueError("Review span text length must match its offsets.")
        return self


class ReviewSpanEvent(StrictModel):
    event_id: str
    operation: SpanOperation
    group_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    category: PhiCategory | None = None
    text: str | None = None
    start_char: int | None = Field(default=None, ge=0)
    end_char: int | None = Field(default=None, gt=0)
    reason_code: str | None = None
    comment: str | None = None

    @model_validator(mode="after")
    def validate_operation_payload(self) -> ReviewSpanEvent:
        has_span = all(
            value is not None
            for value in (self.category, self.text, self.start_char, self.end_char)
        )
        if self.operation in {"add", "modify"} and not has_span:
            raise ValueError("Add and modify operations require a complete replacement span.")
        if self.operation in {"remove", "modify"}:
            if self.group_id is None or not self.finding_ids:
                raise ValueError(
                    "Remove and modify operations require a displayed PHI group and its "
                    "underlying finding IDs."
                )
        elif self.group_id is not None or self.finding_ids:
            raise ValueError("Add operations cannot reference an existing PHI group.")
        if len(self.finding_ids) != len(set(self.finding_ids)):
            raise ValueError("finding_ids cannot contain duplicates.")
        if has_span:
            assert (
                self.text is not None and self.start_char is not None and self.end_char is not None
            )
            if self.end_char <= self.start_char:
                raise ValueError("end_char must be greater than start_char.")
            if len(self.text) != self.end_char - self.start_char:
                raise ValueError("Review span text length must match its offsets.")
        return self


class ReviewStructuredEvent(StrictModel):
    event_id: str
    column_name: str
    category: PhiCategory
    original_value: JsonValue
    replacement_value: JsonValue
    comment: str | None = None

    @field_validator("event_id", "column_name")
    @classmethod
    def nonblank_structured_identifiers(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Structured review identifiers cannot be blank.")
        return value


class ValidationFindingReview(StrictModel):
    validation_finding_id: str
    outcome: ValidationFindingOutcome
    reviewer_id: str | None = None
    comment: str | None = None


class ReviewDecision(StrictModel):
    decision_id: str
    record_id: str
    basis_plan_revision: int = Field(ge=1)
    disposition: ReviewDisposition
    reviewer_id: str
    decided_at: AwareDatetime
    review_seconds: int = Field(default=0, ge=0)
    span_events: list[ReviewSpanEvent] = Field(default_factory=list)
    structured_events: list[ReviewStructuredEvent] = Field(default_factory=list)
    validation_finding_reviews: list[ValidationFindingReview] = Field(default_factory=list)
    record_comment: str | None = None

    @field_validator("decision_id", "record_id", "reviewer_id")
    @classmethod
    def nonblank_identifiers(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Review identifiers cannot be blank.")
        return value

    @model_validator(mode="after")
    def validate_disposition(self) -> ReviewDecision:
        if self.disposition != "corrected" and (self.span_events or self.structured_events):
            raise ValueError("Only corrected decisions can contain PHI changes.")
        return self


class ReviewWorkspace(StrictModel):
    record_id: str
    reviewer_id: str
    basis_plan_revision: int = Field(ge=1)
    span_events: list[ReviewSpanEvent] = Field(default_factory=list)
    structured_events: list[ReviewStructuredEvent] = Field(default_factory=list)
    validation_finding_reviews: list[ValidationFindingReview] = Field(default_factory=list)
    record_comment: str | None = None
    review_seconds: int = Field(default=0, ge=0)
    timer_started_at: AwareDatetime | None = None
    updated_at: AwareDatetime

    @field_validator("record_id", "reviewer_id")
    @classmethod
    def nonblank_workspace_identifiers(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Review workspace identifiers cannot be blank.")
        return value
