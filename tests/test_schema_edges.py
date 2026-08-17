from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import (
    DetectionCandidate,
    ValidationFinding,
    ValidationResult,
    ValidationUsage,
)
from health_deid.models.config import (
    BedrockLlmDetectorConfig,
    InputConfig,
    ValidationConfig,
)
from health_deid.models.export import ExportRequest
from health_deid.models.input import InputImportSummary, StageError
from health_deid.models.ledger import (
    BackendAttempt,
    Finding,
    RenderingEvent,
    SpanGroup,
    TransformEvent,
)
from health_deid.models.policy import (
    ConsistencyScope,
    SurrogateRequest,
    SurrogateResult,
    TransformationAction,
)
from health_deid.models.review import (
    ReviewDecision,
    ReviewSpan,
    ReviewSpanEvent,
    ReviewStructuredEvent,
)

NOW = datetime(2025, 1, 1, tzinfo=UTC)


def test_config_rejects_blank_column_names_and_exposes_fixed_backend_names(tmp_path: Path) -> None:
    base_input = {
        "path": tmp_path / "records.parquet",
        "format": "parquet",
        "record_id_column": "rid",
        "entity_id": {"source": "record_id"},
        "text_column": "text",
    }
    for field in ("record_id_column", "text_column"):
        payload = dict(base_input)
        payload[field] = " "
        with pytest.raises(ValidationError, match="Column names cannot be empty"):
            InputConfig.model_validate(payload)

    with pytest.raises(ValidationError, match="Metadata column names cannot be empty"):
        InputConfig.model_validate({**base_input, "metadata_columns": [" "]})

    assert BedrockLlmDetectorConfig().name == "sonnet_4_6"


def test_validation_token_tiers_are_fixed() -> None:
    assert ValidationConfig().output_token_tiers == (4_096, 8_192, 16_384)


def test_detection_candidate_rejects_empty_text_and_invalid_offsets() -> None:
    valid = {
        "category": "NAME",
        "native_category": "NAME",
        "text": "Ann",
        "start_char": 1,
        "end_char": 4,
    }
    for field in ("native_category", "text"):
        with pytest.raises(ValidationError, match="cannot be empty"):
            DetectionCandidate.model_validate({**valid, field: ""})
    with pytest.raises(ValidationError, match="greater than start_char"):
        DetectionCandidate.model_validate({**valid, "start_char": 4, "end_char": 4})
    with pytest.raises(ValidationError, match="length must match"):
        DetectionCandidate.model_validate({**valid, "end_char": 5})


def test_export_and_input_provenance_reject_ambiguous_values(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="duplicates"):
        ExportRequest(output_path=tmp_path / "out.parquet", selected_columns=["x", "x"])
    with pytest.raises(ValidationError, match="non-empty export"):
        ExportRequest(output_path=tmp_path / "out.parquet", selected_columns=[" "])
    with pytest.raises(ValidationError, match="Stage error fields"):
        StageError(stage=" ", code="bad", message="bad")
    with pytest.raises(ValidationError, match="source_name cannot be blank"):
        InputImportSummary(
            source_name=" ",
            source_format="parquet",
            source_size_bytes=0,
            source_sha256="0" * 64,
            record_count=1,
            active_count=1,
            excluded_count=0,
            normalized_count=0,
            imported_at=NOW,
        )


def test_backend_attempt_and_finding_contracts_reject_bad_identity_and_spans() -> None:
    attempt = {
        "attempt_id": "attempt-1",
        "stage_name": "detection",
        "backend_kind": "detector",
        "backend_name": "detector",
        "attempt_number": 1,
        "status": "running",
        "started_at": NOW,
    }
    for field in ("attempt_id", "backend_name"):
        with pytest.raises(ValidationError, match="cannot be blank"):
            BackendAttempt.model_validate({**attempt, field: " "})

    finding = {
        "finding_id": "finding-1",
        "record_id": "record-1",
        "source_kind": "llm",
        "source_name": "model",
        "category": "NAME",
        "exact_text": "Ann",
        "start_char": 1,
        "end_char": 4,
        "created_at": NOW,
    }
    for field in ("finding_id", "record_id", "source_name", "exact_text"):
        with pytest.raises(ValidationError, match="cannot be empty"):
            Finding.model_validate({**finding, field: ""})
    with pytest.raises(ValidationError, match="greater than start_char"):
        Finding.model_validate({**finding, "start_char": 4, "end_char": 4})
    with pytest.raises(ValidationError, match="length must match"):
        Finding.model_validate({**finding, "end_char": 5})


def test_span_group_and_transform_event_validate_source_coordinates() -> None:
    with pytest.raises(ValidationError, match="greater than start_char"):
        SpanGroup(
            group_id="group-1",
            record_id="record-1",
            category=PhiCategory.NAME,
            start_char=3,
            end_char=2,
            finding_ids=["finding-1"],
        )

    event = {
        "event_id": "event-1",
        "record_id": "record-1",
        "group_id": "group-1",
        "plan_revision": 1,
        "action": TransformationAction.REDACT,
        "category": PhiCategory.NAME,
        "original_text": "Ann",
        "input_start_char": 1,
        "input_end_char": 4,
    }
    with pytest.raises(ValidationError, match="greater than input_start_char"):
        TransformEvent.model_validate({**event, "input_start_char": 4})
    with pytest.raises(ValidationError, match="length must match"):
        TransformEvent.model_validate({**event, "input_end_char": 5})


def test_review_span_and_span_event_reject_incomplete_or_misaligned_edits() -> None:
    assert (
        ReviewSpan(
            category=PhiCategory.NAME,
            text="Ann",
            start_char=0,
            end_char=3,
        ).text
        == "Ann"
    )
    with pytest.raises(ValidationError, match="cannot be empty"):
        ReviewSpan(category=PhiCategory.NAME, text="", start_char=0, end_char=1)
    with pytest.raises(ValidationError, match="greater than start_char"):
        ReviewSpan(category=PhiCategory.NAME, text="x", start_char=2, end_char=1)
    with pytest.raises(ValidationError, match="length must match"):
        ReviewSpan(category=PhiCategory.NAME, text="xx", start_char=0, end_char=1)

    with pytest.raises(ValidationError, match="complete replacement"):
        ReviewSpanEvent(event_id="event-1", operation="add")
    with pytest.raises(ValidationError, match="displayed PHI group"):
        ReviewSpanEvent(event_id="event-1", operation="remove")
    with pytest.raises(ValidationError, match="cannot reference"):
        ReviewSpanEvent(
            event_id="event-1",
            operation="add",
            group_id="group-1",
            finding_ids=["finding-1"],
            category=PhiCategory.NAME,
            text="Ann",
            start_char=0,
            end_char=3,
        )
    with pytest.raises(ValidationError, match="cannot contain duplicates"):
        ReviewSpanEvent(
            event_id="event-1",
            operation="remove",
            group_id="group-1",
            finding_ids=["finding-1", "finding-1"],
        )
    with pytest.raises(ValidationError, match="greater than start_char"):
        ReviewSpanEvent(
            event_id="event-1",
            operation="add",
            category=PhiCategory.NAME,
            text="x",
            start_char=2,
            end_char=1,
        )
    with pytest.raises(ValidationError, match="length must match"):
        ReviewSpanEvent(
            event_id="event-1",
            operation="add",
            category=PhiCategory.NAME,
            text="xx",
            start_char=0,
            end_char=1,
        )
    with pytest.raises(ValidationError, match="identifiers cannot be blank"):
        ReviewStructuredEvent(
            event_id=" ",
            column_name="patient_name",
            category=PhiCategory.NAME,
            original_value="Alice",
            replacement_value="Patient A",
        )


def test_review_decision_rejects_blank_ids_and_edits_on_other_dispositions() -> None:
    event = ReviewSpanEvent(
        event_id="event-1",
        operation="add",
        category=PhiCategory.NAME,
        text="Ann",
        start_char=0,
        end_char=3,
    )
    base = {
        "decision_id": "decision-1",
        "record_id": "record-1",
        "basis_plan_revision": 1,
        "disposition": "corrected",
        "reviewer_id": "Reviewer",
        "decided_at": NOW,
    }
    for field in ("decision_id", "record_id"):
        with pytest.raises(ValidationError, match="cannot be blank"):
            ReviewDecision.model_validate({**base, field: " "})
    with pytest.raises(ValidationError, match="Only corrected"):
        ReviewDecision.model_validate(
            {**base, "disposition": "approved_unchanged", "span_events": [event]}
        )


def test_surrogate_models_reject_empty_required_values() -> None:
    request = {
        "event_id": "event-1",
        "record_id": "record-1",
        "entity_id": "entity-1",
        "category": "NAME",
        "original_text": "Ann",
    }
    for field in ("event_id", "record_id", "entity_id", "original_text"):
        with pytest.raises(ValidationError, match="cannot be empty"):
            SurrogateRequest.model_validate({**request, field: ""})

    result = {
        "assignment_id": "assignment-1",
        "method": "faker",
        "category": "NAME",
        "consistency": ConsistencyScope.ENTITY,
        "scope_key_hmac": "0" * 64,
        "container_key_hmac": "1" * 64,
        "candidates": ["Alex"],
    }
    with pytest.raises(ValidationError):
        SurrogateResult.model_validate({**result, "candidates": []})
    with pytest.raises(ValidationError):
        SurrogateResult.model_validate({**result, "scope_key_hmac": "not-a-hash"})


def test_rendering_event_rejects_reverse_or_misaligned_output_offsets() -> None:
    base = {
        "rendering_event_id": "render-event-1",
        "rendering_id": "rendering-1",
        "event_id": "event-1",
        "category": "NAME",
        "replacement_text": "Alex",
        "output_start_char": 2,
        "output_end_char": 6,
    }
    with pytest.raises(ValidationError, match="cannot be smaller"):
        RenderingEvent.model_validate({**base, "output_end_char": 1})
    with pytest.raises(ValidationError, match="length must match"):
        RenderingEvent.model_validate({**base, "output_end_char": 7})


def test_validation_models_cover_optional_text_and_empty_rationale() -> None:
    finding = ValidationFinding(
        category=PhiCategory.NAME,
        evidence=None,
        rationale=" remaining name ",
        source=" validator ",
    )
    assert finding.rationale == "remaining name"
    assert finding.source == "validator"
    with pytest.raises(ValidationError, match="cannot be empty"):
        ValidationFinding(
            category=PhiCategory.NAME,
            rationale=" ",
            source="validator",
        )

    usage = ValidationUsage(input_chars=1, input_bytes=1, latency_ms=0)
    with pytest.raises(ValidationError, match="rationale cannot be empty"):
        ValidationResult(rationale=" ", raw_output={}, usage=usage)
