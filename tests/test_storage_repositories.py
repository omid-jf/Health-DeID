from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from health_deid.backends.runtime import BackendExecutionError, TextChunk
from health_deid.core.dates import DateShift
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import (
    BackendUsage,
    DetectionCandidate,
    DetectionResult,
    ValidationFinding,
    ValidationResult,
    ValidationUsage,
)
from health_deid.models.config import PipelineConfig
from health_deid.models.input import InputImportSummary, NormalizedInputRecord
from health_deid.models.ledger import RenderedText, RenderingEvent, SpanGroup, TransformEvent
from health_deid.models.policy import (
    ConsistencyScope,
    SurrogateRequest,
    SurrogateResult,
    TransformationAction,
)
from health_deid.models.review import (
    ReviewDecision,
    ReviewSpanEvent,
    ValidationFindingReview,
)
from health_deid.storage.database import SqliteRunStore
from health_deid.storage.findings import BackendDefinition, FindingRepository, _usage_from_error
from health_deid.storage.reviews import ReviewRepository
from health_deid.storage.transformations import TransformationRepository
from health_deid.storage.validation import ValidationRepository
from health_deid.storage.validation import _utc_text as validation_utc_text

NOW = datetime(2026, 7, 31, 15, 0, tzinfo=UTC)


def test_backend_error_usage_accepts_aws_and_normalized_token_keys() -> None:
    payload = _usage_from_error(
        BackendExecutionError(
            "truncated",
            "short",
            True,
            raw_response={
                "usage": {
                    "inputTokens": 3,
                    "output_tokens": 4,
                }
            },
        )
    )
    assert payload is not None
    assert json.loads(payload)["total_tokens"] == 7


def _config(tmp_path: Path) -> PipelineConfig:
    return PipelineConfig.model_validate(
        {
            "run": {"name": "repos", "output_dir": tmp_path / "runs"},
            "input": {
                "path": tmp_path / "notes.jsonl",
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "column", "column": "entity_id"},
                "text_column": "text",
            },
            "detection": {
                "detectors": [
                    {
                        "backend": "aws_bedrock",
                        "model_id": "us.anthropic.claude-sonnet-4-6",
                    }
                ]
            },
            "validation": {"enabled": True},
            "review": {"enabled": True},
        }
    )


def _store(tmp_path: Path) -> SqliteRunStore:
    store = SqliteRunStore.create(
        tmp_path / "run.sqlite", run_id="run-1", config=_config(tmp_path), created_at=NOW
    )
    digest = hashlib.sha256(b"xx Alice Bob").hexdigest()
    store.import_records(
        [
            NormalizedInputRecord.model_validate(
                {
                    "source_index": 0,
                    "record_id": "r1",
                    "entity_id": "e1",
                    "raw_source_text": "xx Alice Bob",
                    "source_text": "xx Alice Bob",
                    "text_normalization": {
                        "normalizer_version": "6.3.1",
                        "changed": False,
                        "raw_sha256": digest,
                        "normalized_sha256": digest,
                    },
                    "metadata": {},
                    "status": "active",
                }
            )
        ],
        InputImportSummary(
            source_name="notes.jsonl",
            source_format="jsonl",
            source_size_bytes=12,
            source_sha256=hashlib.sha256(b"source").hexdigest(),
            record_count=1,
            active_count=1,
            excluded_count=0,
            normalized_count=1,
            imported_at=NOW,
        ),
    )
    return store


def _backend(backend_id: str = "detector") -> BackendDefinition:
    return BackendDefinition(
        backend_id=backend_id,
        kind="detector" if backend_id == "detector" else "validator",
        name=backend_id,
        version="1",
        model_id="model",
        settings={"temperature": 0, "custom": NOW},
        taxonomy_version="1",
        prompt_text="fixed prompt" if backend_id == "detector" else None,
        schema={"type": "object"} if backend_id == "detector" else None,
    )


def _candidate(
    text: str,
    start: int,
    category: PhiCategory = PhiCategory.NAME,
    *,
    confidence: float | None = 0.99,
) -> DetectionCandidate:
    return DetectionCandidate(
        backend_span_id=f"span-{start}-{text}",
        category=category,
        native_category=category.value,
        subtype="manual-test",
        text=text,
        start_char=start,
        end_char=start + len(text),
        confidence=confidence,
        source_group_id="source-group",
        native_payload={"native": True},
    )


def _result(candidates: list[DetectionCandidate]) -> DetectionResult:
    return DetectionResult(
        candidates=candidates,
        raw_output={"response": "ok"},
        usage=BackendUsage(input_chars=5, input_bytes=5, latency_ms=1),
        model_version="model-v1",
        stop_reason="end_turn",
    )


def _rule_finding(store: SqliteRunStore):
    return FindingRepository(store).insert_rule_findings(
        record_id="r1",
        source_name="rules-v1",
        candidates=[_candidate("Alice", 3)],
        created_at=NOW,
    )[0]


def _resolution(
    store: SqliteRunStore,
    *,
    resolver_version: str = "resolver-v1",
    findings_sha256: str = "a" * 64,
) -> tuple[int, SpanGroup]:
    finding = _rule_finding(store)
    group = SpanGroup(
        group_id="group-name",
        record_id="r1",
        category=PhiCategory.NAME,
        start_char=3,
        end_char=8,
        finding_ids=[finding.finding_id],
    )
    revision = TransformationRepository(store).save_resolution(
        record_id="r1",
        findings_sha256=findings_sha256,
        resolver_version=resolver_version,
        groups=[group],
        reason="resolved",
        created_at=NOW,
    )
    return revision, group


def _event(plan_revision: int, *, event_id: str | None = None) -> TransformEvent:
    return TransformEvent(
        event_id=event_id or f"event-{plan_revision}",
        record_id="r1",
        group_id="group-name",
        plan_revision=plan_revision,
        action=TransformationAction.REDACT,
        category=PhiCategory.NAME,
        original_text="Alice",
        replacement_text="[R_NAME]",
        input_start_char=3,
        input_end_char=8,
    )


def _save_plan_and_rendering(
    store: SqliteRunStore,
    *,
    plan_revision: int,
    purpose: str = "draft",
):
    transformations = TransformationRepository(store)
    event = _event(plan_revision)
    transformations.save_plan(
        record_id="r1",
        plan_revision=plan_revision,
        resolution_revision=1,
        policy_revision=1,
        purpose=purpose,  # type: ignore[arg-type]
        events=[event],
        created_at=NOW,
    )
    rendered = RenderedText(
        text="xx [R_NAME] Bob",
        events=[
            RenderingEvent(
                rendering_event_id=f"render-event-{plan_revision}",
                rendering_id=f"prospective-rendering-{plan_revision}",
                event_id=event.event_id,
                category=PhiCategory.NAME,
                replacement_text="[R_NAME]",
                output_start_char=3,
                output_end_char=11,
            )
        ],
    )
    return transformations.save_rendering(
        record_id="r1",
        plan_revision=plan_revision,
        kind="draft" if purpose == "draft" else "final",
        rendered=rendered,
        created_at=NOW,
    )


def test_backend_registration_work_success_and_finding_eligibility(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError, match="Unknown record_id"):
        store.set_draft_metadata("missing", {}, updated_at=NOW)
    repository = FindingRepository(store)
    definition = _backend()
    repository.register_backend(definition, created_at=NOW)
    repository.register_backend(definition, created_at=NOW)
    with pytest.raises(ValueError, match="differently"):
        repository.register_backend(
            replace(definition, settings={"temperature": 1}),
            created_at=NOW,
        )

    chunks = [
        TextChunk(index=0, start_char=3, end_char=8, text="Alice"),
        TextChunk(index=1, start_char=9, end_char=12, text="Bob"),
    ]
    work = repository.prepare_work(
        record_id="r1",
        backend_id="detector",
        stage_name="detection",
        chunks=chunks,
        created_at=NOW,
    )
    assert (
        repository.prepare_work(
            record_id="r1",
            backend_id="detector",
            stage_name="detection",
            chunks=chunks,
            created_at=NOW,
        )
        == work
    )

    attempt_id, attempt_number = repository.begin_attempt(work[0], started_at=NOW)
    assert attempt_number == 1
    findings = repository.finish_detection_attempt(
        attempt_id=attempt_id,
        work_item=work[0],
        result=_result(
            [
                _candidate("Alice", 0, confidence=None),
                _candidate("ice", 2, PhiCategory.ID, confidence=0.1),
            ]
        ),
        source_kind="llm",
        source_name="detector",
        minimum_confidence=0.5,
        finished_at=NOW,
    )
    assert [(item.exact_text, item.start_char) for item in findings] == [
        ("Alice", 3),
        ("ice", 5),
    ]
    with store.connection() as connection:
        statuses = [
            row[0]
            for row in connection.execute(
                "SELECT status FROM backend_work_items ORDER BY chunk_index"
            )
        ]
        assert statuses == ["succeeded", "pending"]
    second_attempt, _ = repository.begin_attempt(work[1], started_at=NOW)
    repository.finish_detection_attempt(
        attempt_id=second_attempt,
        work_item=work[1],
        result=_result([]),
        source_kind="llm",
        source_name="detector",
        minimum_confidence=0.5,
        finished_at=NOW,
    )
    with store.connection() as connection:
        assert {row[0] for row in connection.execute("SELECT status FROM backend_work_items")} == {
            "succeeded"
        }

    all_findings = repository.list_findings("r1")
    eligible = repository.list_findings("r1", eligible_only=True)
    assert len(all_findings) == 2
    assert [item.exact_text for item in eligible] == ["Alice"]
    repository.set_eligibility(
        record_id="r1",
        finding_ids=set(),
        is_eligible=False,
        reason="nothing",
        updated_at=NOW,
    )
    repository.set_eligibility(
        record_id="r1",
        finding_ids={findings[0].finding_id},
        is_eligible=False,
        reason="review rejected",
        updated_at=NOW,
    )
    assert repository.list_findings("r1", eligible_only=True) == []
    with pytest.raises(ValueError, match="Unknown finding"):
        repository.set_eligibility(
            record_id="r1",
            finding_ids={"missing"},
            is_eligible=True,
            reason="bad",
            updated_at=NOW,
        )
    with pytest.raises(ValueError, match="not running"):
        repository.finish_detection_attempt(
            attempt_id=attempt_id,
            work_item=work[0],
            result=_result([]),
            source_kind="llm",
            source_name="detector",
            minimum_confidence=0,
            finished_at=NOW,
        )


def test_attempt_failures_retry_states_truncation_and_recovery(tmp_path: Path) -> None:
    store = _store(tmp_path)
    repository = FindingRepository(store)
    repository.register_backend(_backend(), created_at=NOW)
    work = repository.prepare_work(
        record_id="r1",
        backend_id="detector",
        stage_name="detection",
        chunks=[TextChunk(index=i, start_char=i, end_char=i + 1, text="x") for i in range(4)],
        created_at=NOW,
    )

    attempt, number = repository.begin_attempt(work[0], started_at=NOW)
    assert (
        repository.fail_attempt(
            attempt_id=attempt,
            work_item=work[0],
            error=BackendExecutionError("throttle", "slow", True, raw_response={"x": NOW}),
            attempt_number=number,
            maximum_attempts=3,
            finished_at=NOW,
        )
        == "retry_pending"
    )
    attempt, number = repository.begin_attempt(work[0], started_at=NOW)
    assert number == 2
    assert (
        repository.fail_attempt(
            attempt_id=attempt,
            work_item=work[0],
            error=BackendExecutionError("truncated", "short", True, truncated=True),
            attempt_number=number,
            maximum_attempts=2,
            finished_at=NOW,
        )
        == "truncated"
    )
    assert repository.truncated_attempt_count(work[0].work_item_id) == 1

    attempt, number = repository.begin_attempt(work[1], started_at=NOW)
    assert (
        repository.fail_attempt(
            attempt_id=attempt,
            work_item=work[1],
            error=BackendExecutionError("timeout", "timed out", True),
            attempt_number=number,
            maximum_attempts=1,
            finished_at=NOW,
        )
        == "retry_exhausted"
    )

    attempt, number = repository.begin_attempt(work[2], started_at=NOW)
    assert (
        repository.fail_attempt(
            attempt_id=attempt,
            work_item=work[2],
            error=BackendExecutionError("invalid", "bad request", False),
            attempt_number=number,
            maximum_attempts=3,
            finished_at=NOW,
        )
        == "permanent_error"
    )
    with pytest.raises(ValueError, match="not running"):
        repository.fail_attempt(
            attempt_id=attempt,
            work_item=work[2],
            error=BackendExecutionError("invalid", "again", False),
            attempt_number=number,
            maximum_attempts=3,
            finished_at=NOW,
        )

    interrupted, _ = repository.begin_attempt(work[3], started_at=NOW)
    store.update_record_stage_state("r1", "detection", "running", updated_at=NOW)
    assert store.recover_interrupted_work(updated_at=NOW + timedelta(seconds=1)) == 1
    with store.connection() as connection:
        assert (
            connection.execute(
                "SELECT status FROM backend_attempts WHERE attempt_id = ?", (interrupted,)
            ).fetchone()[0]
            == "cancelled"
        )
        assert (
            connection.execute(
                "SELECT status FROM record_stage_states WHERE record_id='r1' AND stage_name='detection'"
            ).fetchone()[0]
            == "retry_pending"
        )


def test_rule_and_review_findings_support_explicit_transactions(tmp_path: Path) -> None:
    store = _store(tmp_path)
    repository = FindingRepository(store)
    rule = _rule_finding(store)
    review = repository.insert_review_finding(
        record_id="r1",
        reviewer_id="reviewer",
        candidate=_candidate("Bob", 9),
        created_at=NOW,
    )
    with store.connection() as connection:
        second = repository.insert_review_finding(
            record_id="r1",
            reviewer_id="reviewer-2",
            candidate=_candidate("Alice", 3),
            created_at=NOW,
            connection=connection,
        )
        repository.set_eligibility(
            record_id="r1",
            finding_ids={second.finding_id},
            is_eligible=False,
            reason="explicit transaction",
            updated_at=NOW,
            connection=connection,
        )
        listed = repository.list_findings("r1", connection=connection)
    assert {item.finding_id for item in listed} == {
        rule.finding_id,
        review.finding_id,
        second.finding_id,
    }


def test_resolution_plan_rendering_idempotence_and_staleness(tmp_path: Path) -> None:
    store = _store(tmp_path)
    transformations = TransformationRepository(store)
    with pytest.raises(KeyError, match="no active resolution"):
        transformations.active_resolution("r1")
    with pytest.raises(KeyError, match="no active final plan"):
        transformations.plan_events("r1", purpose="final")
    with pytest.raises(KeyError, match="no current final"):
        transformations.current_rendering("r1", "final")

    revision, group = _resolution(store)
    assert revision == 1
    assert _resolution(store) == (1, group)
    assert transformations.active_resolution("r1") == (1, [group])
    assert transformations.next_plan_revision("r1") == 1

    validation_rendering = _save_plan_and_rendering(store, plan_revision=1)
    assert transformations.plan_events("r1", purpose="draft") == (
        1,
        [_event(1).model_copy(update={"status": "rendered"})],
    )
    assert transformations.current_rendering("r1", "draft") == validation_rendering
    assert transformations.next_plan_revision("r1") == 2

    second_event = _event(2)
    transformations.save_plan(
        record_id="r1",
        plan_revision=2,
        resolution_revision=1,
        policy_revision=1,
        purpose="draft",
        events=[second_event],
        created_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="active draft plan"):
        ReviewRepository(store).save_decision(
            ReviewDecision(
                decision_id="stale-plan",
                record_id="r1",
                basis_plan_revision=1,
                disposition="approved_unchanged",
                reviewer_id="reviewer",
                decided_at=NOW,
            )
        )
    with pytest.raises(KeyError, match="no current draft"):
        transformations.current_rendering("r1", "draft")
    with store.connection() as connection:
        old = connection.execute(
            "SELECT status, stale_reason FROM transformation_plans WHERE plan_revision=1"
        ).fetchone()
        assert tuple(old) == ("stale", "superseded plan")

    new_revision, _ = _resolution(store, resolver_version="resolver-updated")
    assert new_revision == 2
    with store.connection() as connection:
        assert (
            connection.execute(
                "SELECT status FROM transformation_plans WHERE plan_revision=2"
            ).fetchone()[0]
            == "stale"
        )


def test_date_shift_surrogate_assignment_collisions_and_structured_events(tmp_path: Path) -> None:
    store = _store(tmp_path)
    transformations = TransformationRepository(store)
    assert transformations.get_date_shift(entity_id="e1", policy_revision=1) is None
    first_shift = DateShift(weeks=3, algorithm_version="v1")
    assert (
        transformations.save_date_shift(
            entity_id="e1",
            policy_revision=1,
            secret_reference="date-key",
            shift=first_shift,
            created_at=NOW,
        )
        == first_shift
    )
    assert (
        transformations.save_date_shift(
            entity_id="e1",
            policy_revision=1,
            secret_reference="date-key",
            shift=first_shift,
            created_at=NOW,
        )
        == first_shift
    )
    with pytest.raises(ValueError, match="differently"):
        transformations.save_date_shift(
            entity_id="e1",
            policy_revision=1,
            secret_reference="date-key",
            shift=DateShift(weeks=4, algorithm_version="v1"),
            created_at=NOW,
        )

    request = SurrogateRequest(
        event_id="event-1",
        record_id="r1",
        entity_id="e1",
        category=PhiCategory.NAME,
        original_text="Alice",
    )
    first = SurrogateResult(
        assignment_id="assignment-1",
        method="custom_list",
        category=PhiCategory.NAME,
        consistency=ConsistencyScope.ENTITY,
        pool_sha256="a" * 64,
        scope_key_hmac="b" * 64,
        container_key_hmac="d" * 64,
        candidates=("Test Person",),
    )
    assert (
        transformations.save_surrogate_assignment(
            request=request,
            result=first,
            created_at=NOW,
        )
        == first
    )

    rematerialized = first.model_copy(
        update={
            "assignment_id": "different-id",
            "candidates": ("Different Person",),
            "pool_sha256": None,
        }
    )
    saved_again = transformations.save_surrogate_assignment(
        request=request,
        result=rematerialized,
        created_at=NOW,
    )
    assert saved_again.assignment_id == first.assignment_id
    assert saved_again.surrogate_text == first.surrogate_text

    second_request = request.model_copy(update={"event_id": "event-2"})
    second = first.model_copy(
        update={
            "assignment_id": "assignment-2",
            "scope_key_hmac": "c" * 64,
        }
    )
    with pytest.raises(ValueError, match="custom replacement list.*too small"):
        transformations.save_surrogate_assignment(
            request=second_request,
            result=second,
            created_at=NOW,
        )

    with pytest.raises(ValueError, match="does not match"):
        transformations.save_surrogate_assignment(
            request=request,
            result=first.model_copy(update={"category": PhiCategory.DATE}),
            created_at=NOW,
        )

    faker_first = first.model_copy(
        update={
            "assignment_id": "faker-1",
            "method": "faker",
            "scope_key_hmac": "e" * 64,
            "container_key_hmac": "f" * 64,
            "pool_sha256": None,
        }
    )
    transformations.save_surrogate_assignment(
        request=request,
        result=faker_first,
        created_at=NOW,
    )
    with pytest.raises(ValueError, match="Faker could not produce another unique"):
        transformations.save_surrogate_assignment(
            request=second_request,
            result=faker_first.model_copy(
                update={"assignment_id": "faker-2", "scope_key_hmac": "0" * 64}
            ),
            created_at=NOW,
        )

    resolution_revision, _ = _resolution(store)
    transformations.save_plan(
        record_id="r1",
        plan_revision=1,
        resolution_revision=resolution_revision,
        policy_revision=1,
        purpose="final",
        events=[],
        created_at=NOW,
    )
    transformations.save_structured_event(
        record_id="r1",
        plan_revision=1,
        policy_revision=1,
        purpose="final",
        column_name="service_date",
        category=PhiCategory.DATE,
        action="surrogate",
        original_value=NOW,
        replacement_value=NOW + timedelta(weeks=3),
        created_at=NOW,
    )
    transformations.save_structured_event(
        record_id="r1",
        plan_revision=1,
        policy_revision=1,
        purpose="final",
        column_name="service_date",
        category=PhiCategory.DATE,
        action="surrogate",
        original_value="ignored duplicate",
        replacement_value="ignored duplicate",
        created_at=NOW,
    )
    with store.connection() as connection:
        assert (
            connection.execute("SELECT count(*) FROM structured_transform_events").fetchone()[0]
            == 1
        )


def test_validation_and_review_repositories_preserve_raw_and_effective_results(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _resolution(store)
    rendering = _save_plan_and_rendering(store, plan_revision=1)
    findings = FindingRepository(store)
    findings.register_backend(_backend("validator"), created_at=NOW)
    work = findings.prepare_work(
        record_id="r1",
        backend_id="validator",
        stage_name="validation",
        chunks=[TextChunk(0, 0, len(rendering.rendered_text), rendering.rendered_text)],
        created_at=NOW,
    )[0]
    attempt, _ = findings.begin_attempt(work, started_at=NOW)
    result = ValidationResult(
        findings=[
            ValidationFinding(
                category=PhiCategory.PROFESSION,
                evidence="doctor",
                rationale="Profession is present.",
                rule_ids=["SH-18"],
                confidence="low",
                source="validator",
            ),
            ValidationFinding(
                category=PhiCategory.NAME,
                evidence="Alice",
                rationale="Name may remain.",
                confidence="high",
                source="validator",
            ),
        ],
        rationale="Two possible findings.",
        raw_output={"findings": 2},
        usage=ValidationUsage(input_chars=10, input_bytes=10, latency_ms=1),
        stop_reason="end_turn",
    )
    stored = ValidationRepository(store).finish_success(
        attempt_id=attempt,
        work_item=work,
        rendering=rendering,
        result=result,
        policy=store.read_active_policy()[1],
        finished_at=NOW,
    )
    assert stored.raw_violation is True
    assert stored.effective_violation is True
    assert [item.ignored_by_policy for item in stored.findings] == [True, False]
    with store.connection() as connection:
        states = {
            str(row["stage_name"]): str(row["status"])
            for row in connection.execute(
                """
                SELECT stage_name, status FROM record_stage_states
                WHERE record_id = 'r1' AND stage_name IN ('validation', 'review')
                """
            )
        }
        assert states == {"validation": "succeeded", "review": "review_pending"}
        assert (
            connection.execute("SELECT status FROM records WHERE record_id = 'r1'").fetchone()[0]
            == "awaiting_review"
        )
    with pytest.raises(ValueError, match="not running"):
        ValidationRepository(store).finish_success(
            attempt_id=attempt,
            work_item=work,
            rendering=rendering,
            result=result,
            policy=store.read_active_policy()[1],
            finished_at=NOW,
        )

    reviews = ReviewRepository(store)
    assert reviews.queue() == ["r1"]
    assert reviews.current_basis_plan_revision("r1") == 1
    with store.connection() as connection:
        assert reviews.current_basis_plan_revision("r1", connection=connection) == 1

    with pytest.raises(ValueError, match="unknown transformation"):
        reviews.save_decision(
            ReviewDecision(
                decision_id="unknown-plan",
                record_id="r1",
                basis_plan_revision=99,
                disposition="approved_unchanged",
                reviewer_id="reviewer",
                decided_at=NOW,
            )
        )

    validation_finding_id = stored.findings[0].finding_id
    assert validation_finding_id is not None
    with pytest.raises(ValueError, match="current reviewed draft"):
        reviews.save_decision(
            ReviewDecision(
                decision_id="unknown-validation-finding",
                record_id="r1",
                basis_plan_revision=1,
                disposition="approved_unchanged",
                reviewer_id="reviewer",
                decided_at=NOW,
                validation_finding_reviews=[
                    ValidationFindingReview(
                        validation_finding_id="missing",
                        outcome="partially_confirmed",
                    )
                ],
            )
        )
    decision = ReviewDecision(
        decision_id="decision-1",
        record_id="r1",
        basis_plan_revision=1,
        disposition="corrected",
        reviewer_id="reviewer",
        decided_at=NOW,
        span_events=[
            ReviewSpanEvent(
                event_id="manual-add",
                operation="add",
                category=PhiCategory.ID,
                text="Bob",
                start_char=9,
                end_char=12,
                reason_code="missed_phi",
                comment="Add identifier.",
            )
        ],
        validation_finding_reviews=[
            ValidationFindingReview(
                validation_finding_id=validation_finding_id,
                outcome="rejected",
                comment="Profession is retained.",
            )
        ],
        record_comment="Corrected manually.",
    )
    reviews.save_decision(decision)
    second = decision.model_copy(
        update={
            "decision_id": "decision-2",
            "span_events": [],
            "disposition": "approved_unchanged",
            "reviewer_id": "reviewer",
            "validation_finding_reviews": [
                ValidationFindingReview(
                    validation_finding_id=validation_finding_id,
                    outcome="confirmed",
                    reviewer_id="reviewer",
                )
            ],
            "record_comment": None,
            "decided_at": NOW + timedelta(seconds=1),
        }
    )
    reviews.save_decision(second)
    with store.connection() as connection:
        assert (
            connection.execute(
                "SELECT decision_id FROM review_decisions WHERE is_current=1"
            ).fetchone()[0]
            == "decision-2"
        )
        current = connection.execute(
            "SELECT validation_reviews_json, reviewer_id FROM review_decisions WHERE is_current=1"
        ).fetchone()
        assert json.loads(current["validation_reviews_json"])[0]["outcome"] == "confirmed"
        assert current["reviewer_id"] == "reviewer"

    replacement_attempt, _ = findings.begin_attempt(work, started_at=NOW)
    ValidationRepository(store).finish_success(
        attempt_id=replacement_attempt,
        work_item=work,
        rendering=rendering,
        result=ValidationResult(
            findings=[],
            rationale="Replacement validation.",
            raw_output={},
            usage=ValidationUsage(input_chars=1, input_bytes=1, latency_ms=0),
        ),
        policy=store.read_active_policy()[1],
        finished_at=NOW + timedelta(seconds=2),
    )
    with store.connection() as connection:
        assert (
            connection.execute(
                "SELECT is_stale FROM validation_results ORDER BY created_at LIMIT 1"
            ).fetchone()[0]
            == 1
        )
    with pytest.raises(ValueError, match="current reviewed draft"):
        reviews.save_decision(
            ReviewDecision(
                decision_id="stale-validation-finding",
                record_id="r1",
                basis_plan_revision=1,
                disposition="approved_unchanged",
                reviewer_id="reviewer",
                decided_at=NOW + timedelta(seconds=3),
                validation_finding_reviews=[
                    ValidationFindingReview(
                        validation_finding_id=validation_finding_id,
                        outcome="partially_confirmed",
                    )
                ],
            )
        )


def test_validation_without_findings_and_review_missing_plan(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError, match="no active draft plan"):
        ReviewRepository(store).current_basis_plan_revision("r1")

    _resolution(store)
    rendering = _save_plan_and_rendering(store, plan_revision=1)
    findings = FindingRepository(store)
    findings.register_backend(_backend("validator"), created_at=NOW)
    work = findings.prepare_work(
        record_id="r1",
        backend_id="validator",
        stage_name="validation",
        chunks=[TextChunk(0, 0, 1, "x")],
        created_at=NOW,
    )[0]
    attempt, _ = findings.begin_attempt(work, started_at=NOW)
    stored = ValidationRepository(store).finish_success(
        attempt_id=attempt,
        work_item=work,
        rendering=rendering,
        result=ValidationResult(
            findings=[],
            rationale="No findings.",
            raw_output={},
            usage=ValidationUsage(input_chars=1, input_bytes=1, latency_ms=0),
        ),
        policy=store.read_active_policy()[1],
        finished_at=NOW,
    )
    assert not stored.raw_violation
    assert not stored.effective_violation


def test_review_workspace_timer_lifecycle_and_revision_refresh(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _resolution(store)
    _save_plan_and_rendering(store, plan_revision=1)
    reviews = ReviewRepository(store)

    assert not reviews.has_workspace("r1")
    with pytest.raises(ValueError, match="reviewer_id cannot be blank"):
        reviews.open_workspace("r1", " ", opened_at=NOW)
    workspace = reviews.open_workspace("r1", "reviewer", opened_at=NOW, start_timer=False)
    assert workspace.timer_started_at is None
    assert reviews.has_workspace("r1")
    saved = reviews.save_workspace(
        record_id="r1",
        reviewer_id="reviewer",
        basis_plan_revision=1,
        span_events=[],
        structured_events=[],
        validation_finding_reviews=[],
        record_comment="Continue later",
        saved_at=NOW,
    )
    assert saved.record_comment == "Continue later"
    with pytest.raises(ValueError, match="draft is stale"):
        reviews.save_workspace(
            record_id="r1",
            reviewer_id="reviewer",
            basis_plan_revision=2,
            span_events=[],
            structured_events=[],
            validation_finding_reviews=[],
            record_comment=None,
            saved_at=NOW,
        )

    started = reviews.set_timer(
        "r1", "reviewer", running=True, changed_at=NOW + timedelta(seconds=1)
    )
    assert started.timer_started_at is not None
    still_started = reviews.set_timer(
        "r1", "reviewer", running=True, changed_at=NOW + timedelta(seconds=2)
    )
    assert still_started.timer_started_at == started.timer_started_at
    paused = reviews.set_timer(
        "r1", "reviewer", running=False, changed_at=NOW + timedelta(seconds=7)
    )
    assert paused.review_seconds == 6
    paused_again = reviews.set_timer(
        "r1", "reviewer", running=False, changed_at=NOW + timedelta(seconds=8)
    )
    assert paused_again.review_seconds == 6
    assert (
        reviews.finish_workspace(
            "r1", "reviewer", finished_at=NOW + timedelta(seconds=9)
        ).timer_started_at
        is None
    )

    _save_plan_and_rendering(store, plan_revision=2)
    refreshed = reviews.open_workspace("r1", "reviewer", opened_at=NOW + timedelta(seconds=10))
    assert refreshed.basis_plan_revision == 2
    assert refreshed.review_seconds == 0
    with store.immediate_transaction() as connection:
        with pytest.raises(KeyError, match="Unknown review workspace"):
            reviews._workspace_row(connection, "missing")


def test_review_workspace_pauses_other_record_and_plan_fallbacks(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _resolution(store)
    _save_plan_and_rendering(store, plan_revision=1)
    reviews = ReviewRepository(store)
    run_id = store.run_id()
    with store.connection() as connection:
        connection.execute(
            """
            INSERT INTO records(
                run_id, record_id, entity_id, source_index, raw_source_text,
                normalized_text, normalization_json, metadata_json, status,
                created_at, updated_at
            ) SELECT run_id, 'r2', 'e2', 1, raw_source_text, normalized_text,
                     normalization_json, metadata_json, status, created_at, updated_at
              FROM records WHERE run_id = ? AND record_id = 'r1'
            """,
            (run_id,),
        )
        connection.execute(
            """
            INSERT INTO resolution_revisions(
                run_id, record_id, revision, resolver_version, findings_sha256,
                is_active, reason, created_at
            ) SELECT run_id, 'r2', revision, resolver_version, findings_sha256,
                     is_active, reason, created_at
              FROM resolution_revisions WHERE run_id = ? AND record_id = 'r1'
            """,
            (run_id,),
        )
        connection.execute(
            """
            INSERT INTO transformation_plans(
                run_id, record_id, plan_revision, resolution_revision,
                policy_revision, purpose, status, created_at
            ) SELECT run_id, 'r2', plan_revision, resolution_revision,
                     policy_revision, purpose, status, created_at
              FROM transformation_plans WHERE run_id = ? AND record_id = 'r1'
            """,
            (run_id,),
        )

    reviews.open_workspace("r1", "reviewer", opened_at=NOW)
    reviews.open_workspace("r2", "reviewer", opened_at=NOW + timedelta(seconds=5))
    with store.connection() as connection:
        r1 = connection.execute(
            "SELECT review_seconds, timer_started_at FROM review_workspaces WHERE record_id='r1'"
        ).fetchone()
    assert tuple(r1) == (5, None)

    reviews.save_decision(
        ReviewDecision(
            decision_id="basis-from-decision",
            record_id="r1",
            basis_plan_revision=1,
            disposition="approved_unchanged",
            reviewer_id="reviewer",
            decided_at=NOW,
        )
    )
    with store.connection() as connection:
        connection.execute(
            "UPDATE transformation_plans SET status='stale' WHERE record_id IN ('r1', 'r2')"
        )
    assert reviews.current_basis_plan_revision("r1") == 1
    assert reviews.current_basis_plan_revision("r2") == 1


def test_validation_failure_results_are_append_only_current_and_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _resolution(store)
    rendering = _save_plan_and_rendering(store, plan_revision=1)
    findings = FindingRepository(store)
    findings.register_backend(_backend("validator"), created_at=NOW)
    work = findings.prepare_work(
        record_id="r1",
        backend_id="validator",
        stage_name="validation",
        chunks=[TextChunk(0, 0, 1, "x")],
        created_at=NOW,
    )[0]
    validations = ValidationRepository(store)

    running_attempt, _ = findings.begin_attempt(work, started_at=NOW)
    with pytest.raises(ValueError, match="terminal failed"):
        validations.record_failure(
            attempt_id=running_attempt,
            work_item=work,
            rendering=rendering,
            error=BackendExecutionError("timeout", "timed out", True),
            finished_at=NOW,
        )
    technical_error = BackendExecutionError("timeout", "timed out", True)
    findings.fail_attempt(
        attempt_id=running_attempt,
        work_item=work,
        error=technical_error,
        attempt_number=1,
        maximum_attempts=3,
        finished_at=NOW,
    )
    first_id = validations.record_failure(
        attempt_id=running_attempt,
        work_item=work,
        rendering=rendering,
        error=technical_error,
        finished_at=NOW,
    )

    truncated_attempt, number = findings.begin_attempt(work, started_at=NOW)
    truncated_error = BackendExecutionError(
        "truncated", "output was truncated", True, truncated=True
    )
    with store.connection() as connection:
        findings.fail_attempt(
            attempt_id=truncated_attempt,
            work_item=work,
            error=truncated_error,
            attempt_number=number,
            maximum_attempts=number,
            finished_at=NOW + timedelta(seconds=1),
            connection=connection,
        )
        second_id = validations.record_failure(
            attempt_id=truncated_attempt,
            work_item=work,
            rendering=rendering,
            error=truncated_error,
            finished_at=NOW + timedelta(seconds=1),
            connection=connection,
        )
    assert second_id != first_id
    assert (
        validations.record_failure(
            attempt_id=truncated_attempt,
            work_item=work,
            rendering=rendering,
            error=truncated_error,
            finished_at=NOW + timedelta(seconds=1),
        )
        == second_id
    )
    with store.connection() as connection:
        rows = connection.execute(
            """
            SELECT validation_id, status, raw_violation, effective_violation,
                   rationale, is_stale
            FROM validation_results ORDER BY created_at
            """
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        (first_id, "technical_error", None, None, "timed out", 1),
        (second_id, "truncated", None, None, "output was truncated", 0),
    ]

    with pytest.raises(ValueError, match="validation work item"):
        validations.record_failure(
            attempt_id=truncated_attempt,
            work_item=replace(work, stage_name="detection"),
            rendering=rendering,
            error=truncated_error,
            finished_at=NOW,
        )
    with pytest.raises(ValueError, match="same record"):
        validations.record_failure(
            attempt_id=truncated_attempt,
            work_item=work,
            rendering=rendering.model_copy(update={"record_id": "different"}),
            error=truncated_error,
            finished_at=NOW,
        )
    with pytest.raises(ValueError, match="does not match"):
        validations.record_failure(
            attempt_id=truncated_attempt,
            work_item=replace(work, work_item_id="different"),
            rendering=rendering,
            error=truncated_error,
            finished_at=NOW,
        )
    with pytest.raises(ValueError, match="truncation"):
        validations.record_failure(
            attempt_id=truncated_attempt,
            work_item=work,
            rendering=rendering,
            error=technical_error,
            finished_at=NOW,
        )

    atomic_attempt, atomic_number = findings.begin_attempt(work, started_at=NOW)
    atomic_error = BackendExecutionError("atomic-truncated", "atomic failure", True, truncated=True)
    with pytest.raises(ValueError, match="truncation"):
        with store.connection() as connection:
            findings.fail_attempt(
                attempt_id=atomic_attempt,
                work_item=work,
                error=atomic_error,
                attempt_number=atomic_number,
                maximum_attempts=atomic_number,
                finished_at=NOW,
                connection=connection,
            )
            validations.record_failure(
                attempt_id=atomic_attempt,
                work_item=work,
                rendering=rendering,
                error=technical_error,
                finished_at=NOW,
                connection=connection,
            )
    with store.connection() as connection:
        assert (
            connection.execute(
                "SELECT status FROM backend_attempts WHERE attempt_id = ?", (atomic_attempt,)
            ).fetchone()[0]
            == "running"
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM processing_errors WHERE error_code = 'atomic-truncated'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "operation",
    [
        lambda store: FindingRepository(store).register_backend(
            _backend(), created_at=datetime(2026, 1, 1)
        ),
        lambda store: TransformationRepository(store).save_date_shift(
            entity_id="e1",
            policy_revision=1,
            secret_reference="date-key",
            shift=DateShift(weeks=1, algorithm_version="v1"),
            created_at=datetime(2026, 1, 1),
        ),
        lambda store: ReviewRepository(store).save_decision(
            ReviewDecision.model_construct(
                decision_id="naive",
                record_id="r1",
                basis_plan_revision=1,
                disposition="approved_unchanged",
                reviewer_id=None,
                decided_at=datetime(2026, 1, 1),
                review_seconds=0,
                span_events=[],
                validation_finding_reviews=[],
                record_comment=None,
            )
        ),
    ],
)
def test_repository_timestamps_must_be_timezone_aware(tmp_path: Path, operation) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="timezone"):
        operation(store)

    with pytest.raises(ValueError, match="timezone"):
        validation_utc_text(datetime(2026, 1, 1))
