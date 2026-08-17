from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from health_deid.core.resolution import RESOLVER_VERSION, resolve_findings
from health_deid.core.secret_refs import MappingSecretResolver
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import DetectionCandidate
from health_deid.models.config import PipelineConfig
from health_deid.models.ledger import RenderedText
from health_deid.models.policy import TransformationPolicy
from health_deid.models.review import (
    ReviewDecision,
    ReviewSpanEvent,
    ReviewStructuredEvent,
    ReviewWorkspace,
    ValidationFindingReview,
)
from health_deid.pipeline.engine import EngineDependencies, PipelineEngine
from health_deid.pipeline.review import ReviewService, build_review_decision_id
from health_deid.storage.database import SqliteRunStore
from health_deid.storage.findings import FindingRepository
from health_deid.storage.transformations import TransformationRepository

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def _review_store(
    tmp_path: Path,
    *,
    duplicate_detection: bool = False,
) -> tuple[SqliteRunStore, str, str]:
    source = tmp_path / "records.jsonl"
    source.write_text(
        '{"record_id":"R1","text":"Jane Smith visited.","site":"north"}\n',
        encoding="utf-8",
    )
    config = PipelineConfig.model_validate(
        {
            "run": {"output_dir": tmp_path / "runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
                "metadata_columns": ["site"],
            },
            "detection": {"enabled": False},
            "validation": {"enabled": True},
            "review": {"enabled": True},
        }
    )
    engine = PipelineEngine.create(config, timestamp=NOW)
    store = engine.store
    finding_repository = FindingRepository(store)
    candidates = [
        DetectionCandidate(
            category=PhiCategory.NAME,
            native_category="NAME",
            text="Jane Smith",
            start_char=0,
            end_char=10,
        )
    ]
    if duplicate_detection:
        candidates.append(
            DetectionCandidate(
                backend_span_id="second-backend-result",
                category=PhiCategory.NAME,
                native_category="PERSON",
                text="Jane Smith",
                start_char=0,
                end_char=10,
            )
        )
    findings = finding_repository.insert_rule_findings(
        record_id="R1",
        source_name="fixture_rule",
        candidates=candidates,
        created_at=NOW,
    )
    resolved = resolve_findings("Jane Smith visited.", findings, record_id="R1")
    transformations = TransformationRepository(store)
    resolution_revision = transformations.save_resolution(
        record_id="R1",
        findings_sha256=resolved.findings_sha256,
        resolver_version=RESOLVER_VERSION,
        groups=resolved.groups,
        reason="test fixture",
        created_at=NOW,
    )
    transformations.save_plan(
        record_id="R1",
        plan_revision=1,
        resolution_revision=resolution_revision,
        policy_revision=1,
        purpose="draft",
        events=[],
        created_at=NOW,
    )
    rendering = transformations.save_rendering(
        record_id="R1",
        plan_revision=1,
        kind="draft",
        rendered=RenderedText(text="[R_NAME] visited.", events=[]),
        created_at=NOW,
    )
    validation_finding_id = "validation-finding-1"
    with store.connection() as connection:
        connection.execute(
            """
            INSERT INTO validation_results(
                validation_id, run_id, record_id, rendering_id, status,
                raw_violation, effective_violation, rationale, is_stale, created_at
            ) VALUES ('validation-1', ?, 'R1', ?, 'succeeded', 1, 1,
                      'Possible identifier remains', 0, ?)
            """,
            (store.run_id(), rendering.rendering_id, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO validation_findings(
                validation_finding_id, run_id, record_id, validation_id,
                canonical_category, evidence, rule_ids_json, confidence,
                rationale, ignored_by_policy
            ) VALUES (?, ?, 'R1', 'validation-1', 'NAME', 'Jane', '["SH-NAME"]',
                      'high', 'Name-like text remains', 0)
            """,
            (validation_finding_id, store.run_id()),
        )
    store.set_record_status("R1", "awaiting_review", updated_at=NOW)
    store.update_record_stage_state("R1", "validation", "succeeded", updated_at=NOW)
    store.update_record_stage_state("R1", "review", "review_pending", updated_at=NOW)
    return store, findings[0].finding_id, validation_finding_id


def _decision(
    *,
    disposition: str,
    span_events: list[ReviewSpanEvent] | None = None,
    validation_reviews: list[ValidationFindingReview] | None = None,
    basis_plan_revision: int = 1,
    record_comment: str | None = None,
    reviewer_id: str | None = "reviewer-7",
) -> ReviewDecision:
    return ReviewDecision.model_validate(
        {
            "decision_id": f"decision-{disposition}",
            "record_id": "R1",
            "basis_plan_revision": basis_plan_revision,
            "disposition": disposition,
            "reviewer_id": reviewer_id,
            "decided_at": NOW,
            "review_seconds": 19,
            "span_events": span_events or [],
            "validation_finding_reviews": validation_reviews or [],
            "record_comment": record_comment,
        }
    )


def test_review_approval_persists_adjudication_and_comments(tmp_path: Path) -> None:
    store, finding_id, validation_finding_id = _review_store(tmp_path)
    service = ReviewService(store)

    assert service.queue() == ["R1"]
    record = service.record("R1")
    assert record.plan_revision == 1
    assert [finding.finding_id for finding in record.findings] == [finding_id]
    assert record.validation_findings[0]["validation_finding_id"] == validation_finding_id

    service.decide(
        _decision(
            disposition="approved_unchanged",
            validation_reviews=[
                ValidationFindingReview(
                    validation_finding_id=validation_finding_id,
                    outcome="confirmed",
                    reviewer_id="reviewer-7",
                    comment="Confirmed in context.",
                )
            ],
            record_comment="Approved after checking the full note.",
        )
    )

    assert service.queue() == []
    assert store.read_record("R1")["status"] == "reviewed"
    with store.connection() as connection:
        decision = connection.execute("SELECT * FROM review_decisions").fetchone()
        stage = connection.execute(
            "SELECT status FROM record_stage_states WHERE record_id = 'R1' AND stage_name = 'review'"
        ).fetchone()
    assert decision["disposition"] == "approved_unchanged"
    assert decision["review_seconds"] == 19
    adjudication = json.loads(decision["validation_reviews_json"])[0]
    assert adjudication["outcome"] == "confirmed"
    assert adjudication["comment"] == "Confirmed in context."
    assert decision["record_comment"] == "Approved after checking the full note."
    assert decision["reviewer_id"] == "reviewer-7"
    assert stage["status"] == "succeeded"


def test_review_correction_revises_findings_and_records_events(tmp_path: Path) -> None:
    store, finding_id, _ = _review_store(tmp_path)
    service = ReviewService(store)
    group = service.record("R1").span_groups[0]

    service.decide(
        _decision(
            disposition="corrected",
            span_events=[
                ReviewSpanEvent(
                    event_id="remove-name",
                    operation="remove",
                    group_id=group.group_id,
                    finding_ids=group.finding_ids,
                    reason_code="false_positive",
                    comment="Not the remaining identifier.",
                ),
                ReviewSpanEvent(
                    event_id="add-visit",
                    operation="add",
                    category=PhiCategory.DATE,
                    text="visited",
                    start_char=11,
                    end_char=18,
                    reason_code="manual_addition",
                    comment="Test correction.",
                ),
            ],
            record_comment="Corrected detector spans.",
        )
    )

    eligible = FindingRepository(store).list_findings("R1", eligible_only=True)
    assert [(finding.source_kind, finding.exact_text) for finding in eligible] == [
        ("review", "visited")
    ]
    with store.connection() as connection:
        old_eligibility = connection.execute(
            "SELECT is_eligible, eligibility_reason FROM findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        revisions = connection.execute(
            "SELECT revision, is_active FROM resolution_revisions ORDER BY revision"
        ).fetchall()
        events = json.loads(
            connection.execute("SELECT span_events_json FROM review_decisions").fetchone()[0]
        )
        plan = connection.execute(
            "SELECT status, stale_reason FROM transformation_plans WHERE plan_revision = 1"
        ).fetchone()
    assert tuple(old_eligibility) == (0, "removed by review decision-corrected")
    assert [tuple(row) for row in revisions] == [(1, 0), (2, 1)]
    assert [(event["operation"], event["reason_code"], event["comment"]) for event in events] == [
        ("remove", "false_positive", "Not the remaining identifier."),
        ("add", "manual_addition", "Test correction."),
    ]
    assert tuple(plan) == ("stale", "review correction decision-corrected")


def test_one_displayed_phi_change_updates_all_duplicate_detector_results(
    tmp_path: Path,
) -> None:
    store, _, _ = _review_store(tmp_path, duplicate_detection=True)
    service = ReviewService(store)
    group = service.record("R1").span_groups[0]
    assert len(group.finding_ids) == 2

    service.decide(
        _decision(
            disposition="corrected",
            span_events=[
                ReviewSpanEvent(
                    event_id="remove-displayed-name",
                    operation="remove",
                    group_id=group.group_id,
                    finding_ids=group.finding_ids,
                    reason_code="false_positive",
                )
            ],
        )
    )

    with store.connection() as connection:
        stored_events = json.loads(
            connection.execute("SELECT span_events_json FROM review_decisions").fetchone()[0]
        )
        eligibility = connection.execute(
            "SELECT finding_id, is_eligible FROM findings ORDER BY finding_id"
        ).fetchall()
    assert len(stored_events) == 1
    assert set(stored_events[0]["finding_ids"]) == set(group.finding_ids)
    assert [(row["finding_id"], row["is_eligible"]) for row in eligibility] == [
        (finding_id, 0) for finding_id in sorted(group.finding_ids)
    ]


def test_review_exclusion_updates_record_and_stage(tmp_path: Path) -> None:
    store, _, _ = _review_store(tmp_path)

    ReviewService(store).decide(_decision(disposition="excluded"))

    assert store.read_record("R1")["status"] == "excluded"
    with store.connection() as connection:
        states = {
            row["stage_name"]: row["status"]
            for row in connection.execute(
                "SELECT stage_name, status FROM record_stage_states WHERE record_id = 'R1'"
            )
        }
    assert states["review"] == "excluded"
    assert {states[name] for name in ("finalization", "export")} == {"excluded"}


def test_review_escalation_disposition_is_not_part_of_single_user_workflow() -> None:
    with pytest.raises(ValidationError, match="disposition"):
        _decision(disposition="needs_escalation")


def test_review_workspace_identifiers_must_not_be_blank() -> None:
    with pytest.raises(ValidationError, match="identifiers cannot be blank"):
        ReviewWorkspace.model_validate(
            {
                "record_id": " ",
                "reviewer_id": "reviewer",
                "basis_plan_revision": 1,
                "updated_at": NOW,
            }
        )


def test_review_rejects_decision_based_on_stale_plan(tmp_path: Path) -> None:
    store, _, _ = _review_store(tmp_path)
    transformations = TransformationRepository(store)
    transformations.save_plan(
        record_id="R1",
        plan_revision=2,
        resolution_revision=1,
        policy_revision=1,
        purpose="draft",
        events=[],
        created_at=NOW,
    )

    with pytest.raises(ValueError, match="Review is stale"):
        ReviewService(store).decide(
            _decision(disposition="approved_unchanged", basis_plan_revision=1)
        )

    with store.connection() as connection:
        count = connection.execute("SELECT count(*) FROM review_decisions").fetchone()[0]
    assert count == 0


def test_review_rejects_unknown_record_and_changed_removed_group(tmp_path: Path) -> None:
    store, _, _ = _review_store(tmp_path)
    service = ReviewService(store)
    group = service.record("R1").span_groups[0]

    with pytest.raises(KeyError, match="Unknown record_id"):
        service.record("missing")
    with pytest.raises(ValueError, match="displayed PHI group changed"):
        service.decide(
            _decision(
                disposition="corrected",
                span_events=[
                    ReviewSpanEvent(
                        event_id="remove-unknown",
                        operation="remove",
                        group_id=group.group_id,
                        finding_ids=["missing-finding"],
                    )
                ],
            )
        )

    with store.connection() as connection:
        assert connection.execute("SELECT count(*) FROM review_decisions").fetchone()[0] == 0


def test_review_defensively_rejects_unknown_ids_after_group_validation(tmp_path: Path) -> None:
    store, _, _ = _review_store(tmp_path)
    service = ReviewService(store)
    current = service.record("R1")
    changed_group = current.span_groups[0].model_copy(update={"finding_ids": ["missing-finding"]})
    changed = replace(current, span_groups=[changed_group])
    event = ReviewSpanEvent(
        event_id="remove-missing",
        operation="remove",
        group_id=changed_group.group_id,
        finding_ids=changed_group.finding_ids,
    )

    with pytest.raises(ValueError, match="unknown PHI IDs"):
        service._preview_findings(changed, [event], reviewer_id="reviewer")
    decision = _decision(disposition="corrected", span_events=[event])
    with store.immediate_transaction() as connection:
        with pytest.raises(ValueError, match="unknown PHI IDs"):
            service._apply_corrections(changed, decision, connection=connection)


def test_review_record_requires_pipeline_rendering(tmp_path: Path) -> None:
    store, _, _ = _review_store(tmp_path)
    with store.connection() as connection:
        connection.execute("DELETE FROM renderings")
    with pytest.raises(KeyError, match="no current pipeline rendering"):
        ReviewService(store).record("R1")


@pytest.mark.parametrize(
    "event",
    [
        ReviewSpanEvent(
            event_id="wrong-text",
            operation="add",
            category=PhiCategory.DATE,
            text="changed",
            start_char=11,
            end_char=18,
        ),
        ReviewSpanEvent(
            event_id="past-end",
            operation="add",
            category=PhiCategory.DATE,
            text="end",
            start_char=20,
            end_char=23,
        ),
    ],
)
def test_review_rejects_manual_spans_that_do_not_match_source(
    tmp_path: Path, event: ReviewSpanEvent
) -> None:
    store, _, _ = _review_store(tmp_path)

    with pytest.raises(ValueError, match="does not match"):
        ReviewService(store).decide(_decision(disposition="corrected", span_events=[event]))

    with store.connection() as connection:
        assert connection.execute("SELECT count(*) FROM review_decisions").fetchone()[0] == 0


def test_review_requires_reviewer_and_normalizes_naive_decision_ids(tmp_path: Path) -> None:
    _review_store(tmp_path)
    with pytest.raises(ValidationError, match="reviewer_id"):
        _decision(disposition="approved_unchanged", reviewer_id=None)
    naive = datetime(2026, 7, 31, 12, 0)
    assert build_review_decision_id("R1", naive) == build_review_decision_id(
        "R1", naive.replace(tzinfo=UTC)
    )


def test_review_disposition_defensively_rejects_unknown_record(tmp_path: Path) -> None:
    store, _, _ = _review_store(tmp_path)
    service = ReviewService(store)
    decision = _decision(disposition="approved_unchanged").model_copy(
        update={"record_id": "missing"}
    )

    with store.immediate_transaction() as connection:
        with pytest.raises(KeyError, match="Unknown record_id"):
            service._apply_record_disposition(decision, connection=connection)


def test_review_preview_validates_and_applies_manual_span_edits(tmp_path: Path) -> None:
    store, _, _ = _review_store(tmp_path)
    service = ReviewService(store, clock=lambda: NOW)
    group = service.record("R1").span_groups[0]

    preview = service.preview(
        "R1",
        [
            ReviewSpanEvent(
                event_id="remove-name-preview",
                operation="remove",
                group_id=group.group_id,
                finding_ids=group.finding_ids,
            ),
            ReviewSpanEvent(
                event_id="add-date-preview",
                operation="add",
                category=PhiCategory.DATE,
                text="visited",
                start_char=11,
                end_char=18,
            ),
        ],
        reviewer_id="reviewer",
    )
    assert preview == "Jane Smith [R_DATE]."

    with pytest.raises(ValueError, match="displayed PHI group changed"):
        service.preview(
            "R1",
            [
                ReviewSpanEvent(
                    event_id="unknown-preview",
                    operation="remove",
                    group_id=group.group_id,
                    finding_ids=["missing"],
                )
            ],
            reviewer_id="reviewer",
        )
    with pytest.raises(ValueError, match="does not match"):
        service.preview(
            "R1",
            [
                ReviewSpanEvent(
                    event_id="bad-preview",
                    operation="add",
                    category=PhiCategory.DATE,
                    text="wrong!!",
                    start_char=11,
                    end_char=18,
                )
            ],
            reviewer_id="reviewer",
        )


def test_structured_review_preview_validates_each_edit_contract(tmp_path: Path) -> None:
    source = tmp_path / "structured-review.jsonl"
    source.write_text(
        '{"record_id":"R1","text":"Routine note.","patient_name":"Alice"}\n',
        encoding="utf-8",
    )
    config = PipelineConfig.model_validate(
        {
            "run": {"output_dir": tmp_path / "structured-runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
                "metadata_columns": ["patient_name"],
                "structured_phi_columns": {"patient_name": "NAME"},
            },
            "detection": {"enabled": False},
            "review": {"enabled": True, "review_scope": "all"},
        }
    )
    engine = PipelineEngine.create(config, timestamp=NOW)
    engine.execute()
    service = ReviewService(engine.store)
    valid = ReviewStructuredEvent(
        event_id="patient-name",
        column_name="patient_name",
        category=PhiCategory.NAME,
        original_value="Alice",
        replacement_value="Patient A",
    )

    assert service.preview_structured("R1", [valid]) == {"patient_name": "Patient A"}
    with pytest.raises(ValueError, match="Only one structured-field change"):
        service.preview_structured(
            "R1",
            [valid, valid.model_copy(update={"event_id": "patient-name-again"})],
        )
    with pytest.raises(ValueError, match="Unknown structured PHI field"):
        service.preview_structured(
            "R1",
            [valid.model_copy(update={"column_name": "missing"})],
        )
    with pytest.raises(ValueError, match="category changed"):
        service.preview_structured(
            "R1",
            [valid.model_copy(update={"category": PhiCategory.DATE})],
        )
    with pytest.raises(ValueError, match="Original structured value changed"):
        service.preview_structured(
            "R1",
            [valid.model_copy(update={"original_value": "Bob"})],
        )


def test_review_preview_uses_real_surrogates_and_date_shift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "surrogate-review.jsonl"
    source.write_text(
        '{"record_id":"R1","entity_id":"E1","text":"Alice on 01/02/2020."}\n',
        encoding="utf-8",
    )
    policy = TransformationPolicy().model_dump(mode="json")
    policy["categories"]["NAME"] = {
        "action": "surrogate",
        "surrogate": {
            "method": "faker",
            "consistency": "entity",
            "secret_reference": "name-secret",
        },
    }
    policy["categories"]["DATE"] = {
        "action": "surrogate",
        "surrogate": {
            "method": "date_shift",
            "consistency": "entity",
            "minimum_weeks": 1,
            "maximum_weeks": 1,
            "secret_reference": "date-secret",
        },
    }
    config = PipelineConfig.model_validate(
        {
            "run": {"output_dir": tmp_path / "surrogate-runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "column", "column": "entity_id"},
                "text_column": "text",
            },
            "detection": {"enabled": False},
            "rules": {
                "enabled": True,
                "embedded": {
                    "rules": [
                        {
                            "id": "name",
                            "name": "Name",
                            "category": "NAME",
                            "type": "exact",
                            "pattern": "Alice",
                        },
                        {
                            "id": "date",
                            "name": "Date",
                            "category": "DATE",
                            "type": "exact",
                            "pattern": "01/02/2020",
                        },
                    ]
                },
            },
            "policy": policy,
            "review": {"enabled": True, "review_scope": "all"},
        }
    )
    secrets = MappingSecretResolver({"name-secret": "name-key", "date-secret": "date-key"})
    engine = PipelineEngine.create(
        config,
        dependencies=EngineDependencies(secrets=secrets),
        timestamp=NOW,
    )
    engine.execute()
    service = ReviewService(engine.store, secrets=secrets, clock=lambda: NOW)

    policy_revision, _ = engine.store.read_active_policy()
    new_shift = service._preview_date_shift(
        entity_id="E-new",
        policy_revision=policy_revision,
        created_at=NOW,
    )
    assert new_shift is not None

    first = service.preview("R1", [], reviewer_id="reviewer")
    second = service.preview("R1", [], reviewer_id="reviewer")
    assert first == second
    assert not first.startswith("Alice")
    assert "01/09/2020" in first

    without_secrets = ReviewService(engine.store, clock=lambda: NOW)
    monkeypatch.setattr(without_secrets, "_preview_date_shift", lambda **_kwargs: None)
    with pytest.raises(ValueError, match="surrogate secrets"):
        without_secrets.preview("R1", [], reviewer_id="reviewer")

    missing_date_secret = ReviewService(engine.store, clock=lambda: NOW)
    with pytest.raises(ValueError, match="date-shift secret"):
        missing_date_secret._preview_date_shift(
            entity_id="E-missing-secret",
            policy_revision=policy_revision,
            created_at=NOW,
        )
