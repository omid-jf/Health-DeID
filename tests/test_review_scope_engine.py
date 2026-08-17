from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from health_deid.backends.contracts import PhiValidator
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import (
    ValidationFinding,
    ValidationResult,
    ValidationUsage,
)
from health_deid.models.config import PipelineConfig
from health_deid.models.review import ReviewDecision
from health_deid.pipeline.engine import EngineDependencies, PipelineEngine
from health_deid.pipeline.review import ReviewService
from health_deid.storage.reviews import ReviewRepository

NOW = datetime(2026, 7, 31, 17, 0, tzinfo=UTC)


class FixedValidator(PhiValidator):
    def __init__(self, *, violation: bool) -> None:
        self.violation = violation

    def validate(
        self,
        *,
        original_text: str,
        deidentified_text: str,
    ) -> ValidationResult:
        del original_text, deidentified_text
        findings = (
            [
                ValidationFinding(
                    category=PhiCategory.NAME,
                    evidence="Alice",
                    rationale="A residual name remains.",
                    source="scope-test-validator",
                )
            ]
            if self.violation
            else []
        )
        return ValidationResult(
            findings=findings,
            rationale="Residual identifier." if findings else "No residual identifier.",
            raw_output={"violation": bool(findings)},
            usage=ValidationUsage(input_chars=1, input_bytes=1, latency_ms=0),
        )


def _engine(
    tmp_path: Path,
    *,
    review_enabled: bool,
    review_scope: str,
    violation: bool,
) -> PipelineEngine:
    source = tmp_path / "records.jsonl"
    source.write_text(
        json.dumps({"record_id": "R1", "text": "Alice arrived."}) + "\n",
        encoding="utf-8",
    )
    config = PipelineConfig.model_validate(
        {
            "run": {"name": "review-scope", "output_dir": tmp_path / "runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
            },
            "detection": {"enabled": False},
            "validation": {"enabled": True},
            "review": {"enabled": review_enabled, "review_scope": review_scope},
        }
    )
    dependencies = EngineDependencies(
        validator_factory=lambda _: FixedValidator(violation=violation),
        clock=lambda: NOW,
    )
    return PipelineEngine.create(config, dependencies=dependencies, timestamp=NOW)


def _record_stage(engine: PipelineEngine, stage: str) -> str:
    with engine.store.connection() as connection:
        row = connection.execute(
            "SELECT status FROM record_stage_states WHERE record_id = 'R1' AND stage_name = ?",
            (stage,),
        ).fetchone()
    return str(row[0])


def test_review_scope_all_queues_validation_passes_before_finalization(tmp_path: Path) -> None:
    engine = _engine(
        tmp_path,
        review_enabled=True,
        review_scope="all",
        violation=False,
    )

    engine.execute()

    assert engine.store.read_run_status() == "awaiting_review"
    assert engine.store.read_record("R1")["status"] == "awaiting_review"
    assert _record_stage(engine, "review") == "review_pending"
    assert _record_stage(engine, "finalization") == "pending"
    assert ReviewRepository(engine.store).queue() == ["R1"]

    review = ReviewService(engine.store).record("R1")
    ReviewService(engine.store).decide(
        ReviewDecision(
            decision_id="approve-validation-pass",
            record_id="R1",
            basis_plan_revision=review.plan_revision,
            disposition="approved_unchanged",
            reviewer_id="reviewer",
            decided_at=NOW,
        )
    )
    engine.resume()

    assert engine.store.read_run_status() == "completed"
    assert engine.store.read_record("R1")["status"] == "ready"
    assert ReviewRepository(engine.store).queue() == []


def test_validator_concern_queues_configured_review(tmp_path: Path) -> None:
    engine = _engine(
        tmp_path,
        review_enabled=True,
        review_scope="effective_validation_failures",
        violation=True,
    )

    engine.execute()

    assert engine.store.read_run_status() == "awaiting_review"
    assert engine.store.read_record("R1")["status"] == "awaiting_review"
    assert _record_stage(engine, "review") == "review_pending"
    assert _record_stage(engine, "finalization") == "pending"
    assert ReviewRepository(engine.store).queue() == ["R1"]
    with engine.store.connection() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM records WHERE status = 'awaiting_review'"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT effective_violation FROM validation_results WHERE is_stale = 0"
            ).fetchone()[0]
            == 1
        )
