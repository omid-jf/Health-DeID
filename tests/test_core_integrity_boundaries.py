from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

import health_deid.pipeline.engine as engine_module
from health_deid.backends.contracts import PhiValidator
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import (
    ValidationFinding,
    ValidationResult,
    ValidationUsage,
)
from health_deid.models.config import PipelineConfig
from health_deid.models.review import ReviewDecision, ReviewSpanEvent
from health_deid.pipeline.engine import EngineDependencies, PipelineEngine
from health_deid.pipeline.review import ReviewService
from health_deid.storage.database import RunDatabaseError


class _FlaggingValidator(PhiValidator):
    def validate(
        self,
        *,
        original_text: str,
        deidentified_text: str,
    ) -> ValidationResult:
        return ValidationResult(
            findings=[
                ValidationFinding(
                    category=PhiCategory.NAME,
                    rationale="A name remains.",
                    source="test-validator",
                )
            ],
            rationale="Manual review is required.",
            raw_output={},
            usage=ValidationUsage(
                input_chars=len(original_text) + len(deidentified_text),
                input_bytes=len(original_text.encode()) + len(deidentified_text.encode()),
                latency_ms=0.0,
            ),
        )


def _config(tmp_path: Path, *, validation: bool = False) -> PipelineConfig:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "records.jsonl"
    source.write_text('{"record_id":"N001","text":"Alice arrived."}\n', encoding="utf-8")
    return PipelineConfig.model_validate(
        {
            "run": {"output_dir": tmp_path / "runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
            },
            "detection": {"enabled": False},
            "validation": {
                "enabled": validation,
                "execution": {"workers": 1},
            },
            "review": {"enabled": validation},
        }
    )


def test_corrected_review_rolls_back_every_mutation_on_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = PipelineEngine.create(
        _config(tmp_path, validation=True),
        dependencies=EngineDependencies(validator_factory=lambda _: _FlaggingValidator()),
    )
    engine.execute()
    service = ReviewService(engine.store)
    basis_revision = service.record("N001").plan_revision
    decision = ReviewDecision(
        decision_id="decision-invalid-comment",
        record_id="N001",
        basis_plan_revision=basis_revision,
        disposition="corrected",
        reviewer_id="reviewer",
        decided_at=datetime.now(UTC),
        record_comment=None,
        span_events=[
            ReviewSpanEvent(
                event_id="manual-name",
                operation="add",
                category=PhiCategory.NAME,
                text="Alice",
                start_char=0,
                end_char=5,
            )
        ],
    )

    original_save = service.reviews.save_decision

    def fail_after_corrections(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise sqlite3.IntegrityError("simulated late write failure")

    monkeypatch.setattr(service.reviews, "save_decision", fail_after_corrections)
    with pytest.raises(sqlite3.IntegrityError, match="late write failure"):
        service.decide(decision)

    with engine.store.connection() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM findings WHERE source_kind = 'review'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT count(*) FROM review_decisions").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM resolution_revisions").fetchone()[0] == 1
        assert connection.execute("SELECT status FROM records").fetchone()[0] == "awaiting_review"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    monkeypatch.setattr(service.reviews, "save_decision", original_save)
    service.decide(decision.model_copy(update={"decision_id": "decision-valid"}))
    engine.resume()

    with engine.store.connection() as connection:
        assert (
            connection.execute(
                """
            SELECT rendered_text FROM renderings
            WHERE kind = 'final' AND is_stale = 0
            """
            ).fetchone()[0]
            == "[R_NAME] arrived."
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_unexpected_run_error_is_audited_releases_file_lock_and_can_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = PipelineEngine.create(_config(tmp_path))
    original_transformation = engine.run_transformation

    def fail_transformation() -> None:
        raise RuntimeError("transformation setup exploded")

    monkeypatch.setattr(engine, "run_transformation", fail_transformation)
    with pytest.raises(RuntimeError, match="transformation setup exploded"):
        engine.execute()

    with engine.store.connection() as connection:
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "failed"
        assert (
            connection.execute(
                "SELECT status FROM run_stages WHERE stage_name = 'transformation'"
            ).fetchone()[0]
            == "failed"
        )
        error = connection.execute(
            """
            SELECT record_id, stage_name, error_code, resolved
            FROM processing_errors
            """
        ).fetchone()
        assert tuple(error) == (None, "transformation", "unexpected_run_error", 0)

    monkeypatch.setattr(engine, "run_transformation", original_transformation)
    engine.resume()

    with engine.store.connection() as connection:
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "completed"
        assert (
            connection.execute(
                "SELECT resolved FROM processing_errors WHERE stage_name = 'transformation'"
            ).fetchone()[0]
            == 1
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_run_level_failure_and_unfinished_records_use_run_status_branches(tmp_path: Path) -> None:
    engine = PipelineEngine.create(_config(tmp_path))
    engine._refresh_run_status()
    assert engine.store.read_run_status() == "blocked"

    engine._record_run_level_failure(
        RuntimeError("run-level failure"),
        stage="run",
        run_status="failed",
        stage_status="failed",
        retryable=False,
    )
    assert engine.store.read_run_status() == "failed"


def test_engine_lock_interrupt_and_failure_cleanup_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    busy_engine = PipelineEngine.create(_config(tmp_path / "busy"))

    class BusyLock:
        def acquire(self, *, timeout: int) -> None:
            del timeout
            raise engine_module.Timeout("busy")

    with monkeypatch.context() as patcher:
        patcher.setattr(engine_module, "FileLock", lambda _path: BusyLock())
        with pytest.raises(RunDatabaseError, match="already being processed"):
            busy_engine.execute()

    interrupted = PipelineEngine.create(_config(tmp_path / "interrupted"))
    with monkeypatch.context() as patcher:
        patcher.setattr(
            interrupted,
            "run_detection",
            lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        with pytest.raises(KeyboardInterrupt):
            interrupted.execute()
    assert interrupted.store.read_run_status() == "blocked"
    assert interrupted.store.read_stage_status("detection") == "blocked"

    bookkeeping_error = RuntimeError("original failure")
    with monkeypatch.context() as patcher:
        patcher.setattr(
            engine_module.SqliteRunStore,
            "record_processing_error",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("database unavailable")),
        )
        interrupted._record_run_level_failure(
            bookkeeping_error,
            stage="run",
            run_status="failed",
            stage_status="failed",
            retryable=False,
        )
    assert "bookkeeping also failed" in bookkeeping_error.__notes__[0]

    create_root = tmp_path / "create-failure"
    create_root.mkdir()
    with monkeypatch.context() as patcher:
        patcher.setattr(
            engine_module.SqliteRunStore,
            "create",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("create failed")),
        )
        with pytest.raises(RuntimeError, match="create failed"):
            PipelineEngine.create(_config(create_root))
    assert not any((create_root / "runs").glob("*"))

    cleanup_root = tmp_path / "cleanup-failure"
    cleanup_root.mkdir()
    cleanup_config = _config(cleanup_root)
    cleanup_context = engine_module.RunContext.from_config(cleanup_config)
    cleanup_context.run_dir.mkdir(parents=True)
    cleanup_error = RuntimeError("create failed")
    with monkeypatch.context() as patcher:
        patcher.setattr(
            engine_module.shutil,
            "rmtree",
            lambda path: (_ for _ in ()).throw(OSError(f"cannot remove {path}")),
        )
        engine_module._remove_partial_run(cleanup_context, error=cleanup_error)
    assert "cleanup also failed" in cleanup_error.__notes__[0]
