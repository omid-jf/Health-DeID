from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from health_deid.backends.runtime import BackendExecutionError, TextChunk
from health_deid.models.config import PipelineConfig
from health_deid.models.input import (
    InputImportSummary,
    NormalizedInputRecord,
    TextNormalizationAudit,
)
from health_deid.pipeline.control import RunControlService
from health_deid.storage.database import SqliteRunStore
from health_deid.storage.findings import BackendDefinition, FindingRepository

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def _store(
    tmp_path: Path,
    *,
    detection: bool = False,
    rules: bool = False,
) -> SqliteRunStore:
    config = PipelineConfig.model_validate(
        {
            "input": {
                "path": tmp_path / "input.parquet",
                "format": "parquet",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
            },
            "rules": {
                "enabled": rules,
                **({"rules_path": tmp_path / "rules.yaml"} if rules else {}),
            },
            "detection": {
                "enabled": detection,
                **(
                    {
                        "detectors": [
                            {
                                "backend": "aws_comprehend_medical",
                            }
                        ]
                    }
                    if detection
                    else {}
                ),
            },
        }
    )
    store = SqliteRunStore.create(
        tmp_path / "run.sqlite",
        run_id="run-1",
        config=config,
        created_at=NOW,
    )
    record = NormalizedInputRecord(
        source_index=0,
        record_id="record-1",
        entity_id="record-1",
        raw_source_text="Jane Smith",
        source_text="Jane Smith",
        text_normalization=TextNormalizationAudit(
            normalizer_version="6.3.1",
            changed=False,
        ),
        status="active",
    )
    summary = InputImportSummary(
        source_name="input.parquet",
        source_path=tmp_path / "input.parquet",
        source_format="parquet",
        source_size_bytes=1,
        source_sha256="a" * 64,
        record_count=1,
        active_count=1,
        excluded_count=0,
        normalized_count=0,
        imported_at=NOW,
    )
    store.import_records([record], summary)
    return store


def _set_stage(store: SqliteRunStore, stage: str, status: str) -> None:
    with store.connection() as connection:
        connection.execute(
            """
            UPDATE record_stage_states SET status = ?, updated_at = ?
            WHERE run_id = ? AND record_id = 'record-1' AND stage_name = ?
            """,
            (status, NOW.isoformat(), store.run_id(), stage),
        )


def test_retry_failed_backend_work_resets_record_and_downstream(tmp_path: Path) -> None:
    store = _store(tmp_path, detection=True)
    repository = FindingRepository(store)
    repository.register_backend(
        BackendDefinition(
            backend_id="detector",
            kind="detector",
            name="detector",
            version="1",
            model_id=None,
            settings={},
        ),
        created_at=NOW,
    )
    work = repository.prepare_work(
        record_id="record-1",
        backend_id="detector",
        stage_name="detection",
        chunks=[TextChunk(index=0, start_char=0, end_char=10, text="Jane Smith")],
        created_at=NOW,
    )[0]
    attempt_id, attempt_number = repository.begin_attempt(work, started_at=NOW)
    repository.fail_attempt(
        attempt_id=attempt_id,
        work_item=work,
        error=BackendExecutionError(
            code="invalid",
            message="invalid response",
            retryable=False,
        ),
        attempt_number=attempt_number,
        maximum_attempts=3,
        finished_at=NOW,
    )
    _set_stage(store, "detection", "permanent_error")
    for stage in ("transformation", "finalization", "export"):
        _set_stage(store, stage, "blocked")

    result = RunControlService(store).retry(
        stage="detection",
        failed=True,
        updated_at=NOW,
    )

    assert result.record_ids == ("record-1",)
    assert result.record_count == 1
    assert result.stages == (
        "detection",
        "transformation",
        "validation",
        "review",
        "finalization",
        "export",
    )
    with store.connection() as connection:
        states = {
            str(row["stage_name"]): str(row["status"])
            for row in connection.execute(
                "SELECT stage_name, status FROM record_stage_states WHERE record_id = 'record-1'"
            )
        }
        assert states["detection"] == "pending"
        assert states["transformation"] == "pending"
        assert states["validation"] == "skipped"
        assert states["review"] == "skipped"
        assert states["finalization"] == "pending"
        assert states["export"] == "pending"
        assert (
            connection.execute(
                "SELECT status FROM backend_work_items WHERE work_item_id = ?", (work.work_item_id,)
            ).fetchone()[0]
            == "retry_pending"
        )
        assert connection.execute("SELECT status FROM runs").fetchone()[0] == "blocked"


def test_retry_record_selects_earliest_failure_and_validates_selection(tmp_path: Path) -> None:
    store = _store(tmp_path, rules=True)
    service = RunControlService(store)
    _set_stage(store, "detection", "permanent_error")
    _set_stage(store, "finalization", "retry_exhausted")

    result = service.retry(record_id=" record-1 ", updated_at=NOW)
    assert result.stages[0] == "detection"
    assert result.stages[-1] == "export"

    with pytest.raises(ValueError, match="Select --record-id"):
        service.retry(updated_at=NOW)
    with pytest.raises(ValueError, match="cannot be combined"):
        service.retry(record_id="record-1", failed=True, updated_at=NOW)
    with pytest.raises(ValueError, match="cannot be blank"):
        service.retry(record_id=" ", updated_at=NOW)
    with pytest.raises(ValueError, match="Unknown pipeline stage"):
        service.retry(stage=cast(Any, "unknown"), failed=True, updated_at=NOW)
    with pytest.raises(KeyError, match="Unknown record_id"):
        service.retry(record_id="missing", updated_at=NOW)
    with pytest.raises(ValueError, match="No retryable failed work"):
        service.retry(record_id="record-1", updated_at=NOW)


def test_retry_requires_timezone_aware_timestamp(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _set_stage(store, "finalization", "permanent_error")
    with pytest.raises(ValueError, match="timezone-aware"):
        RunControlService(store).retry(
            record_id="record-1",
            updated_at=datetime(2026, 7, 31),
        )


@pytest.mark.parametrize("stage", ["finalization", "export"])
def test_retry_late_stage_only_invalidates_relevant_downstream_state(
    tmp_path: Path,
    stage: str,
) -> None:
    store = _store(tmp_path)
    _set_stage(store, stage, "permanent_error")
    result = RunControlService(store).retry(record_id="record-1", updated_at=NOW)
    assert result.stages[0] == stage
