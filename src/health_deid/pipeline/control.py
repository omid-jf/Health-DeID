from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from health_deid.models.config import PipelineConfig
from health_deid.models.ledger import STAGE_NAMES, StageName
from health_deid.storage.database import SqliteRunStore

_RETRYABLE_RECORD_STATES: Final = ("retry_exhausted", "permanent_error")
_RETRYABLE_WORK_STATES: Final = (
    "retry_exhausted",
    "permanent_error",
    "truncated",
    "cancelled",
)
_BACKEND_STAGES: Final = frozenset({"detection", "validation"})


@dataclass(frozen=True, slots=True)
class RetryResult:
    """Records and stages reset by one explicit manual retry request."""

    record_ids: tuple[str, ...]
    stages: tuple[StageName, ...]

    @property
    def record_count(self) -> int:
        return len(self.record_ids)


class RunControlService:
    """Transactional run-state controls shared by the API, CLI, and UI."""

    def __init__(self, store: SqliteRunStore) -> None:
        self.store = store

    def retry(
        self,
        *,
        stage: StageName | None = None,
        failed: bool = False,
        record_id: str | None = None,
        updated_at: datetime | None = None,
    ) -> RetryResult:
        """Reset explicitly selected failed work while preserving attempt history."""

        record_id = _validate_retry_request(record_id=record_id, stage=stage, failed=failed)

        timestamp = _utc_text(updated_at or datetime.now(UTC))
        run_id = self.store.run_id()
        config = self.store.read_config()
        _, active_policy = self.store.read_active_policy()
        config = config.model_copy(update={"policy": active_policy})

        with self.store.connection() as connection:
            selected = _select_retry_targets(
                connection,
                run_id=run_id,
                record_id=record_id,
                stage=stage,
            )
            if not selected:
                target = f"record {record_id!r}" if record_id is not None else f"stage {stage!r}"
                raise ValueError(f"No retryable failed work was found for {target}.")

            affected_stages: set[StageName] = set()
            for selected_record_id, failed_stage in selected.items():
                affected_stages.update(
                    self._reset_record(
                        connection,
                        run_id=run_id,
                        record_id=selected_record_id,
                        failed_stage=failed_stage,
                        timestamp=timestamp,
                        config=config,
                    )
                )

            _reset_run_stages(connection, run_id=run_id, stages=affected_stages)
            connection.execute(
                "UPDATE runs SET status = 'blocked', updated_at = ? WHERE run_id = ?",
                (timestamp, run_id),
            )

        ordered_stages = tuple(item for item in STAGE_NAMES if item in affected_stages)
        return RetryResult(record_ids=tuple(selected), stages=ordered_stages)

    def _reset_record(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        record_id: str,
        failed_stage: StageName,
        timestamp: str,
        config: PipelineConfig,
    ) -> set[StageName]:
        start = STAGE_NAMES.index(failed_stage)
        affected = set(STAGE_NAMES[start:])

        for stage in affected:
            status = "pending" if _stage_enabled(config, stage) else "skipped"
            connection.execute(
                """
                UPDATE record_stage_states
                SET status = ?, started_at = NULL, finished_at = NULL, updated_at = ?
                WHERE run_id = ? AND record_id = ? AND stage_name = ?
                  AND status != 'excluded'
                """,
                (status, timestamp, run_id, record_id, stage),
            )

        if failed_stage in _BACKEND_STAGES:
            _reset_backend_work(
                connection,
                run_id=run_id,
                record_id=record_id,
                stage=failed_stage,
                timestamp=timestamp,
            )

        _stale_downstream_state(
            connection,
            run_id=run_id,
            record_id=record_id,
            failed_stage=failed_stage,
            timestamp=timestamp,
        )
        return affected


def _validate_retry_request(
    *,
    record_id: str | None,
    stage: StageName | None,
    failed: bool,
) -> str | None:
    normalized_record_id = record_id.strip() if record_id is not None else None

    if normalized_record_id == "":
        raise ValueError("record_id cannot be blank.")
    if normalized_record_id is None and (stage is None or not failed):
        raise ValueError("Select --record-id, or select --stage together with --failed.")
    if normalized_record_id is not None and failed:
        raise ValueError("--failed cannot be combined with --record-id.")
    if stage is not None and stage not in STAGE_NAMES:
        raise ValueError(f"Unknown pipeline stage: {stage}")

    return normalized_record_id


def _select_retry_targets(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    record_id: str | None,
    stage: StageName | None,
) -> dict[str, StageName]:
    if record_id is not None:
        exists = connection.execute(
            "SELECT 1 FROM records WHERE run_id = ? AND record_id = ?",
            (run_id, record_id),
        ).fetchone()
        if exists is None:
            raise KeyError(f"Unknown record_id: {record_id}")

    clauses = ["run_id = ?", "status IN (?, ?)"]
    parameters: list[object] = [run_id, *_RETRYABLE_RECORD_STATES]

    if record_id is not None:
        clauses.append("record_id = ?")
        parameters.append(record_id)
    if stage is not None:
        clauses.append("stage_name = ?")
        parameters.append(stage)

    stage_order = " ".join(f"WHEN '{name}' THEN {index}" for index, name in enumerate(STAGE_NAMES))
    rows = connection.execute(
        f"""
        SELECT record_id, stage_name FROM record_stage_states
        WHERE {" AND ".join(clauses)}
        ORDER BY record_id, CASE stage_name {stage_order} END
        """,
        parameters,
    ).fetchall()

    selected: dict[str, StageName] = {}
    for row in rows:
        selected.setdefault(str(row["record_id"]), str(row["stage_name"]))  # type: ignore[arg-type]

    return selected


def _reset_run_stages(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    stages: set[StageName],
) -> None:
    for stage in stages:
        connection.execute(
            """
            UPDATE run_stages
            SET status = 'pending', started_at = NULL, finished_at = NULL
            WHERE run_id = ? AND stage_name = ?
            """,
            (run_id, stage),
        )


def _reset_backend_work(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    record_id: str,
    stage: StageName,
    timestamp: str,
) -> None:
    connection.execute(
        """
        UPDATE backend_work_items SET status = 'retry_pending', updated_at = ?
        WHERE run_id = ? AND record_id = ? AND stage_name = ?
          AND status IN (?, ?, ?, ?)
        """,
        (timestamp, run_id, record_id, stage, *_RETRYABLE_WORK_STATES),
    )


def _stage_enabled(config: PipelineConfig, stage: StageName) -> bool:
    if stage == "detection":
        return bool(config.detection.enabled or config.rules.enabled)
    if stage == "validation":
        return bool(config.validation.enabled)
    if stage == "review":
        return bool(config.review.enabled or config.validation.enabled)
    return True


def _stale_downstream_state(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    record_id: str,
    failed_stage: StageName,
    timestamp: str,
) -> None:
    stage_index = STAGE_NAMES.index(failed_stage)
    if stage_index <= STAGE_NAMES.index("transformation"):
        connection.execute(
            """
            UPDATE transformation_plans SET status = 'stale', stale_at = ?,
                stale_reason = 'manual retry'
            WHERE run_id = ? AND record_id = ? AND status = 'active'
            """,
            (timestamp, run_id, record_id),
        )
    if stage_index <= STAGE_NAMES.index("validation"):
        connection.execute(
            "UPDATE validation_results SET is_stale = 1 WHERE run_id = ? AND record_id = ?",
            (run_id, record_id),
        )
    if stage_index <= STAGE_NAMES.index("review"):
        connection.execute(
            """
            UPDATE review_decisions SET is_stale = 1, is_current = 0,
                stale_reason = 'manual retry'
            WHERE run_id = ? AND record_id = ? AND is_current = 1
            """,
            (run_id, record_id),
        )
    if stage_index <= STAGE_NAMES.index("finalization"):
        connection.execute(
            "UPDATE renderings SET is_stale = 1 WHERE run_id = ? AND record_id = ?",
            (run_id, record_id),
        )
        connection.execute(
            """
            UPDATE records SET status = 'processing', final_rendering_id = NULL,
                final_metadata_json = NULL, updated_at = ?
            WHERE run_id = ? AND record_id = ?
            """,
            (timestamp, run_id, record_id),
        )


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("updated_at must be timezone-aware.")
    return value.astimezone(UTC).isoformat()
