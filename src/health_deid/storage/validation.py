from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from health_deid.backends.runtime import BackendExecutionError
from health_deid.core.ids import build_content_id
from health_deid.models.backend import ValidationFinding, ValidationResult
from health_deid.models.ledger import Rendering
from health_deid.models.policy import TransformationAction, TransformationPolicy
from health_deid.storage.database import SqliteRunStore
from health_deid.storage.findings import BackendWorkItem


@dataclass(frozen=True, slots=True)
class StoredValidation:
    validation_id: str
    raw_violation: bool
    effective_violation: bool
    findings: list[ValidationFinding]


class ValidationRepository:
    def __init__(self, store: SqliteRunStore) -> None:
        self.store = store

    def finish_success(
        self,
        *,
        attempt_id: str,
        work_item: BackendWorkItem,
        rendering: Rendering,
        result: ValidationResult,
        policy: TransformationPolicy,
        finished_at: datetime,
    ) -> StoredValidation:
        run_id = self.store.run_id()
        review = self.store.read_config().review
        timestamp = _utc_text(finished_at)
        normalized_findings = [
            finding.model_copy(
                update={
                    "finding_id": build_content_id(
                        "validation-finding",
                        run_id,
                        work_item.record_id,
                        rendering.rendering_id,
                        index,
                        finding.category.value,
                        finding.evidence,
                    ),
                    "ignored_by_policy": (
                        policy.categories[finding.category].action is TransformationAction.RETAIN
                    ),
                }
            )
            for index, finding in enumerate(result.findings, start=1)
        ]
        raw_violation = bool(normalized_findings)
        effective_violation = any(not item.ignored_by_policy for item in normalized_findings)
        validation_id = build_content_id(
            "validation", run_id, work_item.record_id, rendering.rendering_id, attempt_id
        )
        with self.store.connection() as connection:
            attempt = connection.execute(
                "SELECT status FROM backend_attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None or str(attempt[0]) != "running":
                raise ValueError(f"Attempt {attempt_id!r} is not running.")
            connection.execute(
                """
                UPDATE backend_attempts
                SET status = 'succeeded', stop_reason = ?, finished_at = ?,
                    raw_response = ?, usage_json = ?, retryable = 0
                WHERE attempt_id = ?
                """,
                (
                    result.stop_reason,
                    timestamp,
                    _json(result.raw_output),
                    _json(result.usage.model_dump(mode="json")),
                    attempt_id,
                ),
            )
            connection.execute(
                "UPDATE backend_work_items SET status = 'succeeded', updated_at = ? WHERE work_item_id = ?",
                (timestamp, work_item.work_item_id),
            )
            connection.execute(
                """
                UPDATE validation_results SET is_stale = 1
                WHERE run_id = ? AND record_id = ? AND is_stale = 0
                """,
                (run_id, work_item.record_id),
            )
            connection.execute(
                """
                INSERT INTO validation_results(
                    validation_id, run_id, record_id, rendering_id,
                    backend_attempt_id, status, raw_violation, effective_violation,
                    rationale, is_stale, created_at
                ) VALUES (?, ?, ?, ?, ?, 'succeeded', ?, ?, ?, 0, ?)
                """,
                (
                    validation_id,
                    run_id,
                    work_item.record_id,
                    rendering.rendering_id,
                    attempt_id,
                    int(raw_violation),
                    int(effective_violation),
                    result.rationale,
                    timestamp,
                ),
            )
            for finding in normalized_findings:
                assert finding.finding_id is not None
                connection.execute(
                    """
                    INSERT INTO validation_findings(
                        validation_finding_id, run_id, record_id, validation_id,
                        canonical_category, evidence, rule_ids_json, confidence,
                        rationale, ignored_by_policy
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.finding_id,
                        run_id,
                        work_item.record_id,
                        validation_id,
                        finding.category.value,
                        finding.evidence,
                        _json(finding.rule_ids),
                        finding.confidence,
                        finding.rationale,
                        int(finding.ignored_by_policy),
                    ),
                )
            connection.execute(
                """
                UPDATE record_stage_states
                SET status = 'succeeded', finished_at = ?, updated_at = ?
                WHERE run_id = ? AND record_id = ? AND stage_name = 'validation'
                """,
                (timestamp, timestamp, run_id, work_item.record_id),
            )
            requires_review = effective_violation or (
                review.enabled and review.review_scope == "all"
            )
            if requires_review:
                review_status = "review_pending"
                record_status = "awaiting_review"
            else:
                review_status = "skipped"
                record_status = None
            review_finished_at = None if requires_review else timestamp
            connection.execute(
                """
                UPDATE record_stage_states
                SET status = ?, finished_at = ?, updated_at = ?
                WHERE run_id = ? AND record_id = ? AND stage_name = 'review'
                """,
                (
                    review_status,
                    review_finished_at,
                    timestamp,
                    run_id,
                    work_item.record_id,
                ),
            )
            if record_status is not None:
                connection.execute(
                    """
                    UPDATE records SET status = ?, updated_at = ?
                    WHERE run_id = ? AND record_id = ?
                    """,
                    (record_status, timestamp, run_id, work_item.record_id),
                )
            connection.execute(
                """
                UPDATE processing_errors SET resolved = 1, resolved_at = ?
                WHERE run_id = ? AND record_id = ? AND stage_name = 'validation'
                  AND resolved = 0
                """,
                (timestamp, run_id, work_item.record_id),
            )
        return StoredValidation(
            validation_id=validation_id,
            raw_violation=raw_violation,
            effective_violation=effective_violation,
            findings=normalized_findings,
        )

    def record_failure(
        self,
        *,
        attempt_id: str,
        work_item: BackendWorkItem,
        rendering: Rendering,
        error: BackendExecutionError,
        finished_at: datetime,
        connection: sqlite3.Connection | None = None,
    ) -> str:
        """Persist one terminal validator failure without misclassifying it as PHI."""

        if connection is None:
            with self.store.connection() as owned_connection:
                return self.record_failure(
                    attempt_id=attempt_id,
                    work_item=work_item,
                    rendering=rendering,
                    error=error,
                    finished_at=finished_at,
                    connection=owned_connection,
                )
        run_id = self.store.run_id(connection)
        if work_item.stage_name != "validation":
            raise ValueError("Validation failures require a validation work item.")
        if rendering.record_id != work_item.record_id:
            raise ValueError("Validation rendering and work item must reference the same record.")
        attempt = connection.execute(
            """
            SELECT status, record_id, work_item_id FROM backend_attempts
            WHERE run_id = ? AND attempt_id = ?
            """,
            (run_id, attempt_id),
        ).fetchone()
        terminal_statuses = {"retryable_error", "permanent_error", "truncated", "cancelled"}
        if attempt is None or str(attempt["status"]) not in terminal_statuses:
            raise ValueError(f"Attempt {attempt_id!r} is not a terminal failed attempt.")
        if (
            str(attempt["record_id"]) != work_item.record_id
            or str(attempt["work_item_id"]) != work_item.work_item_id
        ):
            raise ValueError("Validation attempt does not match its work item.")
        status = "truncated" if error.truncated else "technical_error"
        if (str(attempt["status"]) == "truncated") != error.truncated:
            raise ValueError("Validation error truncation does not match the stored attempt.")
        timestamp = _utc_text(finished_at)
        validation_id = build_content_id(
            "validation-failure",
            run_id,
            work_item.record_id,
            rendering.rendering_id,
            attempt_id,
            status,
        )
        if (
            connection.execute(
                "SELECT 1 FROM validation_results WHERE validation_id = ?", (validation_id,)
            ).fetchone()
            is not None
        ):
            return validation_id
        connection.execute(
            """
            UPDATE validation_results SET is_stale = 1
            WHERE run_id = ? AND record_id = ? AND is_stale = 0
            """,
            (run_id, work_item.record_id),
        )
        connection.execute(
            """
            INSERT INTO validation_results(
                validation_id, run_id, record_id, rendering_id,
                backend_attempt_id, status, raw_violation, effective_violation,
                rationale, is_stale, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, 0, ?)
            """,
            (
                validation_id,
                run_id,
                work_item.record_id,
                rendering.rendering_id,
                attempt_id,
                status,
                error.message,
                timestamp,
            ),
        )
        return validation_id


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Timestamps must include timezone information.")
    return value.astimezone(UTC).isoformat()
