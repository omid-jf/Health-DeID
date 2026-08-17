from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import cast

from health_deid.models.review import (
    ReviewDecision,
    ReviewSpanEvent,
    ReviewStructuredEvent,
    ReviewWorkspace,
    ValidationFindingReview,
)
from health_deid.storage.database import SqliteRunStore


class ReviewRepository:
    def __init__(self, store: SqliteRunStore) -> None:
        self.store = store

    def queue(self) -> list[str]:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            rows = connection.execute(
                """
                SELECT records.record_id FROM records
                JOIN record_stage_states USING (run_id, record_id)
                WHERE records.run_id = ? AND stage_name = 'review'
                  AND record_stage_states.status = 'review_pending'
                ORDER BY records.source_index
                """,
                (run_id,),
            ).fetchall()
        return [str(row[0]) for row in rows]

    def has_workspace(self, record_id: str) -> bool:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            return (
                connection.execute(
                    """
                    SELECT 1 FROM review_workspaces
                    WHERE run_id = ? AND record_id = ?
                    """,
                    (run_id, record_id),
                ).fetchone()
                is not None
            )

    def current_basis_plan_revision(
        self,
        record_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> int:
        if connection is None:
            with self.store.connection() as owned_connection:
                return self.current_basis_plan_revision(record_id, connection=owned_connection)
        run_id = self.store.run_id(connection)
        row = connection.execute(
            """
            SELECT plan_revision FROM transformation_plans
            WHERE run_id = ? AND record_id = ? AND purpose = 'draft'
              AND status = 'active'
            """,
            (run_id, record_id),
        ).fetchone()
        if row is not None:
            return int(row[0])
        row = connection.execute(
            """
            SELECT basis_plan_revision FROM review_decisions
            WHERE run_id = ? AND record_id = ? AND is_current = 1 AND is_stale = 0
            """,
            (run_id, record_id),
        ).fetchone()
        if row is not None:
            return int(row[0])
        row = connection.execute(
            """
            SELECT plan_revision FROM transformation_plans
            WHERE run_id = ? AND record_id = ? AND purpose = 'draft'
            ORDER BY plan_revision DESC LIMIT 1
            """,
            (run_id, record_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"Record {record_id!r} has no active draft plan.")
        return int(row[0])

    def open_workspace(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        opened_at: datetime,
        start_timer: bool = True,
    ) -> ReviewWorkspace:
        """Open one draft and enforce a single active timer per reviewer."""

        reviewer_id = _required_text(reviewer_id, "reviewer_id")
        timestamp = _utc_text(opened_at)
        with self.store.immediate_transaction() as connection:
            self._ensure_workspace(
                connection,
                record_id=record_id,
                reviewer_id=reviewer_id,
                timestamp=timestamp,
            )
            if start_timer:
                self._pause_other_timers(
                    connection,
                    reviewer_id=reviewer_id,
                    except_record_id=record_id,
                    paused_at=opened_at,
                )
                connection.execute(
                    """
                    UPDATE review_workspaces SET timer_started_at = coalesce(timer_started_at, ?),
                        updated_at = ?
                    WHERE run_id = ? AND record_id = ?
                    """,
                    (timestamp, timestamp, self.store.run_id(connection), record_id),
                )
            row = self._workspace_row(connection, record_id)
        return _workspace_from_row(row, as_of=opened_at)

    def save_workspace(
        self,
        *,
        record_id: str,
        reviewer_id: str,
        basis_plan_revision: int,
        span_events: list[ReviewSpanEvent],
        structured_events: list[ReviewStructuredEvent],
        validation_finding_reviews: list[ValidationFindingReview],
        record_comment: str | None,
        saved_at: datetime,
    ) -> ReviewWorkspace:
        reviewer_id = _required_text(reviewer_id, "reviewer_id")
        timestamp = _utc_text(saved_at)
        with self.store.immediate_transaction() as connection:
            current_revision = self.current_basis_plan_revision(
                record_id,
                connection=connection,
            )
            if current_revision != basis_plan_revision:
                raise ValueError(
                    "Review draft is stale because the transformation plan changed; "
                    "reload the record."
                )
            self._ensure_workspace(
                connection,
                record_id=record_id,
                reviewer_id=reviewer_id,
                timestamp=timestamp,
            )
            connection.execute(
                """
                UPDATE review_workspaces
                SET reviewer_id = ?, basis_plan_revision = ?, span_events_json = ?,
                    structured_events_json = ?, validation_reviews_json = ?,
                    record_comment = ?, updated_at = ?
                WHERE run_id = ? AND record_id = ?
                """,
                (
                    reviewer_id,
                    basis_plan_revision,
                    _json([event.model_dump(mode="json") for event in span_events]),
                    _json([event.model_dump(mode="json") for event in structured_events]),
                    _json(
                        [review.model_dump(mode="json") for review in validation_finding_reviews]
                    ),
                    record_comment,
                    timestamp,
                    self.store.run_id(connection),
                    record_id,
                ),
            )
            row = self._workspace_row(connection, record_id)
        return _workspace_from_row(row, as_of=saved_at)

    def set_timer(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        running: bool,
        changed_at: datetime,
    ) -> ReviewWorkspace:
        reviewer_id = _required_text(reviewer_id, "reviewer_id")
        timestamp = _utc_text(changed_at)
        with self.store.immediate_transaction() as connection:
            self._ensure_workspace(
                connection,
                record_id=record_id,
                reviewer_id=reviewer_id,
                timestamp=timestamp,
            )
            if running:
                self._pause_other_timers(
                    connection,
                    reviewer_id=reviewer_id,
                    except_record_id=record_id,
                    paused_at=changed_at,
                )
                connection.execute(
                    """
                    UPDATE review_workspaces SET timer_started_at = coalesce(timer_started_at, ?),
                        updated_at = ?
                    WHERE run_id = ? AND record_id = ?
                    """,
                    (timestamp, timestamp, self.store.run_id(connection), record_id),
                )
            else:
                self._pause_timer(connection, record_id=record_id, paused_at=changed_at)
            row = self._workspace_row(connection, record_id)
        return _workspace_from_row(row, as_of=changed_at)

    def set_elapsed_time(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        seconds: int,
        running: bool,
        changed_at: datetime,
    ) -> ReviewWorkspace:
        """Set an exact elapsed time while preserving an explicitly chosen timer state."""

        if seconds < 0:
            raise ValueError("Review time cannot be negative.")
        reviewer_id = _required_text(reviewer_id, "reviewer_id")
        timestamp = _utc_text(changed_at)
        with self.store.immediate_transaction() as connection:
            self._ensure_workspace(
                connection,
                record_id=record_id,
                reviewer_id=reviewer_id,
                timestamp=timestamp,
            )
            self._pause_timer(connection, record_id=record_id, paused_at=changed_at)
            if running:
                self._pause_other_timers(
                    connection,
                    reviewer_id=reviewer_id,
                    except_record_id=record_id,
                    paused_at=changed_at,
                )
            connection.execute(
                """
                UPDATE review_workspaces
                SET review_seconds = ?, timer_started_at = ?, updated_at = ?
                WHERE run_id = ? AND record_id = ?
                """,
                (
                    seconds,
                    timestamp if running else None,
                    timestamp,
                    self.store.run_id(connection),
                    record_id,
                ),
            )
            row = self._workspace_row(connection, record_id)
        return _workspace_from_row(row, as_of=changed_at)

    def finish_workspace(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        finished_at: datetime,
    ) -> ReviewWorkspace:
        reviewer_id = _required_text(reviewer_id, "reviewer_id")
        with self.store.immediate_transaction() as connection:
            self._ensure_workspace(
                connection,
                record_id=record_id,
                reviewer_id=reviewer_id,
                timestamp=_utc_text(finished_at),
            )
            self._pause_timer(connection, record_id=record_id, paused_at=finished_at)
            row = self._workspace_row(connection, record_id)
        return _workspace_from_row(row, as_of=finished_at)

    def _ensure_workspace(
        self,
        connection: sqlite3.Connection,
        *,
        record_id: str,
        reviewer_id: str,
        timestamp: str,
    ) -> None:
        run_id = self.store.run_id(connection)
        revision = self.current_basis_plan_revision(record_id, connection=connection)
        row = connection.execute(
            """
            SELECT basis_plan_revision FROM review_workspaces
            WHERE run_id = ? AND record_id = ?
            """,
            (run_id, record_id),
        ).fetchone()
        if row is not None and int(row[0]) != revision:
            connection.execute(
                "DELETE FROM review_workspaces WHERE run_id = ? AND record_id = ?",
                (run_id, record_id),
            )
            row = None
        if row is None:
            connection.execute(
                """
                INSERT INTO review_workspaces(
                    run_id, record_id, reviewer_id, basis_plan_revision, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, record_id, reviewer_id, revision, timestamp),
            )

    def _workspace_row(
        self,
        connection: sqlite3.Connection,
        record_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM review_workspaces WHERE run_id = ? AND record_id = ?
            """,
            (self.store.run_id(connection), record_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown review workspace: {record_id}")
        return cast(sqlite3.Row, row)

    def _pause_other_timers(
        self,
        connection: sqlite3.Connection,
        *,
        reviewer_id: str,
        except_record_id: str,
        paused_at: datetime,
    ) -> None:
        rows = connection.execute(
            """
            SELECT record_id FROM review_workspaces
            WHERE run_id = ? AND reviewer_id = ? AND timer_started_at IS NOT NULL
              AND record_id != ?
            """,
            (self.store.run_id(connection), reviewer_id, except_record_id),
        ).fetchall()
        for row in rows:
            self._pause_timer(
                connection,
                record_id=str(row[0]),
                paused_at=paused_at,
            )

    def _pause_timer(
        self,
        connection: sqlite3.Connection,
        *,
        record_id: str,
        paused_at: datetime,
    ) -> None:
        row = self._workspace_row(connection, record_id)
        started = row["timer_started_at"]
        if started is None:
            return
        elapsed = max(0, int((paused_at - datetime.fromisoformat(str(started))).total_seconds()))
        timestamp = _utc_text(paused_at)
        connection.execute(
            """
            UPDATE review_workspaces
            SET review_seconds = review_seconds + ?, timer_started_at = NULL, updated_at = ?
            WHERE run_id = ? AND record_id = ?
            """,
            (elapsed, timestamp, self.store.run_id(connection), record_id),
        )

    def save_decision(
        self,
        decision: ReviewDecision,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        if connection is None:
            with self.store.connection() as owned_connection:
                self.save_decision(decision, connection=owned_connection)
            return
        run_id = self.store.run_id(connection)
        timestamp = _utc_text(decision.decided_at)
        reviewer = _required_text(decision.reviewer_id or "", "reviewer_id")
        plan = connection.execute(
            """
            SELECT purpose, status FROM transformation_plans
            WHERE run_id = ? AND record_id = ? AND plan_revision = ?
            """,
            (run_id, decision.record_id, decision.basis_plan_revision),
        ).fetchone()
        if plan is None:
            raise ValueError("Review decision references an unknown transformation plan.")
        current_decision = connection.execute(
            """
            SELECT basis_plan_revision FROM review_decisions
            WHERE run_id = ? AND record_id = ? AND is_current = 1 AND is_stale = 0
            """,
            (run_id, decision.record_id),
        ).fetchone()
        can_edit_prior_decision = (
            current_decision is not None
            and int(current_decision["basis_plan_revision"]) == decision.basis_plan_revision
        )
        if str(plan["purpose"]) != "draft" or (
            str(plan["status"]) != "active"
            and decision.disposition != "corrected"
            and not can_edit_prior_decision
        ):
            raise ValueError("Review decision must reference the active draft plan.")
        connection.execute(
            """
            UPDATE review_decisions SET is_current = 0
            WHERE run_id = ? AND record_id = ? AND is_current = 1
            """,
            (run_id, decision.record_id),
        )
        for review in decision.validation_finding_reviews:
            finding = connection.execute(
                """
                SELECT 1
                FROM validation_findings
                JOIN validation_results USING (validation_id)
                JOIN renderings
                  ON renderings.rendering_id = validation_results.rendering_id
                WHERE validation_findings.run_id = ?
                  AND validation_findings.record_id = ?
                  AND validation_finding_id = ?
                  AND renderings.plan_revision = ?
                  AND (
                    validation_results.is_stale = 0
                    OR NOT EXISTS (
                      SELECT 1 FROM validation_results AS current_validation
                      WHERE current_validation.run_id = validation_results.run_id
                        AND current_validation.record_id = validation_results.record_id
                        AND current_validation.is_stale = 0
                    )
                  )
                """,
                (
                    run_id,
                    decision.record_id,
                    review.validation_finding_id,
                    decision.basis_plan_revision,
                ),
            ).fetchone()
            if finding is None:
                raise ValueError(
                    "Validation finding review does not reference a finding from the "
                    "current reviewed draft."
                )
        validation_reviews = [
            review.model_copy(update={"reviewer_id": review.reviewer_id or reviewer}).model_dump(
                mode="json"
            )
            for review in decision.validation_finding_reviews
        ]
        connection.execute(
            """
            INSERT INTO review_decisions(
                decision_id, run_id, record_id, basis_plan_revision,
                disposition, reviewer_id, review_seconds, span_events_json,
                structured_events_json, validation_reviews_json, record_comment,
                is_current, is_stale, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
            """,
            (
                decision.decision_id,
                run_id,
                decision.record_id,
                decision.basis_plan_revision,
                decision.disposition,
                decision.reviewer_id,
                decision.review_seconds,
                _json([event.model_dump(mode="json") for event in decision.span_events]),
                _json([event.model_dump(mode="json") for event in decision.structured_events]),
                _json(validation_reviews),
                decision.record_comment,
                timestamp,
            ),
        )


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Review timestamps must include timezone information.")
    return value.astimezone(UTC).isoformat()


def _required_text(value: str, field_name: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{field_name} cannot be blank.")
    return value


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _workspace_from_row(row: sqlite3.Row, *, as_of: datetime) -> ReviewWorkspace:
    elapsed = int(row["review_seconds"])
    started = row["timer_started_at"]
    if started is not None:
        elapsed += max(0, int((as_of - datetime.fromisoformat(str(started))).total_seconds()))
    return ReviewWorkspace.model_validate(
        {
            "record_id": row["record_id"],
            "reviewer_id": row["reviewer_id"],
            "basis_plan_revision": row["basis_plan_revision"],
            "span_events": json.loads(str(row["span_events_json"])),
            "structured_events": json.loads(str(row["structured_events_json"])),
            "validation_finding_reviews": json.loads(str(row["validation_reviews_json"])),
            "record_comment": row["record_comment"],
            "review_seconds": elapsed,
            "timer_started_at": started,
            "updated_at": row["updated_at"],
        }
    )
