from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from typing import Literal

from health_deid.core.dates import DateShift
from health_deid.core.ids import build_content_id
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.ledger import RenderedText, Rendering, SpanGroup, TransformEvent
from health_deid.models.policy import SurrogateRequest, SurrogateResult
from health_deid.storage.database import SqliteRunStore


class TransformationRepository:
    def __init__(self, store: SqliteRunStore) -> None:
        self.store = store

    def save_resolution(
        self,
        *,
        record_id: str,
        findings_sha256: str,
        resolver_version: str,
        groups: list[SpanGroup],
        reason: str,
        created_at: datetime,
        connection: sqlite3.Connection | None = None,
    ) -> int:
        if connection is None:
            with self.store.connection() as owned_connection:
                return self.save_resolution(
                    record_id=record_id,
                    findings_sha256=findings_sha256,
                    resolver_version=resolver_version,
                    groups=groups,
                    reason=reason,
                    created_at=created_at,
                    connection=owned_connection,
                )
        run_id = self.store.run_id(connection)
        timestamp = _utc_text(created_at)
        current = connection.execute(
            """
            SELECT revision, findings_sha256, resolver_version FROM resolution_revisions
            WHERE run_id = ? AND record_id = ? AND is_active = 1
            """,
            (run_id, record_id),
        ).fetchone()
        if (
            current is not None
            and str(current["findings_sha256"]) == findings_sha256
            and str(current["resolver_version"]) == resolver_version
        ):
            return int(current["revision"])
        revision = int(
            connection.execute(
                """
                SELECT coalesce(max(revision), 0) + 1 FROM resolution_revisions
                WHERE run_id = ? AND record_id = ?
                """,
                (run_id, record_id),
            ).fetchone()[0]
        )
        connection.execute(
            """
            UPDATE resolution_revisions SET is_active = 0
            WHERE run_id = ? AND record_id = ? AND is_active = 1
            """,
            (run_id, record_id),
        )
        _stale_record_dependencies(
            connection, run_id=run_id, record_id=record_id, timestamp=timestamp, reason=reason
        )
        connection.execute(
            """
            INSERT INTO resolution_revisions(
                run_id, record_id, revision, resolver_version, findings_sha256,
                is_active, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (run_id, record_id, revision, resolver_version, findings_sha256, reason, timestamp),
        )
        for group in groups:
            connection.execute(
                """
                INSERT INTO span_groups(
                    run_id, record_id, resolution_revision, group_id,
                    canonical_category, start_char, end_char, finding_ids_json,
                    resolution_status, resolution_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    record_id,
                    revision,
                    group.group_id,
                    group.category.value,
                    group.start_char,
                    group.end_char,
                    json.dumps(group.finding_ids),
                    group.resolution_status,
                    reason,
                ),
            )
        return revision

    def active_resolution(self, record_id: str) -> tuple[int, list[SpanGroup]]:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            revision_row = connection.execute(
                """
                SELECT revision FROM resolution_revisions
                WHERE run_id = ? AND record_id = ? AND is_active = 1
                """,
                (run_id, record_id),
            ).fetchone()
            if revision_row is None:
                raise KeyError(f"Record {record_id!r} has no active resolution.")
            revision = int(revision_row[0])
            rows = connection.execute(
                """
                SELECT *
                FROM span_groups
                WHERE run_id = ? AND record_id = ? AND resolution_revision = ?
                ORDER BY start_char, end_char, group_id
                """,
                (run_id, record_id, revision),
            ).fetchall()
        return revision, [
            SpanGroup(
                group_id=str(row["group_id"]),
                record_id=record_id,
                category=PhiCategory(str(row["canonical_category"])),
                start_char=int(row["start_char"]),
                end_char=int(row["end_char"]),
                finding_ids=json.loads(str(row["finding_ids_json"])),
                resolution_status=str(row["resolution_status"]),  # type: ignore[arg-type]
            )
            for row in rows
        ]

    def next_plan_revision(self, record_id: str) -> int:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            return int(
                connection.execute(
                    """
                    SELECT coalesce(max(plan_revision), 0) + 1 FROM transformation_plans
                    WHERE run_id = ? AND record_id = ?
                    """,
                    (run_id, record_id),
                ).fetchone()[0]
            )

    def save_plan(
        self,
        *,
        record_id: str,
        plan_revision: int,
        resolution_revision: int,
        policy_revision: int,
        purpose: Literal["draft", "final"],
        events: list[TransformEvent],
        created_at: datetime,
    ) -> None:
        run_id = self.store.run_id()
        timestamp = _utc_text(created_at)
        with self.store.connection() as connection:
            _stale_superseded_plan_outputs(
                connection,
                run_id=run_id,
                record_id=record_id,
                purpose=purpose,
                reason="superseded plan",
            )
            connection.execute(
                """
                UPDATE transformation_plans
                SET status = 'stale', stale_at = ?, stale_reason = 'superseded plan'
                WHERE run_id = ? AND record_id = ? AND purpose = ? AND status = 'active'
                """,
                (timestamp, run_id, record_id, purpose),
            )
            connection.execute(
                """
                INSERT INTO transformation_plans(
                    run_id, record_id, plan_revision, resolution_revision,
                    policy_revision, purpose, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    run_id,
                    record_id,
                    plan_revision,
                    resolution_revision,
                    policy_revision,
                    purpose,
                    timestamp,
                ),
            )
            for event in events:
                connection.execute(
                    """
                    INSERT INTO transform_events(
                        event_id, run_id, record_id, plan_revision, group_id,
                        action, strategy, canonical_category, original_text,
                        replacement_text, input_start_char, input_end_char,
                        surrogate_assignment_id, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        run_id,
                        record_id,
                        plan_revision,
                        event.group_id,
                        event.action.value,
                        event.strategy,
                        event.category.value,
                        event.original_text,
                        event.replacement_text,
                        event.input_start_char,
                        event.input_end_char,
                        event.surrogate_assignment_id,
                        event.status,
                        timestamp,
                    ),
                )

    def plan_events(
        self,
        record_id: str,
        *,
        purpose: Literal["draft", "final"],
    ) -> tuple[int, list[TransformEvent]]:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            plan = connection.execute(
                """
                SELECT plan_revision FROM transformation_plans
                WHERE run_id = ? AND record_id = ? AND purpose = ? AND status = 'active'
                """,
                (run_id, record_id, purpose),
            ).fetchone()
            if plan is None:
                raise KeyError(f"Record {record_id!r} has no active {purpose} plan.")
            revision = int(plan[0])
            rows = connection.execute(
                """
                SELECT * FROM transform_events
                WHERE run_id = ? AND record_id = ? AND plan_revision = ?
                ORDER BY input_start_char, input_end_char
                """,
                (run_id, record_id, revision),
            ).fetchall()
        return revision, [_event_from_row(row) for row in rows]

    def save_rendering(
        self,
        *,
        record_id: str,
        plan_revision: int,
        kind: Literal["preview", "draft", "final"],
        rendered: RenderedText,
        created_at: datetime,
    ) -> Rendering:
        run_id = self.store.run_id()
        timestamp = _utc_text(created_at)
        digest = hashlib.sha256(rendered.text.encode("utf-8")).hexdigest()
        rendering_id = build_content_id("rendering", run_id, record_id, plan_revision, kind, digest)
        with self.store.connection() as connection:
            connection.execute(
                """
                UPDATE renderings SET is_stale = 1
                WHERE run_id = ? AND record_id = ? AND kind = ? AND is_stale = 0
                """,
                (run_id, record_id, kind),
            )
            connection.execute(
                """
                INSERT INTO renderings(
                    rendering_id, run_id, record_id, plan_revision, kind,
                    rendered_text, text_sha256, events_json, is_stale, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    rendering_id,
                    run_id,
                    record_id,
                    plan_revision,
                    kind,
                    rendered.text,
                    digest,
                    json.dumps(
                        [event.model_dump(mode="json") for event in rendered.events],
                        ensure_ascii=False,
                    ),
                    timestamp,
                ),
            )
            connection.execute(
                """
                UPDATE transform_events SET status = 'rendered'
                WHERE run_id = ? AND record_id = ? AND plan_revision = ?
                """,
                (run_id, record_id, plan_revision),
            )
        return Rendering(
            rendering_id=rendering_id,
            record_id=record_id,
            plan_revision=plan_revision,
            kind=kind,
            rendered_text=rendered.text,
            text_sha256=digest,
            created_at=created_at,
        )

    def current_rendering(
        self,
        record_id: str,
        kind: Literal["preview", "draft", "final"],
    ) -> Rendering:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM renderings
                WHERE run_id = ? AND record_id = ? AND kind = ? AND is_stale = 0
                """,
                (run_id, record_id, kind),
            ).fetchone()
        if row is None:
            raise KeyError(f"Record {record_id!r} has no current {kind} rendering.")
        return Rendering(
            rendering_id=str(row["rendering_id"]),
            record_id=record_id,
            plan_revision=int(row["plan_revision"]),
            kind=kind,
            rendered_text=str(row["rendered_text"]),
            text_sha256=str(row["text_sha256"]),
            is_stale=bool(row["is_stale"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
        )

    def get_date_shift(
        self,
        *,
        entity_id: str,
        policy_revision: int,
    ) -> DateShift | None:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            row = connection.execute(
                """
                SELECT shift_weeks, algorithm_version FROM surrogate_assignments
                WHERE run_id = ? AND assignment_kind = 'date_shift'
                  AND entity_id = ? AND policy_revision = ?
                """,
                (run_id, entity_id, policy_revision),
            ).fetchone()
        if row is None:
            return None
        return DateShift(
            weeks=int(row["shift_weeks"]), algorithm_version=str(row["algorithm_version"])
        )

    def save_date_shift(
        self,
        *,
        entity_id: str,
        policy_revision: int,
        secret_reference: str,
        shift: DateShift,
        created_at: datetime,
    ) -> DateShift:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            connection.execute(
                """
                INSERT INTO surrogate_assignments(
                    assignment_id, run_id, assignment_kind, method, canonical_category,
                    consistency_scope, scope_key_hmac, surrogate_value, entity_id,
                    policy_revision, secret_reference, algorithm_version, shift_weeks, created_at
                ) VALUES (?, ?, 'date_shift', 'date_shift', 'DATE', 'entity', ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    build_content_id("date-shift", run_id, entity_id, policy_revision),
                    run_id,
                    hashlib.sha256(
                        f"{run_id}\0{entity_id}\0{policy_revision}".encode()
                    ).hexdigest(),
                    str(shift.weeks),
                    entity_id,
                    policy_revision,
                    secret_reference,
                    shift.algorithm_version,
                    shift.weeks,
                    _utc_text(created_at),
                ),
            )
        saved = self.get_date_shift(entity_id=entity_id, policy_revision=policy_revision)
        assert saved is not None
        if saved != shift:
            raise ValueError("An entity date shift was already materialized differently.")
        return saved

    def save_surrogate_assignment(
        self,
        *,
        request: SurrogateRequest,
        result: SurrogateResult,
        created_at: datetime,
    ) -> SurrogateResult:
        if result.category is not request.category:
            raise ValueError("Surrogate result does not match its request.")
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            existing = connection.execute(
                """
                SELECT * FROM surrogate_assignments
                WHERE run_id = ? AND assignment_kind = 'synthetic'
                  AND method = ? AND canonical_category = ? AND scope_key_hmac = ?
                """,
                (run_id, result.method, request.category.value, result.scope_key_hmac),
            ).fetchone()
            if existing is not None:
                return result.model_copy(
                    update={
                        "assignment_id": existing["assignment_id"],
                        "candidates": (str(existing["surrogate_value"]),),
                        "pool_sha256": existing["pool_sha256"],
                    }
                )
            used_values = {
                str(row[0])
                for row in connection.execute(
                    """
                SELECT surrogate_value FROM surrogate_assignments
                WHERE run_id = ? AND assignment_kind = 'synthetic'
                  AND method = ? AND canonical_category = ? AND container_key_hmac = ?
                """,
                    (
                        run_id,
                        result.method,
                        request.category.value,
                        result.container_key_hmac,
                    ),
                ).fetchall()
            }
            selected = next(
                (value for value in result.candidates if value not in used_values), None
            )
            if selected is None:
                if result.method == "custom_list":
                    raise ValueError(
                        f"The custom replacement list for {request.category.value} is too small "
                        "for the selected consistency mode. Add more unique values."
                    )
                raise ValueError(
                    f"Faker could not produce another unique {request.category.value} value."
                )
            result = result.model_copy(update={"candidates": (selected,)})
            connection.execute(
                """
                INSERT INTO surrogate_assignments(
                    assignment_id, run_id, assignment_kind, method, pool_sha256,
                    canonical_category, consistency_scope, container_key_hmac,
                    scope_key_hmac, surrogate_value, created_at
                ) VALUES (?, ?, 'synthetic', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.assignment_id,
                    run_id,
                    result.method,
                    result.pool_sha256,
                    request.category.value,
                    result.consistency.value,
                    result.container_key_hmac,
                    result.scope_key_hmac,
                    result.surrogate_text,
                    _utc_text(created_at),
                ),
            )
        return result

    def save_structured_event(
        self,
        *,
        record_id: str,
        plan_revision: int,
        policy_revision: int,
        purpose: Literal["draft", "final"],
        column_name: str,
        category: PhiCategory,
        action: str,
        original_value: object,
        replacement_value: object,
        surrogate_assignment_id: str | None = None,
        created_at: datetime,
    ) -> None:
        run_id = self.store.run_id()
        event_id = build_content_id(
            "structured-event", run_id, record_id, plan_revision, purpose, column_name
        )
        with self.store.connection() as connection:
            connection.execute(
                """
                INSERT INTO structured_transform_events(
                    structured_event_id, run_id, record_id, plan_revision, policy_revision,
                    purpose, column_name, canonical_category, action, original_value_json,
                    replacement_value_json, surrogate_assignment_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(structured_event_id) DO NOTHING
                """,
                (
                    event_id,
                    run_id,
                    record_id,
                    plan_revision,
                    policy_revision,
                    purpose,
                    column_name,
                    category.value,
                    action,
                    json.dumps(original_value, ensure_ascii=False, default=str),
                    json.dumps(replacement_value, ensure_ascii=False, default=str),
                    surrogate_assignment_id,
                    _utc_text(created_at),
                ),
            )

    def structured_events(
        self,
        record_id: str,
        *,
        purpose: Literal["draft", "final"],
    ) -> list[dict[str, object]]:
        run_id = self.store.run_id()
        with self.store.read_snapshot() as connection:
            rows = connection.execute(
                """
                SELECT structured_transform_events.*
                FROM structured_transform_events
                JOIN transformation_plans USING (run_id, record_id, plan_revision)
                WHERE structured_transform_events.run_id = ?
                  AND structured_transform_events.record_id = ?
                  AND structured_transform_events.purpose = ?
                  AND transformation_plans.status = 'active'
                ORDER BY structured_transform_events.column_name,
                         structured_transform_events.structured_event_id
                """,
                (run_id, record_id, purpose),
            ).fetchall()
        return [
            {
                **dict(row),
                "original_value": json.loads(str(row["original_value_json"])),
                "replacement_value": json.loads(str(row["replacement_value_json"])),
            }
            for row in rows
        ]


def _event_from_row(row: sqlite3.Row) -> TransformEvent:
    return TransformEvent(
        event_id=str(row["event_id"]),
        record_id=str(row["record_id"]),
        group_id=str(row["group_id"]),
        plan_revision=int(row["plan_revision"]),
        action=str(row["action"]),  # type: ignore[arg-type]
        strategy=row["strategy"],
        category=PhiCategory(str(row["canonical_category"])),
        original_text=str(row["original_text"]),
        replacement_text=row["replacement_text"],
        input_start_char=int(row["input_start_char"]),
        input_end_char=int(row["input_end_char"]),
        surrogate_assignment_id=row["surrogate_assignment_id"],
        status=str(row["status"]),  # type: ignore[arg-type]
    )


def _stale_record_dependencies(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    record_id: str,
    timestamp: str,
    reason: str,
) -> None:
    connection.execute(
        """
        UPDATE transformation_plans SET status = 'stale', stale_at = ?, stale_reason = ?
        WHERE run_id = ? AND record_id = ? AND status = 'active'
        """,
        (timestamp, reason, run_id, record_id),
    )
    connection.execute(
        "UPDATE renderings SET is_stale = 1 WHERE run_id = ? AND record_id = ? AND is_stale = 0",
        (run_id, record_id),
    )
    connection.execute(
        """
        UPDATE validation_results SET is_stale = 1
        WHERE run_id = ? AND record_id = ? AND is_stale = 0
        """,
        (run_id, record_id),
    )
    connection.execute(
        """
        UPDATE review_decisions SET is_stale = 1, stale_reason = ?, is_current = 0
        WHERE run_id = ? AND record_id = ? AND is_current = 1
        """,
        (reason, run_id, record_id),
    )


def _stale_superseded_plan_outputs(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    record_id: str,
    purpose: Literal["draft", "final"],
    reason: str,
) -> None:
    """Invalidate outputs that were derived from the plan being superseded."""

    rendering_kind = "draft" if purpose == "draft" else "final"
    connection.execute(
        """
        UPDATE renderings SET is_stale = 1
        WHERE run_id = ? AND record_id = ? AND kind = ? AND is_stale = 0
        """,
        (run_id, record_id, rendering_kind),
    )
    if purpose != "draft":
        return
    connection.execute(
        """
        UPDATE validation_results SET is_stale = 1
        WHERE run_id = ? AND record_id = ? AND is_stale = 0
        """,
        (run_id, record_id),
    )
    connection.execute(
        """
        UPDATE review_decisions
        SET is_stale = 1, stale_reason = ?, is_current = 0
        WHERE run_id = ? AND record_id = ? AND is_current = 1
        """,
        (reason, run_id, record_id),
    )


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Timestamps must include timezone information.")
    return value.astimezone(UTC).isoformat()
