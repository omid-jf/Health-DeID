from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from health_deid.backends.surrogates import generate_surrogate
from health_deid.core.dates import DateShift, derive_date_shift, shift_date_text
from health_deid.core.ids import build_content_id
from health_deid.core.resolution import RESOLVER_VERSION, resolve_findings
from health_deid.core.secret_refs import SecretResolver
from health_deid.core.taxonomy import PhiCategory
from health_deid.core.transformations import compile_transform_events, render_events
from health_deid.models.backend import DetectionCandidate
from health_deid.models.ledger import Finding, RecordStageStatus, SpanGroup
from health_deid.models.policy import (
    CustomListSurrogate,
    DateShiftSurrogate,
    FakerSurrogate,
    SurrogateRequest,
)
from health_deid.models.review import (
    ReviewDecision,
    ReviewSpanEvent,
    ReviewStructuredEvent,
    ReviewWorkspace,
    ValidationFindingReview,
)
from health_deid.storage.database import SqliteRunStore
from health_deid.storage.findings import FindingRepository
from health_deid.storage.reviews import ReviewRepository
from health_deid.storage.transformations import TransformationRepository


@dataclass(frozen=True, slots=True)
class ReviewRecord:
    record_id: str
    entity_id: str
    normalized_text: str
    pipeline_text: str
    plan_revision: int
    findings: list[Finding]
    span_groups: list[SpanGroup]
    validation_findings: list[dict[str, object]]
    structured_fields: list[dict[str, object]]


class ReviewService:
    def __init__(
        self,
        store: SqliteRunStore,
        *,
        secrets: SecretResolver | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.findings = FindingRepository(store)
        self.transformations = TransformationRepository(store)
        self.reviews = ReviewRepository(store)
        self.secrets = secrets
        self.clock = clock or (lambda: datetime.now(UTC))

    def queue(self) -> list[str]:
        return self.reviews.queue()

    def queue_summary(self) -> dict[str, object]:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT records.record_id, records.entity_id, records.source_index,
                           records.status, record_stage_states.status AS review_status,
                           review_decisions.disposition,
                           coalesce(review_decisions.review_seconds,
                                    review_workspaces.review_seconds, 0) AS review_seconds
                    FROM records
                    JOIN record_stage_states USING (run_id, record_id)
                    LEFT JOIN review_decisions
                      ON review_decisions.run_id = records.run_id
                     AND review_decisions.record_id = records.record_id
                     AND review_decisions.is_current = 1 AND review_decisions.is_stale = 0
                    LEFT JOIN review_workspaces
                      ON review_workspaces.run_id = records.run_id
                     AND review_workspaces.record_id = records.record_id
                    WHERE records.run_id = ? AND record_stage_states.stage_name = 'review'
                      AND (
                        record_stage_states.status = 'review_pending'
                        OR review_decisions.decision_id IS NOT NULL
                      )
                    ORDER BY records.source_index
                    """,
                    (run_id,),
                )
            ]
        pending = sum(item["review_status"] == "review_pending" for item in rows)
        reviewed = len(rows) - pending
        total_seconds = sum(int(item["review_seconds"]) for item in rows)
        return {
            "items": rows,
            "total": len(rows),
            "pending": pending,
            "reviewed": reviewed,
            "total_seconds": total_seconds,
            "average_seconds": round(total_seconds / reviewed, 1) if reviewed else 0.0,
        }

    def open_workspace(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        opened_at: datetime | None = None,
        start_timer: bool = True,
    ) -> ReviewWorkspace:
        return self.reviews.open_workspace(
            record_id,
            reviewer_id,
            opened_at=opened_at or datetime.now(UTC),
            start_timer=start_timer,
        )

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
        saved_at: datetime | None = None,
    ) -> ReviewWorkspace:
        return self.reviews.save_workspace(
            record_id=record_id,
            reviewer_id=reviewer_id,
            basis_plan_revision=basis_plan_revision,
            span_events=span_events,
            structured_events=structured_events,
            validation_finding_reviews=validation_finding_reviews,
            record_comment=record_comment,
            saved_at=saved_at or datetime.now(UTC),
        )

    def set_timer(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        running: bool,
        changed_at: datetime | None = None,
    ) -> ReviewWorkspace:
        return self.reviews.set_timer(
            record_id,
            reviewer_id,
            running=running,
            changed_at=changed_at or datetime.now(UTC),
        )

    def set_elapsed_time(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        seconds: int,
        running: bool,
        changed_at: datetime | None = None,
    ) -> ReviewWorkspace:
        return self.reviews.set_elapsed_time(
            record_id,
            reviewer_id,
            seconds=seconds,
            running=running,
            changed_at=changed_at or datetime.now(UTC),
        )

    def finish_workspace(
        self,
        record_id: str,
        reviewer_id: str,
        *,
        finished_at: datetime | None = None,
    ) -> ReviewWorkspace:
        return self.reviews.finish_workspace(
            record_id,
            reviewer_id,
            finished_at=finished_at or datetime.now(UTC),
        )

    def record(self, record_id: str) -> ReviewRecord:
        with self.store.connection() as connection:
            return self._record(record_id, connection=connection)

    def preview(
        self,
        record_id: str,
        span_events: list[ReviewSpanEvent],
        *,
        reviewer_id: str,
    ) -> str:
        """Render draft review edits with the run's real transformation settings."""

        current = self.record(record_id)
        resolved = resolve_findings(
            current.normalized_text,
            self._preview_findings(current, span_events, reviewer_id=reviewer_id),
            record_id=record_id,
        )
        policy_revision, policy = self.store.read_active_policy()
        now = self.clock()

        def surrogate_value(group: SpanGroup, original: str) -> str:
            if self.secrets is None:
                raise ValueError("Review preview requires configured surrogate secrets.")
            category_policy = policy.categories[group.category]
            replacement = category_policy.surrogate
            assert isinstance(replacement, (FakerSurrogate, CustomListSurrogate))
            request = SurrogateRequest(
                event_id=group.group_id,
                record_id=record_id,
                entity_id=current.entity_id,
                category=group.category,
                original_text=original,
            )
            generated = generate_surrogate(
                request,
                replacement,
                secrets=self.secrets,
            )
            saved = self.transformations.save_surrogate_assignment(
                request=request,
                result=generated,
                created_at=now,
            )
            return saved.surrogate_text

        shift = self._preview_date_shift(
            entity_id=current.entity_id,
            policy_revision=policy_revision,
            created_at=now,
        )

        def date_value(group: SpanGroup, original: str) -> str:
            del group
            replacement = policy.categories[PhiCategory.DATE].surrogate
            assert shift is not None and isinstance(replacement, DateShiftSurrogate)
            return shift_date_text(
                original,
                shift=shift,
                fallback=replacement.fallback,
            )

        events = compile_transform_events(
            current.normalized_text,
            resolved.groups,
            record_id=record_id,
            plan_revision=current.plan_revision,
            policy=policy,
            purpose="final",
            surrogate_provider=surrogate_value,
            date_shift_provider=date_value if shift is not None else None,
        )
        rendered = render_events(
            current.normalized_text,
            events,
            rendering_id=build_content_id(
                "review-preview", self.store.run_id(), record_id, reviewer_id
            ),
        )
        return rendered.text

    def preview_structured(
        self,
        record_id: str,
        structured_events: list[ReviewStructuredEvent],
    ) -> dict[str, Any]:
        current = self.record(record_id)
        fields = {str(item["column_name"]): item for item in current.structured_fields}
        output = {column: item["deidentified_value"] for column, item in fields.items()}
        seen: set[str] = set()
        for event in structured_events:
            if event.column_name in seen:
                raise ValueError(
                    f"Only one structured-field change is allowed for {event.column_name!r}."
                )
            seen.add(event.column_name)
            field = fields.get(event.column_name)
            if field is None:
                raise ValueError(f"Unknown structured PHI field: {event.column_name}")
            if field["category"] != event.category.value:
                raise ValueError(
                    f"Structured PHI category changed for {event.column_name!r}; reload the record."
                )
            if field["original_value"] != event.original_value:
                raise ValueError(
                    f"Original structured value changed for {event.column_name!r}; reload the record."
                )
            output[event.column_name] = event.replacement_value
        return output

    def _preview_findings(
        self,
        current: ReviewRecord,
        span_events: list[ReviewSpanEvent],
        *,
        reviewer_id: str,
    ) -> list[Finding]:
        removed = {
            finding_id
            for event in span_events
            if event.operation in {"remove", "modify"}
            for finding_id in event.finding_ids
        }
        self._validate_group_references(current, span_events)
        known = {finding.finding_id for finding in current.findings}
        unknown = removed.difference(known)
        if unknown:
            raise ValueError("Review removes unknown PHI IDs: " + ", ".join(sorted(unknown)))
        effective = [finding for finding in current.findings if finding.finding_id not in removed]
        created_at = self.clock()
        run_id = self.store.run_id()
        for event in span_events:
            if event.operation not in {"add", "modify"}:
                continue
            assert (
                event.category is not None
                and event.text is not None
                and event.start_char is not None
                and event.end_char is not None
            )
            if (
                event.end_char > len(current.normalized_text)
                or current.normalized_text[event.start_char : event.end_char] != event.text
            ):
                raise ValueError("Review span text does not match normalized-source offsets.")
            effective.append(
                Finding(
                    finding_id=build_content_id(
                        "finding",
                        run_id,
                        current.record_id,
                        "review",
                        reviewer_id,
                        event.start_char,
                        event.end_char,
                        event.category.value,
                        event.text,
                    ),
                    record_id=current.record_id,
                    source_kind="review",
                    source_name=reviewer_id,
                    backend_type="MANUAL",
                    category=event.category,
                    detector_subtype="manual",
                    exact_text=event.text,
                    start_char=event.start_char,
                    end_char=event.end_char,
                    created_at=created_at,
                )
            )
        return effective

    @staticmethod
    def _validate_group_references(
        current: ReviewRecord,
        span_events: list[ReviewSpanEvent],
    ) -> None:
        groups = {group.group_id: group for group in current.span_groups}
        for event in span_events:
            if event.operation not in {"remove", "modify"}:
                continue
            assert event.group_id is not None
            group = groups.get(event.group_id)
            if group is None:
                raise ValueError(f"Review references unknown displayed PHI group: {event.group_id}")
            if set(group.finding_ids) != set(event.finding_ids):
                raise ValueError(
                    "The displayed PHI group changed; reload the record before saving."
                )

    def _preview_date_shift(
        self,
        *,
        entity_id: str,
        policy_revision: int,
        created_at: datetime,
    ) -> DateShift | None:
        _, policy = self.store.read_active_policy()
        replacement = policy.categories[PhiCategory.DATE].surrogate
        if not isinstance(replacement, DateShiftSurrogate):
            return None
        if self.secrets is None:
            raise ValueError("Review preview requires the configured date-shift secret.")
        existing = self.transformations.get_date_shift(
            entity_id=entity_id,
            policy_revision=policy_revision,
        )
        if existing is not None:
            return existing
        shift = derive_date_shift(
            secret=self.secrets.resolve(replacement.secret_reference),
            entity_id=entity_id,
            policy=replacement,
        )
        return self.transformations.save_date_shift(
            entity_id=entity_id,
            policy_revision=policy_revision,
            secret_reference=replacement.secret_reference,
            shift=shift,
            created_at=created_at,
        )

    def decide(self, decision: ReviewDecision) -> None:
        with self.store.immediate_transaction() as connection:
            current = self._record(decision.record_id, connection=connection)
            if decision.basis_plan_revision != current.plan_revision:
                raise ValueError(
                    "Review is stale because the transformation plan changed; reload the record."
                )
            if decision.disposition == "corrected":
                self._apply_corrections(current, decision, connection=connection)
            self.reviews.save_decision(decision, connection=connection)
            self._apply_record_disposition(decision, connection=connection)

    def _record(
        self,
        record_id: str,
        *,
        connection: sqlite3.Connection,
    ) -> ReviewRecord:
        run_id = self.store.run_id(connection)
        row = connection.execute(
            "SELECT * FROM records WHERE run_id = ? AND record_id = ?",
            (run_id, record_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown record_id: {record_id}")
        plan_revision = self.reviews.current_basis_plan_revision(record_id, connection=connection)
        validation_rows = connection.execute(
            """
            SELECT validation_findings.* FROM validation_findings
            JOIN validation_results USING (validation_id)
            WHERE validation_results.run_id = ? AND validation_results.record_id = ?
              AND validation_results.is_stale = 0
            ORDER BY validation_finding_id
            """,
            (run_id, record_id),
        ).fetchall()
        rendering = connection.execute(
            """
            SELECT rendered_text FROM renderings
            WHERE run_id = ? AND record_id = ? AND kind = 'draft'
            ORDER BY is_stale, created_at DESC LIMIT 1
            """,
            (run_id, record_id),
        ).fetchone()
        if rendering is None:
            raise KeyError(f"Record {record_id!r} has no current pipeline rendering.")
        _, span_groups = self.transformations.active_resolution(record_id)
        original_metadata = json.loads(str(row["metadata_json"]))
        draft_metadata = (
            json.loads(str(row["draft_metadata_json"]))
            if row["draft_metadata_json"] is not None
            else original_metadata
        )
        structured_events = {
            str(item["column_name"]): item
            for item in self.transformations.structured_events(record_id, purpose="draft")
        }
        mappings = self.store.read_config().input.structured_phi_columns
        return ReviewRecord(
            record_id=record_id,
            entity_id=str(row["entity_id"]),
            normalized_text=str(row["normalized_text"]),
            pipeline_text=str(rendering["rendered_text"]),
            plan_revision=plan_revision,
            findings=self.findings.list_findings(
                record_id,
                eligible_only=True,
                connection=connection,
            ),
            span_groups=span_groups,
            validation_findings=[dict(item) for item in validation_rows],
            structured_fields=[
                {
                    "column_name": column,
                    "category": category.value,
                    "action": (
                        structured_events[column]["action"]
                        if column in structured_events
                        else "retain"
                    ),
                    "original_value": original_metadata.get(column),
                    "deidentified_value": draft_metadata.get(column),
                }
                for column, category in mappings.items()
            ],
        )

    def _apply_corrections(
        self,
        current: ReviewRecord,
        decision: ReviewDecision,
        *,
        connection: sqlite3.Connection,
    ) -> None:
        source = current.normalized_text
        self._validate_group_references(current, decision.span_events)
        removed = {
            finding_id
            for event in decision.span_events
            if event.operation in {"remove", "modify"}
            for finding_id in event.finding_ids
        }
        known = {finding.finding_id for finding in current.findings}
        unknown = removed.difference(known)
        if unknown:
            raise ValueError("Review removes unknown PHI IDs: " + ", ".join(sorted(unknown)))
        self.findings.set_eligibility(
            record_id=decision.record_id,
            finding_ids=removed,
            is_eligible=False,
            reason=f"removed by review {decision.decision_id}",
            updated_at=decision.decided_at,
            connection=connection,
        )
        effective = [finding for finding in current.findings if finding.finding_id not in removed]
        reviewer = decision.reviewer_id
        for event in decision.span_events:
            if event.operation not in {"add", "modify"}:
                continue
            assert (
                event.category is not None
                and event.text is not None
                and event.start_char is not None
                and event.end_char is not None
            )
            if (
                event.end_char > len(source)
                or source[event.start_char : event.end_char] != event.text
            ):
                raise ValueError("Review span text does not match normalized-source offsets.")
            candidate = DetectionCandidate(
                backend_span_id=event.event_id,
                category=event.category,
                native_category=event.category.value,
                subtype="manual",
                text=event.text,
                start_char=event.start_char,
                end_char=event.end_char,
                native_payload={"reason_code": event.reason_code, "comment": event.comment},
            )
            effective.append(
                self.findings.insert_review_finding(
                    record_id=decision.record_id,
                    reviewer_id=reviewer,
                    candidate=candidate,
                    created_at=decision.decided_at,
                    connection=connection,
                )
            )
        resolved = resolve_findings(source, effective, record_id=decision.record_id)
        self.transformations.save_resolution(
            record_id=decision.record_id,
            findings_sha256=resolved.findings_sha256,
            resolver_version=RESOLVER_VERSION,
            groups=resolved.groups,
            reason=f"review correction {decision.decision_id}",
            created_at=decision.decided_at,
            connection=connection,
        )
        self.preview_structured(decision.record_id, decision.structured_events)

    def _apply_record_disposition(
        self,
        decision: ReviewDecision,
        *,
        connection: sqlite3.Connection,
    ) -> None:
        run_id = self.store.run_id(connection)
        timestamp = decision.decided_at.astimezone(UTC).isoformat()
        if decision.disposition == "excluded":
            record_status = "excluded"
            stage_states: dict[str, RecordStageStatus] = {
                stage: "excluded" for stage in ("review", "finalization", "export")
            }
        else:
            record_status = "reviewed"
            stage_states = {"review": "succeeded"}
        cursor = connection.execute(
            """
            UPDATE records SET status = ?, updated_at = ?
            WHERE run_id = ? AND record_id = ?
            """,
            (record_status, timestamp, run_id, decision.record_id),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"Unknown record_id: {decision.record_id}")
        for stage, status in stage_states.items():
            connection.execute(
                """
                UPDATE record_stage_states
                SET status = ?, finished_at = ?, updated_at = ?
                WHERE run_id = ? AND record_id = ? AND stage_name = ?
                """,
                (status, timestamp, timestamp, run_id, decision.record_id, stage),
            )


def build_review_decision_id(record_id: str, decided_at: datetime) -> str:
    if decided_at.tzinfo is None:
        decided_at = decided_at.replace(tzinfo=UTC)
    return build_content_id("review", record_id, decided_at.astimezone(UTC).isoformat())
