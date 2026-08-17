"""Final output materialization."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import TYPE_CHECKING, Literal, cast

from health_deid.backends.surrogates import generate_surrogate
from health_deid.core.dates import DateShift, derive_date_shift, shift_date_text
from health_deid.core.taxonomy import PhiCategory
from health_deid.core.transformations import (
    ReplacementProvider,
    compile_transform_events,
    render_events,
    transform_structured_metadata,
)
from health_deid.models.ledger import SpanGroup
from health_deid.models.policy import (
    CustomListSurrogate,
    DateShiftSurrogate,
    FakerSurrogate,
    SurrogateRequest,
    SurrogateResult,
    TransformationPolicy,
)

if TYPE_CHECKING:
    from health_deid.pipeline.engine import PipelineEngine


type StructuredEvent = tuple[str, PhiCategory, object, object]


class _FinalizationStage:
    def __init__(self, engine: PipelineEngine) -> None:
        self.engine = engine

    def run(self) -> None:
        now = self.engine.dependencies.clock()
        self.engine.store.update_stage_status("finalization", "running", updated_at=now)
        policy_revision, policy = self.engine.store.read_active_policy()

        for record_id in self.engine.store.record_ids_for_stage("finalization"):
            if not self.record_ready(record_id):
                continue
            try:
                self._finalize_record(
                    record_id,
                    policy_revision=policy_revision,
                    policy=policy,
                )
            except Exception as error:
                self._record_failure(record_id, error)

        self.engine._finish_stage_from_records("finalization")

    def persist_surrogate(
        self,
        request: SurrogateRequest,
        policy: FakerSurrogate | CustomListSurrogate,
    ) -> SurrogateResult:
        generated = generate_surrogate(
            request,
            policy,
            secrets=self.engine.dependencies.secrets,
        )
        return self.engine.transformations.save_surrogate_assignment(
            request=request,
            result=generated,
            created_at=self.engine.dependencies.clock(),
        )

    def materialize_structured_metadata(
        self,
        *,
        record_id: str,
        row: sqlite3.Row,
        entity_id: str,
        plan_revision: int,
        policy_revision: int,
        policy: TransformationPolicy,
        purpose: Literal["draft", "final"],
    ) -> tuple[dict[str, object], list[StructuredEvent]]:
        metadata = json.loads(str(row["metadata_json"]))
        assignments: dict[str, str] = {}

        def structured_surrogate(
            column: str,
            category: PhiCategory,
            original: str,
        ) -> str:
            replacement = policy.categories[category].surrogate
            assert isinstance(replacement, (FakerSurrogate, CustomListSurrogate))
            request = SurrogateRequest(
                event_id=f"structured:{record_id}:{column}",
                record_id=record_id,
                entity_id=entity_id,
                category=category,
                original_text=original,
            )
            saved = self.persist_surrogate(request, replacement)
            assignments[column] = saved.assignment_id
            return saved.surrogate_text

        transformed, events = transform_structured_metadata(
            metadata,
            self.engine.context.config.input.structured_phi_columns,
            policy=policy,
            date_shift=self.date_shift(entity_id, policy_revision),
            surrogate_provider=structured_surrogate,
        )

        if purpose == "final":
            overrides = self._structured_review_overrides(record_id)
            transformed.update(overrides)
            events = [
                (column, category, original, overrides.get(column, replacement))
                for column, category, original, replacement in events
            ]

        for column, category, original, replacement in events:
            self.engine.transformations.save_structured_event(
                record_id=record_id,
                plan_revision=plan_revision,
                policy_revision=policy_revision,
                purpose=purpose,
                column_name=column,
                category=category,
                action=policy.categories[category].action.value,
                original_value=original,
                replacement_value=replacement,
                surrogate_assignment_id=assignments.get(column),
                created_at=self.engine.dependencies.clock(),
            )
        return transformed, events

    def date_shift(self, entity_id: str, policy_revision: int) -> DateShift | None:
        _, policy = self.engine.store.read_active_policy()
        replacement = policy.categories[PhiCategory.DATE].surrogate
        if not isinstance(replacement, DateShiftSurrogate):
            return None
        existing = self.engine.transformations.get_date_shift(
            entity_id=entity_id,
            policy_revision=policy_revision,
        )
        if existing is not None:
            return existing
        shift = derive_date_shift(
            secret=self.engine.dependencies.secrets.resolve(replacement.secret_reference),
            entity_id=entity_id,
            policy=replacement,
        )
        return self.engine.transformations.save_date_shift(
            entity_id=entity_id,
            policy_revision=policy_revision,
            secret_reference=replacement.secret_reference,
            shift=shift,
            created_at=self.engine.dependencies.clock(),
        )

    def record_ready(self, record_id: str) -> bool:
        if not self.engine._prerequisites_succeeded(record_id, ("transformation",)):
            return False
        with self.engine.store.connection() as connection:
            disposition = _review_disposition(
                connection,
                run_id=self.engine.store.run_id(),
                record_id=record_id,
            )
            if disposition == "corrected":
                return True
            if disposition == "excluded":
                return False
            if not self.engine.context.config.validation.enabled:
                review = self.engine.context.config.review
                return not (review.enabled and review.review_scope == "all") or disposition in {
                    "approved_unchanged",
                    "corrected",
                }
            violation = _effective_validation_violation(
                connection,
                run_id=self.engine.store.run_id(),
                record_id=record_id,
            )
        if violation is None:
            return False
        review = self.engine.context.config.review
        requires_review = violation or (review.enabled and review.review_scope == "all")
        return not requires_review or disposition in {"approved_unchanged", "corrected"}

    def _finalize_record(
        self,
        record_id: str,
        *,
        policy_revision: int,
        policy: TransformationPolicy,
    ) -> None:
        row = self.engine.store.read_record(record_id)
        source_text = cast(str, row["normalized_text"])
        entity_id = str(row["entity_id"])
        resolution_revision, groups = self.engine.transformations.active_resolution(record_id)
        assignments: dict[str, str] = {}
        plan_revision = self.engine.transformations.next_plan_revision(record_id)
        events = compile_transform_events(
            source_text,
            groups,
            record_id=record_id,
            plan_revision=plan_revision,
            policy=policy,
            purpose="final",
            surrogate_provider=self._surrogate_provider(
                record_id=record_id,
                entity_id=entity_id,
                assignments=assignments,
                policy=policy,
            ),
            date_shift_provider=self._date_provider(
                shift=self.date_shift(entity_id, policy_revision),
                policy=policy,
            ),
        )
        events = [
            event.model_copy(update={"surrogate_assignment_id": assignments.get(event.group_id)})
            for event in events
        ]
        self.engine.transformations.save_plan(
            record_id=record_id,
            plan_revision=plan_revision,
            resolution_revision=resolution_revision,
            policy_revision=policy_revision,
            purpose="final",
            events=events,
            created_at=self.engine.dependencies.clock(),
        )
        rendered = render_events(
            source_text,
            events,
            rendering_id=_rendering_id(record_id, plan_revision),
        )
        rendering = self.engine.transformations.save_rendering(
            record_id=record_id,
            plan_revision=plan_revision,
            kind="final",
            rendered=rendered,
            created_at=self.engine.dependencies.clock(),
        )
        final_metadata, _ = self.materialize_structured_metadata(
            record_id=record_id,
            row=row,
            entity_id=entity_id,
            plan_revision=plan_revision,
            policy_revision=policy_revision,
            policy=policy,
            purpose="final",
        )
        now = self.engine.dependencies.clock()
        self.engine.store.set_record_status(
            record_id,
            "ready",
            updated_at=now,
            final_rendering_id=rendering.rendering_id,
            final_metadata=final_metadata,
        )
        self.engine.store.update_record_stage_state(
            record_id,
            "finalization",
            "succeeded",
            updated_at=now,
        )
        self.engine.store.resolve_processing_errors(record_id, "finalization", resolved_at=now)

    def _surrogate_provider(
        self,
        *,
        record_id: str,
        entity_id: str,
        assignments: dict[str, str],
        policy: TransformationPolicy,
    ) -> ReplacementProvider:
        def provide(group: SpanGroup, original: str) -> str:
            replacement = policy.categories[group.category].surrogate
            assert isinstance(replacement, (FakerSurrogate, CustomListSurrogate))
            saved = self.persist_surrogate(
                SurrogateRequest(
                    event_id=group.group_id,
                    record_id=record_id,
                    entity_id=entity_id,
                    category=group.category,
                    original_text=original,
                ),
                replacement,
            )
            assignments[group.group_id] = saved.assignment_id
            return saved.surrogate_text

        return provide

    @staticmethod
    def _date_provider(
        *,
        shift: DateShift | None,
        policy: TransformationPolicy,
    ) -> ReplacementProvider | None:
        replacement = policy.categories[PhiCategory.DATE].surrogate
        if shift is None:
            return None
        assert isinstance(replacement, DateShiftSurrogate)

        def provide(group: SpanGroup, original: str) -> str:
            del group
            return shift_date_text(original, shift=shift, fallback=replacement.fallback)

        return provide

    def _structured_review_overrides(self, record_id: str) -> dict[str, object]:
        with self.engine.store.read_snapshot() as connection:
            row = connection.execute(
                """
                SELECT structured_events_json FROM review_decisions
                WHERE run_id = ? AND record_id = ? AND is_current = 1 AND is_stale = 0
                """,
                (self.engine.store.run_id(connection), record_id),
            ).fetchone()
        if row is None:
            return {}
        return {
            str(event["column_name"]): event["replacement_value"]
            for event in json.loads(str(row["structured_events_json"]))
        }

    def _record_failure(self, record_id: str, error: Exception) -> None:
        failed_at = self.engine.dependencies.clock()
        self.engine.store.record_processing_error(
            record_id=record_id,
            stage_name="finalization",
            error=error,
            created_at=failed_at,
        )
        self.engine.store.update_record_stage_state(
            record_id,
            "finalization",
            "permanent_error",
            updated_at=failed_at,
            increment_attempt=True,
        )
        self.engine.store.set_record_status(record_id, "failed", updated_at=failed_at)


def run_finalization(engine: PipelineEngine) -> None:
    _FinalizationStage(engine).run()


def materialize_structured_metadata(
    engine: PipelineEngine,
    *,
    record_id: str,
    row: sqlite3.Row,
    entity_id: str,
    plan_revision: int,
    policy_revision: int,
    policy: TransformationPolicy,
    purpose: Literal["draft", "final"],
) -> tuple[dict[str, object], list[StructuredEvent]]:
    return _FinalizationStage(engine).materialize_structured_metadata(
        record_id=record_id,
        row=row,
        entity_id=entity_id,
        plan_revision=plan_revision,
        policy_revision=policy_revision,
        policy=policy,
        purpose=purpose,
    )


def _review_disposition(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    record_id: str,
) -> str | None:
    row = connection.execute(
        """
        SELECT disposition FROM review_decisions
        WHERE run_id = ? AND record_id = ? AND is_current = 1 AND is_stale = 0
        """,
        (run_id, record_id),
    ).fetchone()
    return None if row is None else str(row[0])


def _effective_validation_violation(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    record_id: str,
) -> bool | None:
    row = connection.execute(
        """
        SELECT effective_violation FROM validation_results
        WHERE run_id = ? AND record_id = ? AND is_stale = 0 AND status = 'succeeded'
        """,
        (run_id, record_id),
    ).fetchone()
    return None if row is None else bool(row[0])


def _rendering_id(record_id: str, plan_revision: int) -> str:
    payload = f"{record_id}\0{plan_revision}\0final".encode()
    return hashlib.sha256(payload).hexdigest()
