"""Finding resolution and draft-rendering stage orchestration."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, cast

from health_deid.core.resolution import RESOLVER_VERSION, resolve_findings
from health_deid.core.transformations import compile_transform_events, render_events
from health_deid.pipeline.finalization import materialize_structured_metadata

if TYPE_CHECKING:
    import sqlite3

    from health_deid.pipeline.engine import PipelineEngine


class _TransformationStage:
    """Resolve findings and create the draft used by validation and review."""

    def __init__(self, engine: PipelineEngine) -> None:
        self.engine = engine

    def run(self) -> None:
        self.engine.store.update_stage_status(
            "transformation",
            "running",
            updated_at=self.engine.dependencies.clock(),
        )

        for record_id in self.engine.store.record_ids_for_stage("transformation"):
            if not self.engine._prerequisites_succeeded(record_id, ("detection",)):
                self.engine.store.update_record_stage_state(
                    record_id,
                    "transformation",
                    "blocked",
                    updated_at=self.engine.dependencies.clock(),
                )
                continue

            self._process_record(record_id)

        self.engine._finish_stage_from_records("transformation")

    def _process_record(self, record_id: str) -> None:
        row = self.engine.store.read_record(record_id)
        source_text = cast(str, row["normalized_text"])

        try:
            self._create_draft_rendering(record_id, row=row, source_text=source_text)
            self.engine.store.update_record_stage_state(
                record_id,
                "transformation",
                "succeeded",
                updated_at=self.engine.dependencies.clock(),
            )
            self.engine.store.resolve_processing_errors(
                record_id,
                "transformation",
                resolved_at=self.engine.dependencies.clock(),
            )
        except Exception as exc:
            failed_at = self.engine.dependencies.clock()
            self.engine.store.record_processing_error(
                record_id=record_id,
                stage_name="transformation",
                error=exc,
                created_at=failed_at,
            )
            self.engine.store.update_record_stage_state(
                record_id,
                "transformation",
                "permanent_error",
                updated_at=failed_at,
                increment_attempt=True,
            )
            self.engine.store.set_record_status(record_id, "failed", updated_at=failed_at)

    def _create_draft_rendering(
        self,
        record_id: str,
        *,
        row: sqlite3.Row,
        source_text: str,
    ) -> None:
        findings = self.engine.findings.list_findings(record_id, eligible_only=True)
        resolved = resolve_findings(source_text, findings, record_id=record_id)
        resolution_revision = self.engine.transformations.save_resolution(
            record_id=record_id,
            findings_sha256=resolved.findings_sha256,
            resolver_version=RESOLVER_VERSION,
            groups=resolved.groups,
            reason="automatic resolution",
            created_at=self.engine.dependencies.clock(),
        )

        policy_revision, policy = self.engine.store.read_active_policy()
        plan_revision = self.engine.transformations.next_plan_revision(record_id)
        events = compile_transform_events(
            source_text,
            resolved.groups,
            record_id=record_id,
            plan_revision=plan_revision,
            policy=policy,
            purpose="draft",
        )
        self.engine.transformations.save_plan(
            record_id=record_id,
            plan_revision=plan_revision,
            resolution_revision=resolution_revision,
            policy_revision=policy_revision,
            purpose="draft",
            events=events,
            created_at=self.engine.dependencies.clock(),
        )

        rendering_id = _rendering_id(record_id, plan_revision)
        rendered = render_events(source_text, events, rendering_id=rendering_id)
        self.engine.transformations.save_rendering(
            record_id=record_id,
            plan_revision=plan_revision,
            kind="draft",
            rendered=rendered,
            created_at=self.engine.dependencies.clock(),
        )

        draft_metadata, _ = materialize_structured_metadata(
            self.engine,
            record_id=record_id,
            row=row,
            entity_id=str(row["entity_id"]),
            plan_revision=plan_revision,
            policy_revision=policy_revision,
            policy=policy,
            purpose="draft",
        )
        self.engine.store.set_draft_metadata(
            record_id,
            draft_metadata,
            updated_at=self.engine.dependencies.clock(),
        )


def run_transformation(engine: PipelineEngine) -> None:
    _TransformationStage(engine).run()


def _rendering_id(record_id: str, plan_revision: int) -> str:
    payload = f"{record_id}\0{plan_revision}\0draft".encode()
    return hashlib.sha256(payload).hexdigest()
