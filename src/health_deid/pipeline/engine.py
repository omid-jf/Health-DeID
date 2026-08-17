"""Resumable pipeline orchestration shared by every public interface."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from filelock import FileLock, Timeout

from health_deid.backends.contracts import PhiDetector, PhiValidator
from health_deid.backends.rules import snapshot_configured_rules
from health_deid.core.secret_refs import EnvironmentSecretResolver, SecretResolver
from health_deid.models.config import PipelineConfig
from health_deid.models.ledger import (
    ProcessingErrorStage,
    RunStageStatus,
    RunStatus,
    StageName,
)
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.detection import run_detection
from health_deid.pipeline.finalization import run_finalization
from health_deid.pipeline.input import (
    build_input_import_summary,
    normalize_input_records,
    read_input_file,
)
from health_deid.pipeline.transformation import run_transformation
from health_deid.pipeline.validation import run_validation
from health_deid.storage.database import RunDatabaseError, SqliteRunStore
from health_deid.storage.findings import FindingRepository
from health_deid.storage.transformations import TransformationRepository
from health_deid.storage.validation import ValidationRepository

ValidatorFactory = Callable[[int], PhiValidator]


@dataclass(slots=True)
class EngineDependencies:
    """Replaceable external dependencies used by the pipeline engine."""

    detectors: dict[str, PhiDetector] = field(default_factory=dict)
    validator_factory: ValidatorFactory | None = None
    secrets: SecretResolver = field(default_factory=EnvironmentSecretResolver)
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


class PipelineEngine:
    """Create, run, and resume one durable de-identification run."""

    def __init__(
        self,
        context: RunContext,
        *,
        dependencies: EngineDependencies | None = None,
    ) -> None:
        self.context = context
        self.store = SqliteRunStore.open(context.database_path)
        self.dependencies = dependencies or EngineDependencies()

        self.findings = FindingRepository(self.store)
        self.transformations = TransformationRepository(self.store)
        self.validations = ValidationRepository(self.store)

    @classmethod
    def create(
        cls,
        config: PipelineConfig,
        *,
        dependencies: EngineDependencies | None = None,
        timestamp: datetime | None = None,
    ) -> PipelineEngine:
        """Create a durable run and import its input data."""

        config = snapshot_configured_rules(config)
        context = RunContext.from_config(config, timestamp=timestamp)
        input_rows = read_input_file(config.input)
        records = normalize_input_records(input_rows, config.input)
        summary = build_input_import_summary(
            config.input,
            records,
            imported_at=context.created_at,
        )

        context.run_dir.mkdir(parents=True, exist_ok=False)
        try:
            context.exports_dir.mkdir()
            store = SqliteRunStore.create(
                context.database_path,
                run_id=context.run_id,
                config=config,
                created_at=context.created_at,
            )
            store.import_records(records, summary)
        except BaseException as error:
            _remove_partial_run(context, error=error)
            raise

        return cls(context, dependencies=dependencies)

    def execute(self) -> RunContext:
        """Run every stage that still has pending work."""

        now = self.dependencies.clock()
        lock = FileLock(str(self.context.run_dir / ".processing.lock"))
        try:
            lock.acquire(timeout=0)
        except Timeout as error:
            raise RunDatabaseError("This run is already being processed.") from error

        active_stage: ProcessingErrorStage = "run"
        try:
            self.store.recover_interrupted_work(updated_at=now)
            self.store.update_run_status("running", updated_at=now)

            operations: tuple[tuple[StageName, Callable[[], None]], ...] = (
                ("detection", self.run_detection),
                ("transformation", self.run_transformation),
                ("validation", self.run_validation),
                ("finalization", self.run_finalization),
            )
            for active_stage, operation in operations:
                operation()
                self.store.resolve_processing_errors(
                    None,
                    active_stage,
                    resolved_at=self.dependencies.clock(),
                )

            active_stage = "run"
            self._refresh_run_status()
            self.store.resolve_processing_errors(
                None,
                "run",
                resolved_at=self.dependencies.clock(),
            )
        except (KeyboardInterrupt, SystemExit) as error:
            self._record_run_level_failure(
                error,
                stage=active_stage,
                run_status="blocked",
                stage_status="blocked",
                retryable=True,
            )
            raise
        except Exception as error:
            self._record_run_level_failure(
                error,
                stage=active_stage,
                run_status="failed",
                stage_status="failed",
                retryable=False,
            )
            raise
        finally:
            lock.release()

        return self.context

    def resume(self) -> RunContext:
        """Resume pending or interrupted work for this run."""

        return self.execute()

    def run_detection(self) -> None:
        """Run enabled PHI detection backends."""

        run_detection(self)

    def run_transformation(self) -> None:
        """Resolve findings and prepare validation renderings."""

        run_transformation(self)

    def run_validation(self) -> None:
        """Run automated validation and route human review."""

        run_validation(self)

    def run_finalization(self) -> None:
        """Create final de-identified text and structured data."""

        run_finalization(self)

    def _prerequisites_succeeded(
        self,
        record_id: str,
        stages: tuple[StageName, ...],
    ) -> bool:
        placeholders = ",".join("?" for _ in stages)
        with self.store.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT stage_name, status
                FROM record_stage_states
                WHERE run_id = ? AND record_id = ?
                  AND stage_name IN ({placeholders})
                """,
                (self.store.run_id(), record_id, *stages),
            ).fetchall()

        return len(rows) == len(stages) and all(
            str(row["status"]) in {"succeeded", "skipped"} for row in rows
        )

    def _record_run_level_failure(
        self,
        error: BaseException,
        *,
        stage: ProcessingErrorStage,
        run_status: RunStatus,
        stage_status: RunStageStatus,
        retryable: bool,
    ) -> None:
        failed_at = self.dependencies.clock()

        try:
            self.store.record_processing_error(
                record_id=None,
                stage_name=stage,
                error=error,
                created_at=failed_at,
                retryable=retryable,
                error_code="interrupted" if retryable else "unexpected_run_error",
            )
            if stage != "run":
                self.store.update_stage_status(stage, stage_status, updated_at=failed_at)

            self.store.update_run_status(run_status, updated_at=failed_at)
        except Exception as bookkeeping_error:
            error.add_note(f"Run failure bookkeeping also failed: {bookkeeping_error}")

    def _finish_disabled_stage(self, stage: StageName) -> None:
        self.store.update_stage_status(
            stage,
            "skipped",
            updated_at=self.dependencies.clock(),
        )

    def _finish_stage_from_records(self, stage: StageName) -> None:
        with self.store.connection() as connection:
            rows = connection.execute(
                """
                SELECT status, count(*) AS count
                FROM record_stage_states
                WHERE run_id = ? AND stage_name = ?
                GROUP BY status
                """,
                (self.store.run_id(), stage),
            ).fetchall()

        statuses = {str(row["status"]): int(row["count"]) for row in rows}
        active_statuses = {status for status in statuses if status not in {"excluded", "skipped"}}

        if not active_statuses:
            result: RunStageStatus = "skipped"
        elif active_statuses <= {"succeeded"}:
            result = "completed"
        elif active_statuses & {"retry_exhausted", "permanent_error", "blocked"}:
            result = "completed_with_errors"
        else:
            result = "blocked"

        self.store.update_stage_status(
            stage,
            result,
            updated_at=self.dependencies.clock(),
        )

    def _refresh_run_status(self) -> None:
        with self.store.connection() as connection:
            rows = connection.execute(
                "SELECT status, count(*) AS count FROM records GROUP BY status"
            ).fetchall()

        statuses = {str(row["status"]): int(row["count"]) for row in rows}
        if statuses.get("awaiting_review"):
            status: RunStatus = "awaiting_review"
        elif (
            statuses.get("failed")
            or self.store.read_stage_status("finalization") == "completed_with_errors"
        ):
            status = "completed_with_errors"
        elif statuses.get("ready") or set(statuses) == {"excluded"}:
            status = "completed"
        else:
            status = "blocked"

        self.store.update_run_status(status, updated_at=self.dependencies.clock())


def _remove_partial_run(context: RunContext, *, error: BaseException) -> None:
    try:
        shutil.rmtree(context.run_dir)
    except Exception as cleanup_error:
        error.add_note(f"Partial run cleanup also failed: {cleanup_error}")
