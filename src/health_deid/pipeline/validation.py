"""Automated validation stage orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from health_deid.backends.bedrock import (
    DEIDENTIFICATION_POLICY,
    SAFEGUARD_POLICY_VERSION,
    SAFEGUARD_SCHEMA,
    AwsBedrockSafeguardValidator,
)
from health_deid.backends.contracts import PhiValidator
from health_deid.backends.runtime import (
    BackendExecutionError,
    chunk_utf8_text,
    classify_exception,
)
from health_deid.core.taxonomy import TAXONOMY_VERSION
from health_deid.models.backend import ValidationResult
from health_deid.models.ledger import RecordStageStatus
from health_deid.storage.findings import BackendDefinition, BackendWorkItem

if TYPE_CHECKING:
    from health_deid.pipeline.engine import PipelineEngine


_VALIDATOR_BACKEND_ID = "validator"


@dataclass(frozen=True, slots=True)
class ValidationCall:
    """One prepared validator request and its persisted attempt metadata."""

    work_item: BackendWorkItem
    attempt_id: str
    attempt_number: int
    token_tier_index: int
    original_text: str
    draft_text: str


class _ValidationStage:
    """Validate de-identified output and route records into human review."""

    def __init__(self, engine: PipelineEngine) -> None:
        self.engine = engine

    def run(self) -> None:
        config = self.engine.context.config.validation
        if not config.enabled:
            self.engine._finish_disabled_stage("validation")
            self.prepare_unvalidated_review()
            return

        self.engine.store.update_stage_status(
            "validation",
            "running",
            updated_at=self.engine.dependencies.clock(),
        )
        self._register_backend()

        while True:
            calls = self.pending_calls(_VALIDATOR_BACKEND_ID)
            if not calls:
                break
            self._process_calls(calls)

        self.engine._finish_stage_from_records("validation")
        self.engine._finish_stage_from_records("review")

    def pending_calls(self, backend_id: str) -> list[ValidationCall]:
        calls: list[ValidationCall] = []
        token_tiers = self.engine.context.config.validation.output_token_tiers

        for record_id in self.engine.store.record_ids_for_stage("validation"):
            if not self.engine._prerequisites_succeeded(record_id, ("transformation",)):
                self.engine.store.update_record_stage_state(
                    record_id,
                    "validation",
                    "blocked",
                    updated_at=self.engine.dependencies.clock(),
                )
                continue

            row = self.engine.store.read_record(record_id)
            original_text = cast(str, row["normalized_text"])
            rendering = self.engine.transformations.current_rendering(record_id, "draft")

            work_items = self._work_items(
                record_id=record_id,
                backend_id=backend_id,
                draft_text=rendering.rendered_text,
            )
            for work_item in work_items:
                if work_item.status not in {"pending", "retry_pending"}:
                    continue

                attempt_id, attempt_number = self.engine.findings.begin_attempt(
                    work_item,
                    started_at=self.engine.dependencies.clock(),
                )
                truncations = self.engine.findings.truncated_attempt_count(work_item.work_item_id)
                tier_index = min(truncations, len(token_tiers) - 1)
                calls.append(
                    ValidationCall(
                        work_item=work_item,
                        attempt_id=attempt_id,
                        attempt_number=attempt_number,
                        token_tier_index=tier_index,
                        original_text=original_text,
                        draft_text=rendering.rendered_text,
                    )
                )

        return calls

    def validator(self, max_output_tokens: int) -> PhiValidator:
        if self.engine.dependencies.validator_factory is not None:
            return self.engine.dependencies.validator_factory(max_output_tokens)

        config = self.engine.context.config.validation
        return AwsBedrockSafeguardValidator(
            region_name=config.region_name,
            max_output_tokens=max_output_tokens,
            input_cost_per_million_tokens=config.input_cost_per_million_tokens,
            output_cost_per_million_tokens=config.output_cost_per_million_tokens,
        )

    def prepare_unvalidated_review(self) -> None:
        review_config = self.engine.context.config.review
        review_all = review_config.enabled and review_config.review_scope == "all"

        for record_id in self.engine.store.record_ids_for_stage("review"):
            now = self.engine.dependencies.clock()

            if review_all:
                self.engine.store.update_record_stage_state(
                    record_id,
                    "review",
                    "review_pending",
                    updated_at=now,
                )
                self.engine.store.set_record_status(record_id, "awaiting_review", updated_at=now)
            else:
                self.engine.store.update_record_stage_state(
                    record_id,
                    "review",
                    "skipped",
                    updated_at=now,
                )

        self.engine._finish_stage_from_records("review")

    def _register_backend(self) -> None:
        config = self.engine.context.config.validation
        self.engine.findings.register_backend(
            BackendDefinition(
                backend_id=_VALIDATOR_BACKEND_ID,
                kind="validator",
                name=config.backend,
                version=SAFEGUARD_POLICY_VERSION,
                model_id=config.model_id,
                settings=config.model_dump(mode="json"),
                taxonomy_version=TAXONOMY_VERSION,
                prompt_text=DEIDENTIFICATION_POLICY,
                schema=SAFEGUARD_SCHEMA,
            ),
            created_at=self.engine.dependencies.clock(),
        )

    def _work_items(
        self,
        *,
        record_id: str,
        backend_id: str,
        draft_text: str,
    ) -> list[BackendWorkItem]:
        existing = self.engine.findings.work_items(
            record_id=record_id,
            backend_id=backend_id,
        )
        if existing:
            return existing

        chunks = chunk_utf8_text(
            draft_text,
            maximum_bytes=max(1, len(draft_text.encode("utf-8"))),
            overlap_characters=0,
        )
        return self.engine.findings.prepare_work(
            record_id=record_id,
            backend_id=backend_id,
            stage_name="validation",
            chunks=chunks,
            created_at=self.engine.dependencies.clock(),
        )

    def _process_calls(
        self,
        calls: list[ValidationCall],
    ) -> None:
        config = self.engine.context.config.validation

        def invoke(
            call: ValidationCall,
        ) -> tuple[ValidationCall, ValidationResult | None, BaseException | None]:
            try:
                validator = self.validator(config.output_token_tiers[call.token_tier_index])
                return (
                    call,
                    validator.validate(
                        original_text=call.original_text,
                        deidentified_text=call.draft_text,
                    ),
                    None,
                )
            except BaseException as error:
                return call, None, error

        with ThreadPoolExecutor(max_workers=config.execution.workers) as executor:
            for start in range(0, len(calls), config.execution.workers):
                systemic_error: BackendExecutionError | None = None
                batch = calls[start : start + config.execution.workers]
                for call, result, error in executor.map(invoke, batch):
                    classified = self._finish_outcome(call, result, error)
                    if classified is not None and classified.systemic:
                        systemic_error = systemic_error or classified
                if systemic_error is not None:
                    raise systemic_error

    def _finish_outcome(
        self,
        call: ValidationCall,
        result: ValidationResult | None,
        error: BaseException | None,
    ) -> BackendExecutionError | None:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise error

        rendering = self.engine.transformations.current_rendering(
            call.work_item.record_id,
            "draft",
        )
        if error is None:
            assert result is not None
            _, policy = self.engine.store.read_active_policy()
            self.engine.validations.finish_success(
                attempt_id=call.attempt_id,
                work_item=call.work_item,
                rendering=rendering,
                result=result,
                policy=policy,
                finished_at=self.engine.dependencies.clock(),
            )
            return None

        classified = classify_exception(error)
        config = self.engine.context.config.validation
        next_token_tier_available = classified.truncated and call.token_tier_index + 1 < len(
            config.output_token_tiers
        )
        maximum_attempts = call.attempt_number + 1 if next_token_tier_available else 1
        finished_at = self.engine.dependencies.clock()

        with self.engine.store.connection() as connection:
            state = self.engine.findings.fail_attempt(
                attempt_id=call.attempt_id,
                work_item=call.work_item,
                error=classified,
                attempt_number=call.attempt_number,
                maximum_attempts=maximum_attempts,
                finished_at=finished_at,
                connection=connection,
            )
            self.engine.validations.record_failure(
                attempt_id=call.attempt_id,
                work_item=call.work_item,
                rendering=rendering,
                error=classified,
                finished_at=finished_at,
                connection=connection,
            )

        if state == "retry_pending":
            return None

        terminal_status: RecordStageStatus = (
            "retry_exhausted" if classified.retryable else "permanent_error"
        )
        self.engine.store.update_record_stage_state(
            call.work_item.record_id,
            "validation",
            terminal_status,
            updated_at=self.engine.dependencies.clock(),
            increment_attempt=True,
        )
        self.engine.store.set_record_status(
            call.work_item.record_id,
            "failed",
            updated_at=self.engine.dependencies.clock(),
        )
        return classified


def run_validation(engine: PipelineEngine) -> None:
    _ValidationStage(engine).run()
