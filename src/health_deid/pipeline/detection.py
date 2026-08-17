"""PHI detection stage orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from health_deid.backends.bedrock import (
    LLM_DETECTION_SCHEMA,
    LLM_DETECTION_SYSTEM_PROMPT,
    LLM_DETECTOR_VERSION,
    AwsBedrockLlmPhiDetector,
)
from health_deid.backends.comprehend import AwsComprehendMedicalPhiDetector
from health_deid.backends.contracts import PhiDetector
from health_deid.backends.rules import RulesFile, find_rule_candidates, load_rules_file
from health_deid.backends.runtime import (
    BackendExecutionError,
    chunk_utf8_text,
    classify_exception,
)
from health_deid.core.taxonomy import TAXONOMY_VERSION
from health_deid.models.backend import DetectionResult
from health_deid.models.config import (
    AwsComprehendDetectorConfig,
    BedrockLlmDetectorConfig,
    DetectorConfig,
    RulesConfig,
)
from health_deid.models.ledger import RecordStageStatus
from health_deid.storage.findings import BackendDefinition, BackendWorkItem

if TYPE_CHECKING:
    from health_deid.pipeline.engine import PipelineEngine


@dataclass(frozen=True, slots=True)
class DetectionCall:
    """One prepared detector request and its persisted attempt metadata."""

    config: DetectorConfig
    detector: PhiDetector
    work_item: BackendWorkItem
    attempt_id: str
    attempt_number: int
    text: str


class _DetectionStage:
    """Run configured detectors and persist each request outcome."""

    def __init__(self, engine: PipelineEngine) -> None:
        self.engine = engine

    def run(self) -> None:
        config = self.engine.context.config.detection
        rules_config = self.engine.context.config.rules
        if not config.enabled and not rules_config.enabled:
            self.engine._finish_disabled_stage("detection")
            return

        stage_is_finished = self.engine.store.read_stage_status(
            "detection"
        ) == "completed" and not self.engine.store.record_ids_for_stage("detection")
        if stage_is_finished:
            return

        self.engine.store.update_stage_status(
            "detection",
            "running",
            updated_at=self.engine.dependencies.clock(),
        )

        record_ids = self.engine.store.record_ids_for_stage("detection")
        if config.enabled:
            bindings = [
                (detector_config, self.detector(detector_config))
                for detector_config in config.detectors
            ]
            for detector_config, _ in bindings:
                self.register_detector(detector_config)
            while True:
                calls = self.pending_calls(bindings)
                if not calls:
                    break
                self._process_calls(calls)
            self.derive_record_states([detector.name for detector, _ in bindings])
        else:
            for record_id in record_ids:
                self.engine.store.update_record_stage_state(
                    record_id,
                    "detection",
                    "succeeded",
                    updated_at=self.engine.dependencies.clock(),
                )

        if rules_config.enabled:
            self._run_rules(record_ids, rules_config)
        self.engine._finish_stage_from_records("detection")

    def pending_calls(
        self,
        bindings: list[tuple[DetectorConfig, PhiDetector]],
    ) -> list[DetectionCall]:
        calls: list[DetectionCall] = []

        for record_id in self.engine.store.record_ids_for_stage("detection"):
            row = self.engine.store.read_record(record_id)
            source_text = cast(str, row["normalized_text"])

            for detector_config, detector in bindings:
                work_items = self._work_items(
                    record_id=record_id,
                    source_text=source_text,
                    detector_config=detector_config,
                )

                for work_item in work_items:
                    if work_item.status not in {"pending", "retry_pending"}:
                        continue

                    attempt_id, attempt_number = self.engine.findings.begin_attempt(
                        work_item,
                        started_at=self.engine.dependencies.clock(),
                    )
                    calls.append(
                        DetectionCall(
                            config=detector_config,
                            detector=detector,
                            work_item=work_item,
                            attempt_id=attempt_id,
                            attempt_number=attempt_number,
                            text=source_text[work_item.start_char : work_item.end_char],
                        )
                    )

        return calls

    def detector(self, config: DetectorConfig) -> PhiDetector:
        override = self.engine.dependencies.detectors.get(config.name)
        if override is not None:
            return override

        if isinstance(config, AwsComprehendDetectorConfig):
            return AwsComprehendMedicalPhiDetector(
                region_name=config.region_name,
                cost_per_100_characters_usd=config.cost_per_100_characters_usd,
            )

        return AwsBedrockLlmPhiDetector(
            model_id=config.model_id,
            region_name=config.region_name,
            max_output_tokens=config.max_output_tokens,
            reasoning_effort=config.reasoning_effort,
            input_cost_per_million_tokens=config.input_cost_per_million_tokens,
            output_cost_per_million_tokens=config.output_cost_per_million_tokens,
        )

    def register_detector(self, config: DetectorConfig) -> None:
        is_llm = isinstance(config, BedrockLlmDetectorConfig)
        model_id = None if isinstance(config, AwsComprehendDetectorConfig) else config.model_id

        self.engine.findings.register_backend(
            BackendDefinition(
                backend_id=config.name,
                kind="detector",
                name=config.backend,
                version=LLM_DETECTOR_VERSION if is_llm else None,
                model_id=model_id,
                settings=config.model_dump(mode="json"),
                taxonomy_version=TAXONOMY_VERSION,
                prompt_text=LLM_DETECTION_SYSTEM_PROMPT if is_llm else None,
                schema=LLM_DETECTION_SCHEMA if is_llm else None,
            ),
            created_at=self.engine.dependencies.clock(),
        )

    def derive_record_states(self, backend_ids: list[str]) -> None:
        run_id = self.engine.store.run_id()

        for record_id in self.engine.store.record_ids_for_stage("detection"):
            with self.engine.store.connection() as connection:
                rows = connection.execute(
                    """
                    SELECT backend_id,
                        CASE
                            WHEN sum(status != 'succeeded') = 0 THEN 'succeeded'
                            WHEN sum(status = 'retry_pending') > 0 THEN 'retry_pending'
                            WHEN sum(status = 'permanent_error') > 0 THEN 'permanent_error'
                            ELSE 'retry_exhausted'
                        END AS status
                    FROM backend_work_items
                    WHERE run_id = ? AND record_id = ? AND stage_name = 'detection'
                      AND backend_id IN ({})
                    GROUP BY backend_id
                    """.format(",".join("?" for _ in backend_ids)),
                    (run_id, record_id, *backend_ids),
                ).fetchall()

            statuses = {str(row["status"]) for row in rows}
            status = _record_stage_status(
                backend_count=len(backend_ids),
                returned_count=len(rows),
                statuses=statuses,
            )
            self.engine.store.update_record_stage_state(
                record_id,
                "detection",
                status,
                updated_at=self.engine.dependencies.clock(),
            )

            if status == "succeeded":
                self.engine.store.resolve_processing_errors(
                    record_id,
                    "detection",
                    resolved_at=self.engine.dependencies.clock(),
                )
            elif status in {"retry_exhausted", "permanent_error"}:
                self.engine.store.set_record_status(
                    record_id,
                    "failed",
                    updated_at=self.engine.dependencies.clock(),
                )

    def _run_rules(self, record_ids: list[str], config: RulesConfig) -> None:
        rules, source_name = _configured_rules(config)
        for record_id in record_ids:
            with self.engine.store.connection() as connection:
                row = connection.execute(
                    """
                    SELECT status FROM record_stage_states
                    WHERE run_id = ? AND record_id = ? AND stage_name = 'detection'
                    """,
                    (self.engine.store.run_id(connection), record_id),
                ).fetchone()
            if row is None or str(row["status"]) != "succeeded":
                continue
            try:
                text = cast(str, self.engine.store.read_record(record_id)["normalized_text"])
                candidates = find_rule_candidates(text, rules)
                self.engine.findings.insert_rule_findings(
                    record_id=record_id,
                    source_name=source_name,
                    candidates=candidates,
                    created_at=self.engine.dependencies.clock(),
                )
            except Exception as error:
                failed_at = self.engine.dependencies.clock()
                self.engine.store.record_processing_error(
                    record_id=record_id,
                    stage_name="detection",
                    error=error,
                    created_at=failed_at,
                )
                self.engine.store.update_record_stage_state(
                    record_id,
                    "detection",
                    "permanent_error",
                    updated_at=failed_at,
                    increment_attempt=True,
                )
                self.engine.store.set_record_status(record_id, "failed", updated_at=failed_at)

    def _work_items(
        self,
        *,
        record_id: str,
        source_text: str,
        detector_config: DetectorConfig,
    ) -> list[BackendWorkItem]:
        existing = self.engine.findings.work_items(
            record_id=record_id,
            backend_id=detector_config.name,
        )
        if existing:
            return existing

        if isinstance(detector_config, AwsComprehendDetectorConfig):
            chunks = chunk_utf8_text(
                source_text,
                maximum_bytes=detector_config.maximum_bytes,
                overlap_characters=detector_config.overlap_characters,
            )
        else:
            chunks = chunk_utf8_text(
                source_text,
                maximum_bytes=max(1, len(source_text.encode("utf-8"))),
                overlap_characters=0,
            )

        return self.engine.findings.prepare_work(
            record_id=record_id,
            backend_id=detector_config.name,
            stage_name="detection",
            chunks=chunks,
            created_at=self.engine.dependencies.clock(),
        )

    def _process_calls(
        self,
        calls: list[DetectionCall],
    ) -> None:
        config = self.engine.context.config.detection

        def invoke(
            call: DetectionCall,
        ) -> tuple[DetectionCall, DetectionResult | None, BaseException | None]:
            try:
                return call, call.detector.detect(call.text), None
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
        call: DetectionCall,
        result: DetectionResult | None,
        error: BaseException | None,
    ) -> BackendExecutionError | None:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise error

        if error is None:
            assert result is not None
            source_kind: Literal["aws", "llm"] = (
                "aws" if isinstance(call.config, AwsComprehendDetectorConfig) else "llm"
            )
            self.engine.findings.finish_detection_attempt(
                attempt_id=call.attempt_id,
                work_item=call.work_item,
                result=result,
                source_kind=source_kind,
                source_name=call.config.name,
                minimum_confidence=call.config.min_confidence,
                finished_at=self.engine.dependencies.clock(),
            )
            return None

        classified = classify_exception(error)
        self.engine.findings.fail_attempt(
            attempt_id=call.attempt_id,
            work_item=call.work_item,
            error=classified,
            attempt_number=call.attempt_number,
            maximum_attempts=1,
            finished_at=self.engine.dependencies.clock(),
        )
        return classified


def run_detection(engine: PipelineEngine) -> None:
    _DetectionStage(engine).run()


def _record_stage_status(
    *,
    backend_count: int,
    returned_count: int,
    statuses: set[str],
) -> RecordStageStatus:
    if returned_count == backend_count and statuses == {"succeeded"}:
        return "succeeded"
    if "retry_pending" in statuses:
        return "retry_pending"
    if "permanent_error" in statuses:
        return "permanent_error"

    return "retry_exhausted"


def _configured_rules(config: RulesConfig) -> tuple[RulesFile, str]:
    if config.embedded is not None:
        return config.embedded, "embedded_rules"
    assert config.rules_path is not None
    return load_rules_file(config.rules_path), str(config.rules_path)
