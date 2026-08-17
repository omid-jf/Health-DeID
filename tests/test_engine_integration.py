from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

import pytest

import health_deid.pipeline.detection as detection_module
import health_deid.pipeline.validation as validation_module
from health_deid.backends.contracts import PhiDetector, PhiValidator
from health_deid.backends.rules import RedactionRule, RulesFile
from health_deid.backends.runtime import BackendExecutionError, TextChunk
from health_deid.core.secret_refs import MappingSecretResolver
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import (
    BackendUsage,
    DetectionCandidate,
    DetectionResult,
    ValidationFinding,
    ValidationResult,
    ValidationUsage,
)
from health_deid.models.config import PipelineConfig, RulesConfig
from health_deid.models.policy import TransformationPolicy
from health_deid.models.review import ReviewDecision
from health_deid.pipeline.detection import _DetectionStage, _record_stage_status
from health_deid.pipeline.engine import EngineDependencies, PipelineEngine
from health_deid.pipeline.finalization import _FinalizationStage
from health_deid.pipeline.review import ReviewService, build_review_decision_id
from health_deid.pipeline.transformation import _TransformationStage
from health_deid.pipeline.validation import _ValidationStage

NOW = datetime(2026, 7, 31, 15, 0, tzinfo=UTC)


class FakeDetector(PhiDetector):
    def __init__(
        self,
        finder: Callable[[str], list[DetectionCandidate]],
        *,
        fail_when: str | None = None,
    ) -> None:
        self.finder = finder
        self.fail_when = fail_when
        self.calls: list[str] = []
        self._lock = Lock()

    def detect(self, text: str) -> DetectionResult:
        with self._lock:
            self.calls.append(text)
        if self.fail_when and self.fail_when in text:
            raise ValueError("synthetic detector failure")
        return DetectionResult(
            candidates=self.finder(text),
            raw_output={"text": text},
            model_version="fake-v1",
            usage=BackendUsage(
                input_chars=len(text),
                input_bytes=len(text.encode()),
                latency_ms=1,
            ),
        )


class SequenceValidator(PhiValidator):
    def __init__(self, action: object, calls: list[tuple[str, str]]) -> None:
        self.action = action
        self.calls = calls

    def validate(
        self,
        *,
        original_text: str,
        deidentified_text: str,
    ) -> ValidationResult:
        self.calls.append((original_text, deidentified_text))
        if isinstance(self.action, BaseException):
            raise self.action
        assert isinstance(self.action, ValidationResult)
        return self.action


def _candidate(text: str, needle: str, category: PhiCategory) -> DetectionCandidate:
    start = text.index(needle)
    return DetectionCandidate(
        backend_span_id=f"{category.value}:{start}",
        category=category,
        native_category=category.value,
        text=needle,
        start_char=start,
        end_char=start + len(needle),
        confidence=0.99,
    )


def _name_finder(text: str) -> list[DetectionCandidate]:
    return [_candidate(text, name, PhiCategory.NAME) for name in ("Alice", "Bob") if name in text]


def _source(tmp_path: Path, rows: list[dict[str, object]]) -> Path:
    path = tmp_path / "notes.jsonl"
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    return path


def _config(
    tmp_path: Path,
    rows: list[dict[str, object]],
    *,
    validation: bool = False,
    review: bool = False,
    policy: dict[str, object] | None = None,
    structured: dict[str, str] | None = None,
    detector_backend: str = "aws_bedrock",
    detector_overrides: dict[str, object] | None = None,
    surrogates: dict[str, object] | None = None,
) -> PipelineConfig:
    metadata = ["service_date"] if any("service_date" in row for row in rows) else []
    detector: dict[str, object] = {
        "backend": detector_backend,
    }
    if detector_backend == "aws_bedrock":
        detector["model_id"] = "us.anthropic.claude-sonnet-4-6"
    if detector_overrides:
        detector.update(detector_overrides)
    payload: dict[str, object] = {
        "run": {"name": "integration", "output_dir": tmp_path / "runs"},
        "input": {
            "path": _source(tmp_path, rows),
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "column", "column": "entity_id"},
            "text_column": "text",
            "metadata_columns": metadata,
            "structured_phi_columns": structured or {},
        },
        "detection": {
            "detectors": [detector],
            "execution": {"workers": 2},
        },
        "validation": {
            "enabled": validation,
            "execution": {"workers": 1},
        },
        "review": {"enabled": review},
    }
    if policy is not None:
        payload["policy"] = policy
    assert surrogates is None
    return PipelineConfig.model_validate(payload)


def _dependencies(
    detector: PhiDetector,
    *,
    validator_factory: Callable[[int], PhiValidator] | None = None,
    secrets: MappingSecretResolver | None = None,
) -> EngineDependencies:
    return EngineDependencies(
        detectors={"sonnet_4_6": detector, "comprehend_medical": detector},
        validator_factory=validator_factory,
        secrets=secrets or MappingSecretResolver({}),
        clock=lambda: NOW,
    )


def _no_findings() -> ValidationResult:
    return ValidationResult(
        findings=[],
        rationale="No residual identifiers.",
        raw_output={"findings": []},
        usage=ValidationUsage(input_chars=1, input_bytes=1, latency_ms=1),
    )


def test_full_run_partial_failure_and_policy_only_rerender(tmp_path: Path) -> None:
    rows = [
        {"record_id": "R1", "entity_id": "E1", "text": "Alice arrived."},
        {"record_id": "R2", "entity_id": "E2", "text": "FAIL Bob arrived."},
    ]
    detector = FakeDetector(_name_finder, fail_when="FAIL")
    engine = PipelineEngine.create(
        _config(tmp_path, rows),
        dependencies=_dependencies(detector),
        timestamp=NOW,
    )

    engine.execute()

    assert engine.store.read_run_status() == "completed_with_errors"
    assert engine.store.read_record("R1")["status"] == "ready"
    assert engine.store.read_record("R2")["status"] == "failed"
    final = engine.transformations.current_rendering("R1", "final")
    assert final.rendered_text == "[R_NAME] arrived."
    assert len(detector.calls) == 2
    with engine.store.connection() as connection:
        assert connection.execute("SELECT count(*) FROM processing_errors").fetchone()[0] == 1


def test_rules_only_run_uses_normalized_source_and_no_stage_files(tmp_path: Path) -> None:
    rows = [{"record_id": "R1", "entity_id": "E1", "text": "Code ZX-123 here."}]
    config = _config(tmp_path, rows)
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: custom-id\n    name: Custom ID\n    pattern: 'ZX-[0-9]+'\n    category: ID\n",
        encoding="utf-8",
    )
    payload = config.model_dump(mode="python")
    payload["detection"]["enabled"] = False
    payload["rules"] = {"enabled": True, "rules_path": rules}
    config = PipelineConfig.model_validate(payload)
    detector = FakeDetector(lambda text: [])
    engine = PipelineEngine.create(config, dependencies=_dependencies(detector), timestamp=NOW)
    assert engine.context.config.rules.rules_path is None
    assert engine.context.config.rules.embedded is not None
    rules.unlink()

    engine.execute()

    assert detector.calls == []
    assert engine.transformations.current_rendering("R1", "final").rendered_text == (
        "Code [R_ID] here."
    )
    run_files = {path.name for path in engine.context.run_dir.iterdir()}
    run_files.discard(".processing.lock")
    assert run_files == {"run.sqlite", "exports"}


def test_validation_retries_escalate_only_after_truncation_and_review_can_finalize(
    tmp_path: Path,
) -> None:
    rows = [{"record_id": "R1", "entity_id": "E1", "text": "Alice arrived."}]
    detector = FakeDetector(_name_finder)
    actions: list[object] = [
        BackendExecutionError("truncated", "too short", True, truncated=True),
        ValidationResult(
            findings=[
                ValidationFinding(
                    category=PhiCategory.NAME,
                    evidence="Alice",
                    rationale="Possible residual name.",
                    source="validator",
                )
            ],
            rationale="Residual identifier found.",
            raw_output={"findings": ["name"]},
            usage=ValidationUsage(input_chars=1, input_bytes=1, latency_ms=1),
        ),
    ]
    token_tiers: list[int] = []
    validation_calls: list[tuple[str, str]] = []

    def factory(tokens: int) -> PhiValidator:
        token_tiers.append(tokens)
        return SequenceValidator(actions.pop(0), validation_calls)

    engine = PipelineEngine.create(
        _config(tmp_path, rows, validation=True, review=True),
        dependencies=_dependencies(detector, validator_factory=factory),
        timestamp=NOW,
    )

    engine.execute()

    assert token_tiers == [4_096, 8_192]
    assert engine.store.read_run_status() == "awaiting_review"
    assert validation_calls[-1][1] == "[R_NAME] arrived."
    with engine.store.connection() as connection:
        statuses = [
            row[0]
            for row in connection.execute(
                "SELECT status FROM backend_attempts WHERE stage_name='validation' ORDER BY attempt_number"
            )
        ]
        assert statuses == ["truncated", "succeeded"]

    decision = ReviewDecision(
        decision_id=build_review_decision_id("R1", NOW),
        record_id="R1",
        basis_plan_revision=1,
        disposition="approved_unchanged",
        reviewer_id="reviewer",
        decided_at=NOW,
    )
    ReviewService(engine.store).decide(decision)
    engine.resume()

    assert engine.store.read_run_status() == "completed"
    assert engine.store.read_record("R1")["status"] == "ready"


def test_resume_recovers_interrupted_work_without_duplicate_findings(tmp_path: Path) -> None:
    rows = [{"record_id": "R1", "entity_id": "E1", "text": "Alice arrived."}]
    detector = FakeDetector(_name_finder)
    engine = PipelineEngine.create(
        _config(tmp_path, rows),
        dependencies=_dependencies(detector),
        timestamp=NOW,
    )
    detector_config = engine.context.config.detection.detectors[0]
    _DetectionStage(engine).register_detector(detector_config)
    work = engine.findings.prepare_work(
        record_id="R1",
        backend_id="sonnet_4_6",
        stage_name="detection",
        chunks=[TextChunk(0, 0, len("Alice arrived."), "Alice arrived.")],
        created_at=NOW,
    )[0]
    engine.findings.begin_attempt(work, started_at=NOW)
    engine.store.update_record_stage_state("R1", "detection", "running", updated_at=NOW)

    engine.resume()

    assert engine.store.read_run_status() == "completed"
    assert len(engine.findings.list_findings("R1")) == 1
    with engine.store.connection() as connection:
        statuses = [
            row[0]
            for row in connection.execute(
                "SELECT status FROM backend_attempts ORDER BY attempt_number"
            )
        ]
    assert statuses == ["cancelled", "succeeded"]


def test_detection_stage_remaining_failure_and_status_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [{"record_id": "R1", "entity_id": "E1", "text": "Alice arrived."}]
    config = _config(tmp_path, rows, detector_backend="aws_comprehend_medical")
    engine = PipelineEngine.create(config, dependencies=EngineDependencies(clock=lambda: NOW))
    stage = _DetectionStage(engine)
    detector_config = config.detection.detectors[0]
    sentinel = FakeDetector(_name_finder)
    monkeypatch.setattr(
        detection_module,
        "AwsComprehendMedicalPhiDetector",
        lambda **kwargs: sentinel,
    )
    assert stage.detector(detector_config) is sentinel

    bedrock_root = tmp_path / "bedrock-default"
    bedrock_root.mkdir()
    bedrock_config = _config(bedrock_root, rows)
    bedrock_stage = _DetectionStage(PipelineEngine.create(bedrock_config))
    monkeypatch.setattr(
        detection_module,
        "AwsBedrockLlmPhiDetector",
        lambda **kwargs: sentinel,
    )
    assert bedrock_stage.detector(bedrock_config.detection.detectors[0]) is sentinel

    stage.register_detector(detector_config)
    work = stage._work_items(
        record_id="R1",
        source_text="Alice arrived.",
        detector_config=detector_config,
    )[0]
    assert stage._work_items(
        record_id="R1",
        source_text="Alice arrived.",
        detector_config=detector_config,
    ) == [work]

    rules = RulesConfig(
        enabled=True,
        embedded=RulesFile(
            rules=[
                RedactionRule(
                    id="alice",
                    name="Alice",
                    category=PhiCategory.NAME,
                    type="exact",
                    pattern="Alice",
                )
            ]
        ),
    )
    stage._run_rules(["missing", "R1"], rules)
    engine.store.update_record_stage_state("R1", "detection", "succeeded", updated_at=NOW)
    monkeypatch.setattr(
        detection_module,
        "find_rule_candidates",
        lambda text, configured: (_ for _ in ()).throw(RuntimeError("rule failure")),
    )
    stage._run_rules(["R1"], rules)
    assert engine.store.read_record("R1")["status"] == "failed"

    with engine.store.connection() as connection:
        connection.execute(
            "UPDATE backend_work_items SET status = 'retry_pending' WHERE work_item_id = ?",
            (work.work_item_id,),
        )
    engine.store.update_record_stage_state("R1", "detection", "pending", updated_at=NOW)
    stage.derive_record_states([detector_config.name])
    with engine.store.read_snapshot() as connection:
        status = connection.execute(
            "SELECT status FROM record_stage_states WHERE record_id = 'R1' "
            "AND stage_name = 'detection'"
        ).fetchone()[0]
    assert status == "retry_pending"

    class SystemicDetector(PhiDetector):
        def detect(self, text: str) -> DetectionResult:
            del text
            raise BackendExecutionError("throttle", "slow", True, systemic=True)

    calls = stage.pending_calls([(detector_config, SystemicDetector())])
    assert len(calls) == 1
    with pytest.raises(BackendExecutionError, match="slow"):
        stage._process_calls(calls)
    with pytest.raises(KeyboardInterrupt):
        stage._finish_outcome(calls[0], None, KeyboardInterrupt())

    assert (
        _record_stage_status(backend_count=1, returned_count=1, statuses={"succeeded"})
        == "succeeded"
    )
    assert (
        _record_stage_status(backend_count=1, returned_count=1, statuses={"retry_pending"})
        == "retry_pending"
    )
    assert (
        _record_stage_status(backend_count=1, returned_count=1, statuses={"permanent_error"})
        == "permanent_error"
    )
    assert (
        _record_stage_status(backend_count=2, returned_count=1, statuses={"succeeded"})
        == "retry_exhausted"
    )


def test_entity_consistent_surrogates_and_structured_date_shift(tmp_path: Path) -> None:
    rows = [
        {
            "record_id": "R1",
            "entity_id": "E1",
            "text": "Alice on 01/01/2024 literal [R_NAME].",
            "service_date": "2024-01-01",
        },
        {
            "record_id": "R2",
            "entity_id": "E1",
            "text": "Alice on 01/08/2024.",
            "service_date": "2024-01-08",
        },
    ]

    def finder(text: str) -> list[DetectionCandidate]:
        result = [_candidate(text, "Alice", PhiCategory.NAME)]
        date = "01/01/2024" if "01/01/2024" in text else "01/08/2024"
        result.append(_candidate(text, date, PhiCategory.DATE))
        return result

    policy = TransformationPolicy().model_dump(mode="json")
    policy["categories"]["NAME"] = {
        "action": "surrogate",
        "surrogate": {
            "method": "faker",
            "consistency": "entity",
            "secret_reference": "name-secret",
        },
    }
    policy["categories"]["DATE"] = {
        "action": "surrogate",
        "surrogate": {
            "method": "date_shift",
            "consistency": "entity",
            "minimum_weeks": -4,
            "maximum_weeks": 4,
            "secret_reference": "date-secret",
        },
    }
    config = _config(
        tmp_path,
        rows,
        policy=policy,
        structured={"service_date": "DATE"},
    )
    engine = PipelineEngine.create(
        config,
        dependencies=_dependencies(
            FakeDetector(finder),
            secrets=MappingSecretResolver({"name-secret": "name-key", "date-secret": "date-key"}),
        ),
        timestamp=NOW,
    )

    engine.execute()

    first = engine.transformations.current_rendering("R1", "final").rendered_text
    second = engine.transformations.current_rendering("R2", "final").rendered_text
    first_name = first.split()[0]
    second_name = second.split()[0]
    assert first_name == second_name
    assert first_name not in {"Alice", "Bob"}
    assert "literal [R_NAME]" in first
    first_date = first.split(" on ")[1].split()[0]
    second_date = second.split(" on ")[1].rstrip(".")
    shifted_interval = datetime.strptime(second_date, "%m/%d/%Y") - datetime.strptime(
        first_date, "%m/%d/%Y"
    )
    assert shifted_interval.days == 7
    with engine.store.connection() as connection:
        metadata = [
            json.loads(row[0])["service_date"]
            for row in connection.execute(
                "SELECT final_metadata_json FROM records ORDER BY source_index"
            )
        ]
        assert (
            connection.execute(
                "SELECT count(*) FROM surrogate_assignments WHERE assignment_kind = 'date_shift'"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM surrogate_assignments WHERE assignment_kind = 'synthetic'"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM structured_transform_events WHERE surrogate_assignment_id IS NOT NULL"
            ).fetchone()[0]
            == 0
        )
        database_text = engine.context.database_path.read_bytes()
    assert (datetime.fromisoformat(metadata[1]) - datetime.fromisoformat(metadata[0])).days == 7
    assert b"name-key" not in database_text and b"date-key" not in database_text


def _local_config(
    root: Path,
    *,
    validation: bool = False,
    review_all: bool = False,
    structured_name: bool = False,
) -> PipelineConfig:
    root.mkdir()
    source = root / "records.jsonl"
    source.write_text(
        '{"record_id":"R1","text":"No detected PHI.","patient_name":"Alice"}\n',
        encoding="utf-8",
    )
    payload: dict[str, object] = {
        "run": {"output_dir": root / "runs"},
        "input": {
            "path": source,
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "record_id"},
            "text_column": "text",
            "metadata_columns": ["patient_name"] if structured_name else [],
            "structured_phi_columns": {"patient_name": "NAME"} if structured_name else {},
        },
        "detection": {"enabled": False},
        "validation": {"enabled": validation},
        "review": {
            "enabled": validation or review_all,
            "review_scope": "all" if review_all else "effective_validation_failures",
        },
    }
    if structured_name:
        policy = TransformationPolicy().model_dump(mode="json")
        policy["categories"]["NAME"] = {
            "action": "surrogate",
            "surrogate": {
                "method": "faker",
                "consistency": "entity",
                "secret_reference": "name-key",
            },
        }
        payload["policy"] = policy
    return PipelineConfig.model_validate(payload)


def test_structured_faker_and_stage_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    structured = PipelineEngine.create(
        _local_config(tmp_path / "structured", structured_name=True),
        dependencies=EngineDependencies(
            secrets=MappingSecretResolver({"name-key": "secret"}),
            clock=lambda: NOW,
        ),
    )
    structured.execute()
    final_metadata = json.loads(str(structured.store.read_record("R1")["final_metadata_json"]))
    assert final_metadata["patient_name"] != "Alice"

    transformation = PipelineEngine.create(_local_config(tmp_path / "transformation"))
    transformation.run_detection()
    monkeypatch.setattr(
        _TransformationStage,
        "_create_draft_rendering",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("transform failed")),
    )
    transformation.run_transformation()
    assert transformation.store.read_record("R1")["status"] == "failed"

    monkeypatch.undo()
    finalization = PipelineEngine.create(_local_config(tmp_path / "finalization"))
    monkeypatch.setattr(
        _FinalizationStage,
        "_finalize_record",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("final failed")),
    )
    finalization.execute()
    assert finalization.store.read_record("R1")["status"] == "failed"


def test_finalization_waits_for_review_or_validation_result(tmp_path: Path) -> None:
    review_engine = PipelineEngine.create(_local_config(tmp_path / "review", review_all=True))
    review_engine.execute()
    service = ReviewService(review_engine.store)
    service.decide(
        ReviewDecision(
            decision_id="exclude-r1",
            record_id="R1",
            basis_plan_revision=service.record("R1").plan_revision,
            disposition="excluded",
            reviewer_id="reviewer",
            decided_at=NOW,
        )
    )
    assert not _FinalizationStage(review_engine).record_ready("R1")

    validation_engine = PipelineEngine.create(
        _local_config(tmp_path / "validation", validation=True)
    )
    validation_engine.run_detection()
    validation_engine.run_transformation()
    assert not _FinalizationStage(validation_engine).record_ready("R1")


def test_validation_stage_remaining_blocked_failure_and_systemic_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocked_engine = PipelineEngine.create(
        _local_config(tmp_path / "blocked-validation", validation=True)
    )
    blocked_stage = _ValidationStage(blocked_engine)
    assert blocked_stage.pending_calls("validator") == []
    with blocked_engine.store.read_snapshot() as connection:
        status = connection.execute(
            "SELECT status FROM record_stage_states WHERE record_id = 'R1' "
            "AND stage_name = 'validation'"
        ).fetchone()[0]
    assert status == "blocked"

    sentinel = SequenceValidator(_no_findings(), [])
    monkeypatch.setattr(
        validation_module,
        "AwsBedrockSafeguardValidator",
        lambda **kwargs: sentinel,
    )
    assert blocked_stage.validator(4_096) is sentinel

    terminal = PipelineEngine.create(_local_config(tmp_path / "terminal", validation=True))
    terminal.run_detection()
    terminal.run_transformation()
    terminal_stage = _ValidationStage(terminal)
    terminal_stage._register_backend()
    calls = terminal_stage.pending_calls("validator")
    terminal.dependencies.validator_factory = lambda tokens: SequenceValidator(
        BackendExecutionError("invalid", "invalid response", False), []
    )
    terminal_stage._process_calls(calls)
    assert terminal.store.read_record("R1")["status"] == "failed"
    terminal.store.update_record_stage_state("R1", "validation", "pending", updated_at=NOW)
    assert terminal_stage.pending_calls("validator") == []
    with pytest.raises(SystemExit):
        terminal_stage._finish_outcome(calls[0], None, SystemExit())

    systemic = PipelineEngine.create(_local_config(tmp_path / "systemic", validation=True))
    systemic.run_detection()
    systemic.run_transformation()
    systemic_stage = _ValidationStage(systemic)
    systemic_stage._register_backend()
    systemic_calls = systemic_stage.pending_calls("validator")
    systemic.dependencies.validator_factory = lambda tokens: SequenceValidator(
        BackendExecutionError("throttle", "slow validator", True, systemic=True), []
    )
    with pytest.raises(BackendExecutionError, match="slow validator"):
        systemic_stage._process_calls(systemic_calls)

    no_review = PipelineEngine.create(_local_config(tmp_path / "no-review"))
    no_review_stage = _ValidationStage(no_review)
    no_review.store.update_record_stage_state("R1", "review", "pending", updated_at=NOW)
    no_review_stage.prepare_unvalidated_review()
    with no_review.store.read_snapshot() as connection:
        assert (
            connection.execute(
                "SELECT status FROM record_stage_states WHERE record_id = 'R1' "
                "AND stage_name = 'review'"
            ).fetchone()[0]
            == "skipped"
        )
