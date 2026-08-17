from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import health_deid.pipeline.revision as revision_module
from health_deid.api import RunHandle, _ApiDependencies
from health_deid.backends.contracts import PhiDetector
from health_deid.core.secret_refs import MappingSecretResolver
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import BackendUsage, DetectionCandidate, DetectionResult
from health_deid.models.config import PipelineConfig
from health_deid.pipeline.engine import EngineDependencies, PipelineEngine
from health_deid.pipeline.revision import (
    _utc_text,
    create_revised_run_context,
    plan_revised_run,
)
from health_deid.storage.database import SqliteRunStore

NOW = datetime(2026, 7, 31, 15, 0, tzinfo=UTC)


class TrackingDetector(PhiDetector):
    def __init__(self) -> None:
        self.calls: list[str] = []

    def detect(self, text: str) -> DetectionResult:
        self.calls.append(text)
        start = text.find("Alice")
        candidates = []
        if start >= 0:
            candidates.append(
                DetectionCandidate(
                    backend_span_id="name-1",
                    category=PhiCategory.NAME,
                    native_category="NAME",
                    text="Alice",
                    start_char=start,
                    end_char=start + 5,
                    confidence=0.99,
                )
            )
        return DetectionResult(
            candidates=candidates,
            raw_output={"text": text},
            model_version="test-v1",
            usage=BackendUsage(
                input_chars=len(text),
                input_bytes=len(text.encode()),
                latency_ms=1,
                cost_usd=0.01,
            ),
        )


def _source(tmp_path: Path) -> Path:
    path = tmp_path / "source.jsonl"
    path.write_text(
        '{"record_id":"R1","entity_id":"E1","text":"Alice called 555-0100.",'
        '"site":"north"}\n'
        '{"record_id":"R2","entity_id":"E2","text":"   ","site":"south"}\n',
        encoding="utf-8",
    )
    return path


def _config(tmp_path: Path, *, detection: bool = True) -> PipelineConfig:
    payload: dict[str, object] = {
        "run": {"name": "parent", "output_dir": tmp_path / "runs"},
        "input": {
            "path": _source(tmp_path),
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "column", "column": "entity_id"},
            "text_column": "text",
            "metadata_columns": ["site"],
        },
        "detection": {"enabled": False},
    }
    if detection:
        payload["detection"] = {
            "detectors": [
                {
                    "backend": "aws_bedrock",
                    "model_id": "us.anthropic.claude-sonnet-4-6",
                    "input_cost_per_million_tokens": 1.0,
                    "output_cost_per_million_tokens": 2.0,
                }
            ],
            "execution": {"workers": 1},
        }
    return PipelineConfig.model_validate(payload)


def _parent(tmp_path: Path) -> tuple[PipelineEngine, TrackingDetector, EngineDependencies]:
    detector = TrackingDetector()
    dependencies = EngineDependencies(
        detectors={"sonnet_4_6": detector},
        secrets=MappingSecretResolver({"faker-key": "secret"}),
        clock=lambda: NOW,
    )
    engine = PipelineEngine.create(_config(tmp_path), dependencies=dependencies, timestamp=NOW)
    engine.execute()
    return engine, detector, dependencies


def _revised_config(parent: PipelineConfig, *, name: str = "revised") -> PipelineConfig:
    payload = parent.model_dump(mode="python")
    payload["run"] = {"name": name, "output_dir": parent.run.output_dir}
    payload["policy"]["categories"][PhiCategory.NAME] = {"action": "retain"}
    return PipelineConfig.model_validate(payload)


def test_revised_run_reuses_paid_detection_and_reruns_rules_and_output(tmp_path: Path) -> None:
    parent, detector, dependencies = _parent(tmp_path)
    assert detector.calls == ["Alice called 555-0100."]
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - id: phone\n"
        "    name: Phone\n"
        "    category: PHONE_OR_FAX\n"
        "    pattern: '555-[0-9]{4}'\n",
        encoding="utf-8",
    )
    payload = _revised_config(parent.context.config).model_dump(mode="python")
    payload["rules"] = {"enabled": True, "rules_path": rules}
    revised_config = PipelineConfig.model_validate(payload)

    plan = plan_revised_run(parent.store, revised_config)
    assert plan.detection == "reuse"
    assert not plan.requires_paid_detection
    context = create_revised_run_context(
        parent.context.run_dir,
        revised_config,
        timestamp=NOW + timedelta(minutes=1),
        secret_resolver=dependencies.secrets,
        reason="retain names and add phone rule",
    )
    rules.unlink()
    child = PipelineEngine(context, dependencies=dependencies)
    child.execute()

    assert detector.calls == ["Alice called 555-0100."]
    assert child.context.config.rules.embedded is not None
    assert child.transformations.current_rendering("R1", "final").rendered_text == (
        "Alice called [R_PHONE_OR_FAX]."
    )
    assert child.store.read_record("R2")["status"] == "excluded"
    with child.store.read_snapshot() as connection:
        reuse = json.loads(connection.execute("SELECT reuse_json FROM runs").fetchone()[0])
        counts = connection.execute(
            "SELECT count(*), count(DISTINCT backend_attempt_id) FROM findings"
        ).fetchone()
    assert reuse["parent_run_id"] == parent.context.run_id
    assert reuse["detection"] == "reuse"
    assert reuse["reused_backends"] == 1
    assert counts[0] == 2


def test_pricing_changes_do_not_force_redetection_but_behavior_changes_do(tmp_path: Path) -> None:
    parent, _, _ = _parent(tmp_path)
    payload = _revised_config(parent.context.config).model_dump(mode="python")
    detector = payload["detection"]["detectors"][0]
    detector["input_cost_per_million_tokens"] = 99.0
    detector["output_cost_per_million_tokens"] = 100.0
    pricing = PipelineConfig.model_validate(payload)
    assert plan_revised_run(parent.store, pricing).detection == "reuse"

    detector["min_confidence"] = 0.5
    changed = PipelineConfig.model_validate(payload)
    plan = plan_revised_run(parent.store, changed)
    assert plan.detection == "rerun"
    assert plan.requires_paid_detection
    with pytest.raises(ValueError, match="approve it explicitly"):
        create_revised_run_context(parent.context.run_dir, changed, reason="new threshold")

    context = create_revised_run_context(
        parent.context.run_dir,
        changed,
        timestamp=NOW + timedelta(minutes=2),
        secret_resolver=MappingSecretResolver({}),
        reason="new threshold",
        rerun_detection=True,
    )
    store = SqliteRunStore.open(context.database_path)
    assert store.read_stage_status("detection") == "pending"
    with store.read_snapshot() as connection:
        reuse = json.loads(connection.execute("SELECT reuse_json FROM runs").fetchone()[0])
    assert reuse["detection"] == "rerun"
    assert reuse["reused_attempts"] == 0


def test_revision_contracts_and_disabled_detection(tmp_path: Path) -> None:
    parent, _, _ = _parent(tmp_path)
    disabled_payload = _revised_config(parent.context.config).model_dump(mode="python")
    disabled_payload["detection"] = {"enabled": False}
    disabled = PipelineConfig.model_validate(disabled_payload)
    assert plan_revised_run(parent.context.run_dir, disabled).detection == "skip"
    skipped = create_revised_run_context(
        parent.context.run_dir,
        disabled,
        timestamp=NOW + timedelta(minutes=3),
        reason="rules only",
    )
    assert SqliteRunStore.open(skipped.database_path).read_stage_status("detection") == "pending"

    changed_input = _revised_config(parent.context.config).model_dump(mode="python")
    changed_input["input"]["text_column"] = "different"
    with pytest.raises(ValueError, match="must keep record IDs"):
        plan_revised_run(parent.store, PipelineConfig.model_validate(changed_input))

    wrong_parent = _revised_config(parent.context.config).model_dump(mode="python")
    wrong_parent["run"]["parent_run_id"] = "another-run"
    with pytest.raises(ValueError, match="different parent"):
        create_revised_run_context(
            parent.context.run_dir,
            PipelineConfig.model_validate(wrong_parent),
            reason="invalid parent",
        )
    with pytest.raises(ValueError, match="cannot be blank"):
        create_revised_run_context(parent.context.run_dir, reason=" ")
    with pytest.raises(ValueError, match="timezone-aware"):
        _utc_text(datetime(2026, 1, 1))


def test_incomplete_or_absent_parent_detector_ledger_requires_rerun(tmp_path: Path) -> None:
    parent, _, _ = _parent(tmp_path)
    with parent.store.connection() as connection:
        connection.execute("UPDATE backend_work_items SET status = 'permanent_error'")
    revised = _revised_config(parent.context.config)
    assert "complete successful" in plan_revised_run(parent.store, revised).reason

    no_detection_root = tmp_path / "no-detection"
    no_detection_root.mkdir()
    config = _config(no_detection_root, detection=False)
    engine = PipelineEngine.create(config, timestamp=NOW)
    plan = plan_revised_run(engine.store, config)
    assert plan.detection == "skip"

    enabled = _config(no_detection_root, detection=True)
    parent_without_detection = plan_revised_run(engine.store, enabled)
    assert parent_without_detection.detection == "rerun"
    assert "parent did not use paid detectors" in parent_without_detection.reason


def test_revision_precheck_and_partial_child_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent, _, _ = _parent(tmp_path)
    payload = _revised_config(parent.context.config).model_dump(mode="python")
    payload["policy"]["categories"][PhiCategory.NAME] = {
        "action": "surrogate",
        "surrogate": {
            "method": "faker",
            "consistency": "entity",
            "secret_reference": "missing-secret",
        },
    }
    missing_secret = PipelineConfig.model_validate(payload)
    with pytest.raises(ValueError, match="precheck failed"):
        create_revised_run_context(
            parent.context.run_dir,
            missing_secret,
            timestamp=NOW + timedelta(minutes=10),
            secret_resolver=MappingSecretResolver({}),
            reason="missing secret",
        )

    def fail_create(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("cannot create child database")

    monkeypatch.setattr(revision_module.SqliteRunStore, "create", fail_create)
    child_time = NOW + timedelta(minutes=11)
    with pytest.raises(RuntimeError, match="cannot create child"):
        create_revised_run_context(
            parent.context.run_dir,
            _revised_config(parent.context.config, name="cleanup"),
            timestamp=child_time,
            reason="test cleanup",
        )
    expected = parent.context.config.run.output_dir / f"{child_time:%Y%m%dT%H%M%S}_cleanup"
    assert not expected.exists()


def test_run_handle_revise_returns_a_child_and_can_defer_execution(tmp_path: Path) -> None:
    parent, detector, dependencies = _parent(tmp_path)
    handle = RunHandle(
        parent,
        _dependencies=_ApiDependencies(engine=dependencies),
    )
    revised = handle.revise(
        _revised_config(parent.context.config),
        reason="retain names",
        execute=False,
        created_at=NOW + timedelta(minutes=4),
    )

    assert revised.run_id != handle.run_id
    assert revised.context.config.run.parent_run_id == handle.run_id
    assert revised.status()["run"]["status"] == "initialized"
    revised.execute()
    assert revised.status()["run"]["status"] == "completed"
    assert detector.calls == ["Alice called 555-0100."]
