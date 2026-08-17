from __future__ import annotations

import tomllib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml

import health_deid.api as public_api
from health_deid import __version__
from health_deid.api import PrecheckError, RunHandle, _ApiDependencies
from health_deid.models.config import PipelineConfig
from health_deid.models.export import ExportRequest, ExportResult
from health_deid.pipeline.control import RetryResult
from health_deid.pipeline.engine import EngineDependencies
from health_deid.pipeline.precheck import PrecheckIssue, PrecheckResult


def test_release_versions_match() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    citation = yaml.safe_load(Path("CITATION.cff").read_text(encoding="utf-8"))

    assert project["project"]["version"] == __version__ == citation["version"]


class FakeEngine:
    def __init__(self, tmp_path: Path) -> None:
        self.context = SimpleNamespace(
            run_id="run-1",
            run_dir=tmp_path / "run-1",
            database_path=tmp_path / "run-1" / "run.sqlite",
            exports_dir=tmp_path / "run-1" / "exports",
            config=SimpleNamespace(run=SimpleNamespace(output_dir=tmp_path / "runs")),
        )
        self.store = object()
        self.dependencies = EngineDependencies()
        self.calls: list[str] = []

    def execute(self) -> object:
        self.calls.append("execute")
        return self.context

    def resume(self) -> object:
        self.calls.append("resume")
        return self.context


class FakeControl:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def retry(self, **kwargs) -> RetryResult:
        self.calls.append(kwargs)
        return RetryResult(
            ("record-1",), ("validation", "review", "transformation", "finalization", "export")
        )


class FakeReports:
    def build(self) -> dict[str, Any]:
        return {"run": {"run_id": "run-1", "status": "completed"}}


class FakeExports:
    def __init__(self) -> None:
        self.requests: list[ExportRequest] = []

    def export(self, request: ExportRequest) -> ExportResult:
        self.requests.append(request)
        timestamp = datetime(2026, 7, 31, tzinfo=UTC)
        return ExportResult(
            export_id="export-1",
            output_path=request.output_path,
            format=request.format,
            mode=request.mode,
            selected_columns=request.selected_columns,
            record_count=1,
            output_sha256="a" * 64,
            created_at=timestamp,
            finished_at=timestamp,
        )


def _handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RunHandle, FakeEngine, FakeControl, FakeExports, list[dict[str, object]]]:
    engine = FakeEngine(tmp_path)
    control = FakeControl()
    exports = FakeExports()
    ui_calls: list[dict[str, object]] = []

    def launch(run_path=None, **kwargs) -> None:
        ui_calls.append({"run_path": run_path, **kwargs})

    monkeypatch.setattr(public_api, "RunControlService", lambda store: control)
    monkeypatch.setattr(public_api, "ExportService", lambda store: exports)
    monkeypatch.setattr(public_api, "LiveReportService", lambda store: FakeReports())
    dependencies = _ApiDependencies(engine=engine.dependencies, ui_launcher=launch)
    handle = RunHandle(cast(Any, engine), _dependencies=dependencies)
    return handle, engine, control, exports, ui_calls


def test_run_handle_delegates_all_public_operations(tmp_path: Path, monkeypatch) -> None:
    handle, engine, control, exports, ui_calls = _handle(tmp_path, monkeypatch)
    monkeypatch.setattr(
        public_api,
        "_precheck",
        lambda config, dependencies: PrecheckResult(
            (PrecheckIssue("info", "ready", "ready"),), record_count=1
        ),
    )

    assert handle.run_id == "run-1"
    assert handle.run_dir == tmp_path / "run-1"
    assert handle.database_path.name == "run.sqlite"
    assert handle.execute() is handle
    assert handle.resume() is handle
    assert engine.calls == ["execute", "resume"]
    assert handle.status()["run"]["status"] == "completed"
    assert handle.precheck().ok

    retried = handle.retry(stage="validation", failed=True)
    assert retried.record_count == 1
    assert engine.calls[-1] == "resume"
    handle.retry(record_id="record-1", resume=False)
    assert len(control.calls) == 2

    result = handle.export(format="jsonl", mode="all_records")
    assert result.output_path == tmp_path / "run-1" / "exports" / "final.jsonl"
    selected = handle.export(
        output_path=tmp_path / "selected.parquet",
        selected_columns=["final_text"],
    )
    assert selected.selected_columns == ["final_text"]
    explicit = ExportRequest(output_path=tmp_path / "chosen.parquet")
    assert handle.export(explicit).output_path == explicit.output_path
    with pytest.raises(ValueError, match="ExportRequest or export keyword"):
        handle.export(explicit, output_path=tmp_path / "other.parquet")
    assert len(exports.requests) == 3

    handle.ui(reviewer_id="Dr Test", port=5001, open_browser=False)
    assert ui_calls[0]["run_path"] == tmp_path / "run-1"
    assert ui_calls[0]["port"] == 5001
    assert ui_calls[0]["reviewer_id"] == "Dr Test"


def test_create_open_run_and_precheck_dependency_normalization(tmp_path: Path, monkeypatch) -> None:
    config = PipelineConfig.model_validate(
        {
            "input": {
                "path": tmp_path / "input.jsonl",
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
            }
        }
    )
    engine = FakeEngine(tmp_path)
    created: list[tuple[object, object, object]] = []

    class FakePipelineEngine:
        @classmethod
        def create(cls, supplied, *, dependencies, timestamp):
            created.append((supplied, dependencies, timestamp))
            return engine

        def __new__(cls, context, *, dependencies):
            engine.context = context
            engine.dependencies = dependencies
            return engine

    context = engine.context
    monkeypatch.setattr(public_api, "PipelineEngine", FakePipelineEngine)
    monkeypatch.setattr(
        public_api.RunContext,
        "from_run_path",
        classmethod(lambda cls, path: context),
    )
    monkeypatch.setattr(
        public_api,
        "_precheck",
        lambda supplied, dependencies: PrecheckResult((), record_count=1),
    )
    dependencies = EngineDependencies()

    created_handle = public_api.create_run(
        cast(Any, config),
        _dependencies=dependencies,
        timestamp=datetime(2026, 7, 31, tzinfo=UTC),
    )
    assert created_handle.run_id == "run-1"
    assert created[0][0] is config
    assert created[0][1] is dependencies
    assert public_api.open_run(tmp_path, _dependencies=dependencies).run_id == "run-1"
    assert public_api.run(cast(Any, config), _dependencies=_ApiDependencies()).run_id == "run-1"

    monkeypatch.setattr(public_api, "load_config", lambda path: config)
    assert public_api.precheck(tmp_path / "config.yaml").ok
    public_api.create_run(tmp_path / "config.yaml", check_precheck=False)


def test_create_run_rejects_failed_precheck(tmp_path: Path, monkeypatch) -> None:
    result = PrecheckResult((PrecheckIssue("error", "bad", "configuration is invalid"),))
    monkeypatch.setattr(public_api, "_precheck", lambda config, dependencies: result)
    config = {
        "input": {
            "path": tmp_path / "input.jsonl",
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "record_id"},
            "text_column": "text",
        }
    }
    with pytest.raises(PrecheckError, match="configuration is invalid") as caught:
        public_api.create_run(config)
    assert caught.value.result is result


def test_launch_ui_supports_injected_and_default_launchers(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[object, dict[str, object]]] = []

    def injected(run_path=None, **kwargs) -> None:
        calls.append((run_path, kwargs))

    public_api.launch_ui(
        tmp_path,
        reviewer_id="Dr Test",
        _dependencies=_ApiDependencies(ui_launcher=injected),
        open_browser=False,
    )
    assert calls[0][0] == tmp_path

    import health_deid.ui

    monkeypatch.setattr(
        health_deid.ui,
        "run_ui_app",
        lambda run_path=None, **kwargs: calls.append((run_path, kwargs)),
    )
    public_api.launch_ui(None, reviewer_id="Dr Test", port=5002)
    assert calls[-1][1]["port"] == 5002


def test_precheck_delegates_injected_engine_dependencies(monkeypatch) -> None:
    expected = PrecheckResult((), record_count=3)
    observed: dict[str, object] = {}

    def fake_precheck(config, *, secret_resolver):
        observed.update(
            config=config,
            secret_resolver=secret_resolver,
        )
        return expected

    dependencies = _ApiDependencies()
    monkeypatch.setattr(public_api, "precheck_config", fake_precheck)
    config = cast(Any, object())
    assert public_api._precheck(config, dependencies) is expected
    assert observed["config"] is config
    assert observed["secret_resolver"] is dependencies.engine.secrets
