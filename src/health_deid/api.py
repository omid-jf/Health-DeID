"""Python API for creating, processing, revising, and exporting runs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from health_deid.models.config import PipelineConfig, load_config
from health_deid.models.export import ExportFormat, ExportMode, ExportRequest, ExportResult
from health_deid.models.ledger import StageName
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.control import RetryResult, RunControlService
from health_deid.pipeline.engine import EngineDependencies, PipelineEngine
from health_deid.pipeline.exports import ExportService
from health_deid.pipeline.precheck import PrecheckResult, precheck_config
from health_deid.pipeline.reporting import LiveReportService
from health_deid.pipeline.revision import create_revised_run_context


class _UiLauncher(Protocol):
    def __call__(
        self,
        run_path: str | Path | None,
        *,
        reviewer_id: str,
        runs_dir: Path,
        host: str,
        port: int,
        open_browser: bool,
        reload: bool,
        dependencies: EngineDependencies | None,
    ) -> None: ...


@dataclass(slots=True)
class _ApiDependencies:
    engine: EngineDependencies = field(default_factory=EngineDependencies)
    ui_launcher: _UiLauncher | None = None


class PrecheckError(ValueError):
    def __init__(self, result: PrecheckResult) -> None:
        self.result = result
        super().__init__(
            "Run precheck failed: " + "; ".join(issue.message for issue in result.errors)
        )


class RunHandle:
    """One durable local de-identification run."""

    def __init__(
        self,
        engine: PipelineEngine,
        *,
        _dependencies: _ApiDependencies | None = None,
    ) -> None:
        self._engine = engine
        self._dependencies = _dependencies or _ApiDependencies(engine=engine.dependencies)
        self._control = RunControlService(engine.store)
        self._exports = ExportService(engine.store)
        self._reports = LiveReportService(engine.store)

    @property
    def context(self) -> RunContext:
        return self._engine.context

    @property
    def run_id(self) -> str:
        return self.context.run_id

    @property
    def run_dir(self) -> Path:
        return self.context.run_dir

    @property
    def database_path(self) -> Path:
        return self.context.database_path

    def execute(self) -> RunHandle:
        """Process every pending stage."""

        self._engine.execute()
        return self

    def resume(self) -> RunHandle:
        self._engine.resume()
        return self

    def status(self) -> dict[str, Any]:
        return self._reports.build()

    def precheck(self) -> PrecheckResult:
        return _precheck(self.context.config, self._dependencies)

    def retry(
        self,
        *,
        stage: StageName | None = None,
        failed: bool = False,
        record_id: str | None = None,
        resume: bool = True,
    ) -> RetryResult:
        result = self._control.retry(stage=stage, failed=failed, record_id=record_id)
        if resume:
            self._engine.resume()
        return result

    def revise(
        self,
        config: PipelineConfig | Mapping[str, Any] | str | Path,
        *,
        reason: str,
        execute: bool = True,
        rerun_detection: bool = False,
        created_at: datetime | None = None,
    ) -> RunHandle:
        """Create a revised run; reuse matching detector results and rerun everything else."""

        resolved = _resolve_config(config)
        context = create_revised_run_context(
            self.run_dir,
            resolved,
            timestamp=created_at,
            secret_resolver=self._dependencies.engine.secrets,
            reason=reason,
            rerun_detection=rerun_detection,
        )
        revised = RunHandle(
            PipelineEngine(context, dependencies=self._dependencies.engine),
            _dependencies=self._dependencies,
        )
        return revised.execute() if execute else revised

    def export(
        self,
        request: ExportRequest | None = None,
        *,
        output_path: str | Path | None = None,
        format: ExportFormat = "parquet",
        mode: ExportMode = "ready_only",
        selected_columns: list[str] | None = None,
    ) -> ExportResult:
        if request is not None and (
            output_path is not None
            or selected_columns is not None
            or format != "parquet"
            or mode != "ready_only"
        ):
            raise ValueError("Pass an ExportRequest or export keyword arguments, not both.")
        if request is None:
            destination = (
                Path(output_path) if output_path else self.context.exports_dir / f"final.{format}"
            )
            request = ExportRequest(
                output_path=destination,
                format=format,
                mode=mode,
                **({"selected_columns": selected_columns} if selected_columns is not None else {}),
            )
        return self._exports.export(request)

    def ui(
        self,
        *,
        reviewer_id: str,
        runs_dir: str | Path | None = None,
        host: str = "127.0.0.1",
        port: int = 5000,
        open_browser: bool = True,
        reload: bool = False,
    ) -> None:
        launcher = self._dependencies.ui_launcher or _default_ui_launcher
        launcher(
            self.run_dir,
            reviewer_id=reviewer_id,
            runs_dir=Path(runs_dir or self.context.config.run.output_dir),
            host=host,
            port=port,
            open_browser=open_browser,
            reload=reload,
            dependencies=self._dependencies.engine,
        )


def create_run(
    config: PipelineConfig | Mapping[str, Any] | str | Path,
    *,
    timestamp: datetime | None = None,
    check_precheck: bool = True,
    _dependencies: _ApiDependencies | EngineDependencies | None = None,
) -> RunHandle:
    """Create and import a run without starting paid processing."""

    resolved = _resolve_config(config)
    dependencies = _normalize_dependencies(_dependencies)
    if check_precheck:
        result = _precheck(resolved, dependencies)
        if not result.ok:
            raise PrecheckError(result)
    engine = PipelineEngine.create(
        resolved,
        dependencies=dependencies.engine,
        timestamp=timestamp,
    )
    return RunHandle(engine, _dependencies=dependencies)


def open_run(
    run_path: str | Path,
    *,
    _dependencies: _ApiDependencies | EngineDependencies | None = None,
) -> RunHandle:
    dependencies = _normalize_dependencies(_dependencies)
    engine = PipelineEngine(
        RunContext.from_run_path(run_path),
        dependencies=dependencies.engine,
    )
    return RunHandle(engine, _dependencies=dependencies)


def run(
    config: PipelineConfig | Mapping[str, Any] | str | Path,
    *,
    timestamp: datetime | None = None,
    _dependencies: _ApiDependencies | EngineDependencies | None = None,
) -> RunHandle:
    """Create and execute a run."""

    return create_run(config, timestamp=timestamp, _dependencies=_dependencies).execute()


def precheck(
    config: PipelineConfig | Mapping[str, Any] | str | Path,
    *,
    _dependencies: _ApiDependencies | EngineDependencies | None = None,
) -> PrecheckResult:
    """Validate setup and estimate pre-run AWS cost."""

    dependencies = _normalize_dependencies(_dependencies)
    return _precheck(_resolve_config(config), dependencies)


def launch_ui(
    run_path: str | Path | None = None,
    *,
    reviewer_id: str,
    runs_dir: str | Path = "runs",
    host: str = "127.0.0.1",
    port: int = 5000,
    open_browser: bool = True,
    reload: bool = False,
    _dependencies: _ApiDependencies | EngineDependencies | None = None,
) -> None:
    dependencies = _normalize_dependencies(_dependencies)
    launcher = dependencies.ui_launcher or _default_ui_launcher
    launcher(
        run_path,
        reviewer_id=reviewer_id,
        runs_dir=Path(runs_dir),
        host=host,
        port=port,
        open_browser=open_browser,
        reload=reload,
        dependencies=dependencies.engine,
    )


def _resolve_config(source: PipelineConfig | Mapping[str, Any] | str | Path) -> PipelineConfig:
    if isinstance(source, PipelineConfig):
        return source
    if isinstance(source, Mapping):
        return PipelineConfig.model_validate(dict(source))
    return load_config(source)


def _normalize_dependencies(
    dependencies: _ApiDependencies | EngineDependencies | None,
) -> _ApiDependencies:
    if dependencies is None:
        return _ApiDependencies()
    if isinstance(dependencies, EngineDependencies):
        return _ApiDependencies(engine=dependencies)
    return dependencies


def _precheck(config: PipelineConfig, dependencies: _ApiDependencies) -> PrecheckResult:
    return precheck_config(config, secret_resolver=dependencies.engine.secrets)


def _default_ui_launcher(
    run_path: str | Path | None,
    *,
    reviewer_id: str,
    runs_dir: Path,
    host: str,
    port: int,
    open_browser: bool,
    reload: bool,
    dependencies: EngineDependencies | None,
) -> None:
    from health_deid.ui import run_ui_app

    run_ui_app(
        run_path,
        host=host,
        port=port,
        open_browser=open_browser,
        reload=reload,
        dependencies=dependencies,
        reviewer_id=reviewer_id,
        runs_dir=runs_dir,
    )


__all__ = [
    "PrecheckError",
    "PrecheckResult",
    "RetryResult",
    "RunHandle",
    "create_run",
    "launch_ui",
    "open_run",
    "precheck",
    "run",
]
