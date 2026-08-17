"""Optional local web interface."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from health_deid.pipeline.engine import EngineDependencies


def create_ui_app(
    run_path: str | Path | None = None,
    *,
    secret_key: str | None = None,
    dependencies: EngineDependencies | None = None,
    temp_root: str | Path | None = None,
    reviewer_id: str,
    runs_dir: str | Path = "runs",
) -> Any:
    from health_deid.ui.app import create_ui_app as factory

    return factory(
        run_path,
        secret_key=secret_key,
        dependencies=dependencies,
        temp_root=temp_root,
        reviewer_id=reviewer_id,
        runs_dir=runs_dir,
    )


def run_ui_app(
    run_path: str | Path | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 5000,
    open_browser: bool = True,
    reload: bool = False,
    dependencies: EngineDependencies | None = None,
    reviewer_id: str,
    runs_dir: str | Path = "runs",
) -> None:
    from health_deid.ui.app import run_ui_app as runner

    runner(
        run_path,
        host=host,
        port=port,
        open_browser=open_browser,
        reload=reload,
        dependencies=dependencies,
        reviewer_id=reviewer_id,
        runs_dir=runs_dir,
    )


__all__ = ["create_ui_app", "run_ui_app"]
