from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, cast

import typer

from health_deid import __version__
from health_deid.api import create_run, launch_ui, open_run, precheck


class ExportFormatOption(StrEnum):
    PARQUET = "parquet"
    JSONL = "jsonl"


class ExportModeOption(StrEnum):
    READY_ONLY = "ready_only"
    ALL_RECORDS = "all_records"


class StageOption(StrEnum):
    INPUT = "input"
    DETECTION = "detection"
    TRANSFORMATION = "transformation"
    VALIDATION = "validation"
    REVIEW = "review"
    FINALIZATION = "finalization"
    EXPORT = "export"


app = typer.Typer(
    name="health-deid",
    help="Auditable, resumable de-identification for medical text.",
    no_args_is_help=True,
    invoke_without_command=True,
)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the installed version and exit.", is_eager=True),
    ] = False,
) -> None:
    if version:
        typer.echo(f"Health-DeID {__version__}")
        raise typer.Exit()


@app.command()
def ui(
    reviewer: Annotated[str, typer.Option("--reviewer", help="Reviewer name.")],
    run_path: Annotated[
        Path | None,
        typer.Argument(help="Optional run directory or run.sqlite file."),
    ] = None,
    runs_dir: Annotated[
        Path,
        typer.Option("--runs-dir", help="Directory used by the local UI."),
    ] = Path("runs"),
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65_535)] = 5000,
    open_browser: Annotated[bool, typer.Option("--open-browser/--no-open-browser")] = True,
    reload: Annotated[bool, typer.Option("--reload/--no-reload")] = False,
) -> None:
    """Launch the local desktop UI."""

    _call(
        launch_ui,
        run_path,
        reviewer_id=reviewer,
        runs_dir=runs_dir,
        host=host,
        port=port,
        open_browser=open_browser,
        reload=reload,
    )


@app.command()
def check(
    config_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate configuration and show the precheck cost estimate."""

    try:
        result = precheck(config_path)
        payload = result.as_dict()
        typer.echo(
            json.dumps(payload, indent=2, default=str) if as_json else _precheck_text(payload)
        )
        if not result.ok:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as error:
        _fail(error)


@app.command()
def run(
    config_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
) -> None:
    """Precheck, create, and process a new run."""

    try:
        result = precheck(config_path)
        typer.echo(_precheck_text(result.as_dict()))
        if not result.ok:
            raise ValueError("Precheck found blocking errors.")
        handle = create_run(config_path, check_precheck=False).execute()
        typer.echo(_status_text(handle.status(), handle.run_dir))
    except Exception as error:
        _fail(error)


@app.command()
def status(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    as_json: Annotated[bool, typer.Option("--json")] = False,
    show_errors: Annotated[bool, typer.Option("--errors")] = False,
) -> None:
    """Show current progress, usage, cost, and errors."""

    try:
        handle = open_run(run_path)
        report = handle.status()
        if as_json:
            typer.echo(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        else:
            typer.echo(_status_text(report, handle.run_dir, show_errors=show_errors))
    except Exception as error:
        _fail(error)


@app.command()
def resume(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
) -> None:
    """Recover interrupted work and continue processing."""

    try:
        handle = open_run(run_path).resume()
        typer.echo(_status_text(handle.status(), handle.run_dir))
    except Exception as error:
        _fail(error)


@app.command()
def retry(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    stage: Annotated[StageOption | None, typer.Option()] = None,
    failed: Annotated[bool, typer.Option("--failed")] = False,
    record_id: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Reset selected failed work and resume."""

    try:
        handle = open_run(run_path)
        result = handle.retry(
            stage=stage.value if stage else None,
            failed=failed,
            record_id=record_id,
        )
        typer.echo(f"Retried {result.record_count} record(s): {', '.join(result.stages)}")
        typer.echo(_status_text(handle.status(), handle.run_dir))
    except Exception as error:
        _fail(error)


@app.command()
def revise(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    config_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    reason: Annotated[str, typer.Option("--reason")],
    execute: Annotated[bool, typer.Option("--execute/--no-execute")] = True,
    rerun_detection: Annotated[bool, typer.Option("--rerun-detection")] = False,
) -> None:
    """Create a revised run and reuse matching paid detector results."""

    try:
        parent = open_run(run_path)
        revised = parent.revise(
            config_path,
            reason=reason,
            execute=execute,
            rerun_detection=rerun_detection,
        )
        typer.secho(f"Created revised run {revised.run_id}.", fg=typer.colors.GREEN)
        if execute:
            typer.echo(_status_text(revised.status(), revised.run_dir))
        else:
            typer.echo(f"Next: health-deid resume {revised.run_dir}")
    except Exception as error:
        _fail(error)


@app.command()
def export(
    run_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    output_path: Annotated[Path, typer.Argument()],
    format: Annotated[ExportFormatOption, typer.Option()] = ExportFormatOption.PARQUET,
    mode: Annotated[ExportModeOption, typer.Option()] = ExportModeOption.READY_ONLY,
    columns: Annotated[list[str] | None, typer.Option("--column")] = None,
) -> None:
    """Export ready records to Parquet or JSONL."""

    try:
        result = open_run(run_path).export(
            output_path=output_path,
            format=format.value,
            mode=mode.value,
            selected_columns=columns,
        )
        typer.secho(f"Exported {result.record_count} record(s).", fg=typer.colors.GREEN)
        typer.echo(f"Output: {result.output_path}\nSHA-256: {result.output_sha256}")
    except Exception as error:
        _fail(error)


def _call(function: Any, *args: Any, **kwargs: Any) -> None:
    try:
        function(*args, **kwargs)
    except Exception as error:
        _fail(error)


def _precheck_text(payload: dict[str, object]) -> str:
    lines: list[str] = []
    for issue in cast(list[dict[str, Any]], payload["issues"]):
        field = f" [{issue['field']}]" if issue.get("field") else ""
        lines.append(f"{str(issue['severity']).upper()}{field}: {issue['message']}")
    estimate = payload.get("cost_estimate")
    if isinstance(estimate, dict):
        lines.append("Precheck estimate: " + _money(estimate.get("estimated_total_cost_usd")))
        for backend in cast(list[dict[str, Any]], estimate["backends"]):
            lines.append(
                f"  {backend['backend_id']}: {backend['request_count']} request(s), "
                + _money(backend.get("estimated_total_cost_usd"))
            )
    return "\n".join(lines) or "Precheck passed."


def _status_text(
    report: dict[str, Any],
    run_dir: Path,
    *,
    show_errors: bool = False,
) -> str:
    run_data = report["run"]
    records = report["records"]
    lines = [
        f"Run: {run_data['run_id']}",
        f"Directory: {run_dir}",
        f"Status: {run_data['status']}",
        f"Records: {records['denominator']}",
    ]
    counts = records.get("counts", {})
    if counts:
        lines.append(
            "Record states: " + ", ".join(f"{key}={value}" for key, value in counts.items())
        )
    for backend in report.get("usage", {}).get("backends", []):
        label = "Reused usage" if backend["provenance"] == "reused_from_parent" else "Usage"
        details = [
            f"attempts={backend['attempts']}",
            f"requests={backend['request_count']}",
        ]
        if backend.get("actual_cost_usd") is not None:
            details.append(f"actual_cost={_money(backend['actual_cost_usd'])}")
        lines.append(f"{label} [{backend['backend_id']}]: " + ", ".join(details))
    unresolved = [item for item in report["errors"]["items"] if not item["resolved"]]
    if unresolved:
        lines.append(f"Unresolved errors: {len(unresolved)}")
        for item in unresolved if show_errors else unresolved[:3]:
            target = item["record_id"] or "run"
            lines.append(f"  {target} · {item['stage_name']}: {item['message']}")
    return "\n".join(lines)


def _money(value: object) -> str:
    return "not priced" if not isinstance(value, (int, float)) else f"${value:,.6f}"


def _fail(error: BaseException) -> None:
    message = str(error).strip() or type(error).__name__
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1) from error
