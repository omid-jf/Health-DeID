"""Explicit-column export routes."""

from __future__ import annotations

from flask import flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from pydantic import ValidationError

from health_deid.models.export import ExportRequest
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.exports import ExportService
from health_deid.storage.database import SqliteRunStore
from health_deid.ui.route_helpers import require_context, store


def export(run_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    run_store = store(context)
    template_context = _export_template_context(context, run_store)

    if request.method == "GET":
        return render_template("ui/export.html", **template_context)

    try:
        export_request = _export_request(context)
        result = ExportService(run_store).export(export_request)
    except (OSError, ValidationError, ValueError) as error:
        flash(str(error), "error")
        return render_template("ui/export.html", **template_context), 400

    flash(f"Exported {result.record_count} records to {result.output_path}.", "success")
    return redirect(url_for("ui.export", run_id=run_id))


def _export_request(context: RunContext) -> ExportRequest:
    output_filename = request.form.get("output_filename", "").strip()
    if not output_filename:
        raise ValueError("Enter an output filename.")
    if output_filename in {".", ".."} or "/" in output_filename or "\\" in output_filename:
        raise ValueError("Enter a filename without folders.")

    return ExportRequest.model_validate(
        {
            "output_path": str(context.exports_dir / output_filename),
            "format": request.form.get("format", "parquet"),
            "mode": request.form.get("mode", "ready_only"),
            "selected_columns": request.form.getlist("selected_columns"),
        }
    )


def _export_template_context(
    context: RunContext,
    run_store: SqliteRunStore,
) -> dict[str, object]:
    config = run_store.read_config()
    with run_store.read_snapshot() as connection:
        total_count = int(connection.execute("SELECT count(*) FROM records").fetchone()[0])
        completed_count = int(
            connection.execute("SELECT count(*) FROM records WHERE status = 'ready'").fetchone()[0]
        )

    return {
        "context": context,
        "output_columns": ["final_text"],
        "identifier_columns": ["record_id", "entity_id"],
        "operational_columns": ["deid_status", "input_row_number"],
        "source_text_columns": ["raw_source_text", "normalized_text"],
        "raw_structured_columns": [
            f"raw_{column}" for column in config.input.structured_phi_columns
        ],
        "metadata_columns": config.input.metadata_columns,
        "structured_columns": set(config.input.structured_phi_columns),
        "ready_count": completed_count,
        "total_count": total_count,
    }
