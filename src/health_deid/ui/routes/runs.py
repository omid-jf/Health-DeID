"""Run dashboard, audit, retry, and revision routes."""

from __future__ import annotations

import json

import yaml
from flask import Response, abort, flash, jsonify, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from pydantic import ValidationError

from health_deid.models.config import PipelineConfig
from health_deid.pipeline.control import RunControlService
from health_deid.pipeline.engine import PipelineEngine
from health_deid.pipeline.reporting import LiveReportService
from health_deid.pipeline.revision import (
    RevisionPlan,
    create_revised_run_context,
    plan_revised_run,
)
from health_deid.storage.database import SqliteRunStore
from health_deid.ui.configuration import (
    render_settings,
    revised_config_from_form,
    rules_payload,
)
from health_deid.ui.route_helpers import (
    capture_form,
    require_context,
    state,
    store,
    yaml_response,
)


def dashboard(run_id: str) -> str:
    context = require_context(run_id)
    report = LiveReportService(store(context)).build()
    rules_json, rules_error = _rules_json(context.config)

    return render_template(
        "ui/dashboard.html",
        context=context,
        report=report,
        configuration_json=json.dumps(
            context.config.model_dump(mode="json"), ensure_ascii=False, indent=2
        ),
        rules_json=rules_json,
        rules_error=rules_error,
    )


def download_run_configuration(run_id: str) -> Response:
    context = require_context(run_id)
    return yaml_response(
        store(context).read_config().model_dump(mode="json"),
        f"{run_id}-configuration.yaml",
    )


def download_run_rules(run_id: str) -> Response:
    context = require_context(run_id)
    config = store(context).read_config()
    if not config.rules.enabled:
        abort(404, description="This run does not use custom rules.")

    try:
        payload = rules_payload(config)
    except (OSError, ValidationError, ValueError, yaml.YAMLError) as error:
        abort(422, description=f"The run's rules cannot be read: {error}")

    return yaml_response(payload, f"{run_id}-rules.yaml")


def status_api(run_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    return jsonify(
        {
            "report": LiveReportService(store(context)).build(),
            "job": state().jobs.snapshot().as_dict(),
        }
    )


def resume_run(run_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    ui_state = state()
    report = LiveReportService(store(context)).build()
    action = report.get("action")
    if not isinstance(action, dict) or action.get("kind") != "continue":
        flash("This run has no interrupted processing to continue.", "warning")
        return redirect(url_for("ui.dashboard", run_id=run_id))

    try:
        ui_state.jobs.start(
            "continue",
            PipelineEngine(context, dependencies=ui_state.dependencies).resume,
        )
    except RuntimeError as error:
        flash(str(error), "error")

    return redirect(url_for("ui.dashboard", run_id=run_id))


def retry_failed(run_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    ui_state = state()
    run_store = store(context)

    try:
        record_ids = _failed_record_ids(run_store)
        if not record_ids:
            raise ValueError("No retryable failed records were found.")

        control = RunControlService(run_store)
        for record_id in record_ids:
            control.retry(record_id=record_id)

        ui_state.jobs.start(
            "retry-failed",
            PipelineEngine(context, dependencies=ui_state.dependencies).resume,
        )
    except (KeyError, RuntimeError, ValueError) as error:
        flash(str(error), "error")

    return redirect(url_for("ui.dashboard", run_id=run_id))


def records(run_id: str) -> str:
    context = require_context(run_id)
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1

    page = max(1, page)
    status = request.args.get("status", "").strip() or None
    result = LiveReportService(store(context)).records(page=page, status=status)
    return render_template(
        "ui/records.html",
        context=context,
        result=result,
        status=status,
    )


def record_audit(run_id: str, record_id: str) -> str:
    context = require_context(run_id)
    run_store = store(context)

    try:
        audit = LiveReportService(run_store).record_audit(record_id)
    except KeyError:
        abort(404)

    record_ids = _record_ids(run_store)
    index = record_ids.index(record_id)
    return render_template(
        "ui/record_audit.html",
        context=context,
        audit=audit,
        position=index + 1,
        total=len(record_ids),
        previous_id=record_ids[index - 1] if index else None,
        next_id=record_ids[index + 1] if index + 1 < len(record_ids) else None,
    )


def retry_record(run_id: str, record_id: str) -> ResponseReturnValue:
    context = require_context(run_id)

    try:
        RunControlService(store(context)).retry(record_id=record_id)
        ui_state = state()
        ui_state.jobs.start(
            "retry-record",
            PipelineEngine(context, dependencies=ui_state.dependencies).resume,
        )
    except (KeyError, RuntimeError, ValueError) as error:
        flash(str(error), "error")

    return redirect(url_for("ui.record_audit", run_id=run_id, record_id=record_id))


def settings(run_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    ui_state = state()
    config = context.config

    if request.method == "GET":
        return render_settings(
            context,
            config,
            plan=plan_revised_run(context.run_dir),
        )

    if ui_state.jobs.snapshot().state == "running":
        flash("Wait for the current processing job before creating a revised run.", "warning")
        return render_settings(context, config, form=capture_form()), 409

    plan: RevisionPlan | None = None
    try:
        revised_config = revised_config_from_form(context, config)
        _require_settings_change(config, revised_config)
        rerun_detection = request.form.get("rerun_detection") == "yes"
        plan = plan_revised_run(context.run_dir, revised_config)
        child_context = create_revised_run_context(
            context.run_dir,
            revised_config,
            secret_resolver=ui_state.dependencies.secrets,
            reason=request.form.get("reason", ""),
            rerun_detection=rerun_detection,
        )
        child_engine = PipelineEngine(child_context, dependencies=ui_state.dependencies)
        ui_state.remember_context(child_context)
    except (KeyError, RuntimeError, ValidationError, ValueError) as error:
        flash(str(error), "error")
        return render_settings(
            context,
            config,
            form=capture_form(),
            plan=plan,
        ), 400

    try:
        ui_state.jobs.start("revised-run", child_engine.execute)
    except RuntimeError as error:
        flash(
            f"Created revised run {child_context.run_id}, but processing did not start: {error}",
            "warning",
        )
        return redirect(url_for("ui.dashboard", run_id=child_context.run_id))

    flash(
        f"Created revised run {child_context.run_id}. The parent run remains unchanged.",
        "success",
    )
    return redirect(url_for("ui.dashboard", run_id=child_context.run_id))


def _rules_json(config: PipelineConfig) -> tuple[str | None, str | None]:
    if not config.rules.enabled:
        return None, None

    try:
        payload = rules_payload(config)
    except (OSError, ValidationError, ValueError, yaml.YAMLError) as error:
        return None, str(error)

    return json.dumps(payload, ensure_ascii=False, indent=2), None


def _failed_record_ids(run_store: SqliteRunStore) -> list[str]:
    with run_store.read_snapshot() as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT record_stage_states.record_id
            FROM record_stage_states
            JOIN records USING (run_id, record_id)
            WHERE record_stage_states.run_id = ?
              AND record_stage_states.status IN ('retry_exhausted', 'permanent_error')
            ORDER BY records.source_index
            """,
            (run_store.run_id(connection),),
        ).fetchall()

    return [str(row[0]) for row in rows]


def _record_ids(run_store: SqliteRunStore) -> list[str]:
    with run_store.read_snapshot() as connection:
        rows = connection.execute(
            "SELECT record_id FROM records WHERE run_id = ? ORDER BY source_index",
            (run_store.run_id(connection),),
        ).fetchall()

    return [str(row[0]) for row in rows]


def _require_settings_change(
    original: PipelineConfig,
    revised: PipelineConfig,
) -> None:
    original_payload = original.model_dump(mode="json")
    revised_payload = revised.model_dump(mode="json")
    original_payload["run"] = {}
    revised_payload["run"] = {}
    if revised_payload == original_payload:
        raise ValueError("Run settings are unchanged.")
