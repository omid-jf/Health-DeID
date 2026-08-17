"""Shared helpers for local UI routes."""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from typing import Any

import yaml
from flask import Response, abort, current_app, request, session

from health_deid.models.config import PipelineConfig
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.engine import PipelineEngine
from health_deid.pipeline.precheck import PrecheckResult, precheck_config
from health_deid.pipeline.review import ReviewService
from health_deid.storage.database import SqliteRunStore
from health_deid.ui.state import SetupDraft, UiState


def state() -> UiState:
    """Return the state object configured for the current Flask app."""

    configured = current_app.config.get("HEALTH_DEID_UI_STATE")
    if not isinstance(configured, UiState):
        raise RuntimeError("Unified UI state is not configured.")

    return configured


def require_context(run_id: str) -> RunContext:
    """Resolve a known run or respond with HTTP 404."""

    try:
        return state().context_for(run_id)
    except KeyError:
        abort(404, description=f"Run {run_id!r} was not found in configured run locations.")


def store(context: RunContext) -> SqliteRunStore:
    """Open the database for a UI run context."""

    return SqliteRunStore.open(context.database_path)


def review_service(context: RunContext) -> ReviewService:
    """Create a review service with the UI's configured dependencies."""

    dependencies = state().dependencies
    return ReviewService(
        store(context),
        secrets=dependencies.secrets,
        clock=dependencies.clock,
    )


def current_draft() -> SetupDraft:
    """Return the active setup draft or respond with HTTP 409."""

    draft_id = session.get("setup_draft_id")
    if not isinstance(draft_id, str):
        abort(409, description="Upload input data before configuring the run.")

    try:
        return state().draft(draft_id)
    except KeyError as error:
        abort(409, description=str(error))


def capture_form() -> dict[str, Any]:
    """Copy submitted form data for redisplaying an invalid form."""

    multiple_value_fields = {"metadata_columns", "structured_columns", "detectors"}
    return {
        key: (
            request.form.getlist(key) if key in multiple_value_fields else request.form.get(key, "")
        )
        for key in request.form
        if key != "csrf_token"
    }


def run_precheck(config: PipelineConfig) -> PrecheckResult:
    """Run setup checks with the UI's secret resolver."""

    return precheck_config(
        config,
        secret_resolver=state().dependencies.secrets,
    )


def sanitize_imported_source(engine: PipelineEngine, source_name: str) -> RunContext:
    """Remove a temporary upload path from persisted run configuration."""

    neutral_path = engine.context.run_dir / "input-imported-into-run-database"
    sanitized_input = engine.context.config.input.model_copy(update={"path": neutral_path})
    sanitized_config = engine.context.config.model_copy(update={"input": sanitized_input})
    config_json = json.dumps(
        sanitized_config.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    config_sha256 = sha256(config_json.encode("utf-8")).hexdigest()

    with engine.store.connection() as connection:
        connection.execute(
            """
            UPDATE runs SET input_source_name = ?, input_source_path = NULL
            WHERE run_id = ?
            """,
            (source_name, engine.context.run_id),
        )
        connection.execute(
            "UPDATE runs SET config_json = ?, config_sha256 = ? WHERE run_id = ?",
            (config_json, config_sha256, engine.context.run_id),
        )

    sanitized_context = replace(engine.context, config=sanitized_config)
    engine.context = sanitized_context
    return sanitized_context


def yaml_response(payload: object, filename: str) -> Response:
    """Return a YAML attachment response."""

    body = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    return Response(
        body,
        mimetype="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
