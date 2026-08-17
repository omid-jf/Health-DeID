"""New-run setup routes."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml
from flask import abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask.typing import ResponseReturnValue
from pydantic import ValidationError
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from health_deid.backends.rules import RulesFile
from health_deid.models.config import PipelineConfig
from health_deid.models.input import InputFormat, InputPreview
from health_deid.pipeline.engine import PipelineEngine
from health_deid.pipeline.input import preview_input_file
from health_deid.ui.configuration import (
    config_from_form,
    embedded_rules,
    render_configuration,
)
from health_deid.ui.route_helpers import (
    capture_form,
    current_draft,
    run_precheck,
    sanitize_imported_source,
    state,
    yaml_response,
)
from health_deid.ui.state import SetupDraft, UiState


@dataclass(frozen=True, slots=True)
class _SourceSelection:
    path: Path
    name: str
    format: InputFormat
    owns_file: bool


def setup() -> str:
    return render_template("ui/setup_upload.html")


def upload_source() -> ResponseReturnValue:
    ui_state = state()
    source_upload = request.files.get("source")
    config_upload = request.files.get("config_file")

    has_source = source_upload is not None and bool(source_upload.filename)
    has_config = config_upload is not None and bool(config_upload.filename)
    if not has_source and not has_config:
        abort(400, description="Choose input data, a configuration YAML, or both.")

    imported_config = _load_config_upload(config_upload) if has_config else None
    source = _select_source(
        ui_state,
        source_upload=source_upload if has_source else None,
        imported_config=imported_config,
    )
    preview = _preview_source(source)
    imported_config = _use_selected_source(imported_config, source)

    draft = _new_draft(
        ui_state,
        source=source,
        preview=preview,
        imported_config=imported_config,
    )
    session["setup_draft_id"] = draft.draft_id
    return redirect(url_for("ui.configure"))


def configure() -> str:
    return render_configuration(current_draft())


def import_rules() -> ResponseReturnValue:
    draft = current_draft()
    upload = request.files.get("rules_file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose a rules YAML file."}), 400

    try:
        raw = yaml.safe_load(upload.stream)
        if not isinstance(raw, dict):
            raise ValueError("Rules YAML must contain an object with a rules list.")
        parsed = RulesFile.model_validate(raw)
    except (ValidationError, ValueError, yaml.YAMLError) as error:
        return jsonify({"error": str(error)}), 400

    draft.rules_payload = parsed.model_dump(mode="json")
    draft.rules_source_name = secure_filename(upload.filename) or "uploaded-rules.yaml"
    return jsonify(
        {
            "rules": draft.rules_payload,
            "source_name": draft.rules_source_name,
            "count": len(parsed.rules),
        }
    )


def download_draft_rules() -> ResponseReturnValue:
    draft = current_draft()
    try:
        parsed = embedded_rules(draft)
    except (json.JSONDecodeError, ValidationError, ValueError, yaml.YAMLError) as error:
        flash(str(error), "error")
        return render_configuration(draft, form=capture_form()), 400

    return yaml_response(parsed.model_dump(mode="json"), "health-deid-rules.yaml")


def download_draft_configuration() -> ResponseReturnValue:
    draft = current_draft()
    try:
        config = config_from_form(draft)
    except (json.JSONDecodeError, ValidationError, ValueError, yaml.YAMLError) as error:
        flash(str(error), "error")
        return render_configuration(draft, form=capture_form()), 400

    return yaml_response(
        config.model_dump(mode="json"),
        "health-deid-configuration.yaml",
    )


def preview_draft_configuration() -> ResponseReturnValue:
    draft = current_draft()

    try:
        config = config_from_form(draft)
    except (json.JSONDecodeError, ValidationError, ValueError, yaml.YAMLError) as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(config.model_dump(mode="json"))


def precheck() -> ResponseReturnValue:
    draft = current_draft()
    try:
        config = config_from_form(draft)
        result = run_precheck(config)
        draft.config_payload = config.model_dump(mode="json")
    except (json.JSONDecodeError, ValidationError, ValueError, yaml.YAMLError) as error:
        flash(str(error), "error")
        return render_configuration(draft, form=capture_form()), 400

    return render_configuration(draft, form=capture_form(), result=result)


def start_run() -> ResponseReturnValue:
    draft = current_draft()
    try:
        config = config_from_form(draft)
        result = run_precheck(config)
    except (json.JSONDecodeError, ValidationError, ValueError, yaml.YAMLError) as error:
        flash(str(error), "error")
        return render_configuration(draft, form=capture_form()), 400

    if not result.ok:
        flash("Check setup found blocking errors; processing was not started.", "error")
        return render_configuration(
            draft,
            form=capture_form(),
            result=result,
        ), 409

    ui_state = state()
    if ui_state.jobs.snapshot().state == "running":
        flash("Another processing job is running. Wait for it to finish.", "warning")
        return render_configuration(
            draft,
            form=capture_form(),
            result=result,
        ), 409

    try:
        engine = PipelineEngine.create(config, dependencies=ui_state.dependencies)
    except (OSError, RuntimeError, ValueError) as error:
        flash(str(error), "error")
        return render_configuration(
            draft,
            form=capture_form(),
            result=result,
        ), 400

    context = sanitize_imported_source(engine, draft.source_name)
    ui_state.remember_context(context)
    ui_state.discard_draft(draft.draft_id)
    session.pop("setup_draft_id", None)

    try:
        ui_state.jobs.start("run", engine.execute)
    except RuntimeError as error:
        flash(f"The run was created but processing did not start: {error}", "warning")

    return redirect(url_for("ui.dashboard", run_id=context.run_id))


def _load_config_upload(upload: FileStorage | None) -> PipelineConfig:
    assert upload is not None

    try:
        raw = yaml.safe_load(upload.stream)
        if not isinstance(raw, dict):
            raise ValueError("Configuration YAML must contain an object.")
        return PipelineConfig.model_validate(raw)
    except (ValidationError, ValueError, yaml.YAMLError) as error:
        abort(400, description=f"The configuration YAML is invalid: {error}")


def _select_source(
    ui_state: UiState,
    *,
    source_upload: FileStorage | None,
    imported_config: PipelineConfig | None,
) -> _SourceSelection:
    if source_upload is not None:
        return _save_source_upload(ui_state, source_upload)

    assert imported_config is not None
    return _SourceSelection(
        path=imported_config.input.path,
        name=imported_config.input.path.name,
        format=imported_config.input.format,
        owns_file=False,
    )


def _save_source_upload(ui_state: UiState, upload: FileStorage) -> _SourceSelection:
    original_name = secure_filename(upload.filename or "") or "input-data"
    suffix = Path(original_name).suffix.lower()
    input_format = _input_format_for_suffix(suffix)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix="upload-",
        suffix=suffix,
        dir=ui_state.temp_root,
    )
    os.close(descriptor)
    source_path = Path(temporary_name)
    source_path.unlink(missing_ok=True)
    upload.save(source_path)

    return _SourceSelection(
        path=source_path,
        name=original_name,
        format=input_format,
        owns_file=True,
    )


def _input_format_for_suffix(suffix: str) -> InputFormat:
    if suffix == ".parquet":
        return "parquet"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"

    abort(400, description="Only .parquet, .jsonl, and .ndjson files are supported.")


def _preview_source(source: _SourceSelection) -> InputPreview:
    try:
        return preview_input_file(source.path, source.format, sample_size=10)
    except Exception as error:
        if source.owns_file:
            source.path.unlink(missing_ok=True)

        abort(
            400,
            description=(
                "The input file could not be read. Verify the configuration path and "
                f"that it is valid {source.format.upper()} data. Details: {error}"
            ),
        )


def _use_selected_source(
    imported_config: PipelineConfig | None,
    source: _SourceSelection,
) -> PipelineConfig | None:
    if imported_config is None:
        return None

    imported_input = imported_config.input.model_copy(
        update={"path": source.path, "format": source.format}
    )
    return imported_config.model_copy(update={"input": imported_input})


def _new_draft(
    ui_state: UiState,
    *,
    source: _SourceSelection,
    preview: InputPreview,
    imported_config: PipelineConfig | None,
) -> SetupDraft:
    previous_draft_id = session.get("setup_draft_id")
    if isinstance(previous_draft_id, str):
        ui_state.discard_draft(previous_draft_id)

    draft = SetupDraft(
        draft_id=uuid.uuid4().hex,
        source_path=source.path,
        source_name=source.name,
        preview=preview,
        config_payload=(
            imported_config.model_dump(mode="json") if imported_config is not None else None
        ),
        imported_config=imported_config is not None,
        owns_source_file=source.owns_file,
    )
    ui_state.add_draft(draft)
    return draft
