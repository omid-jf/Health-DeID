from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any, cast

import polars as pl
import pytest
import yaml
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.datastructures import MultiDict

import health_deid.ui.configuration as configuration_module
import health_deid.ui.route_helpers as common_routes
import health_deid.ui.routes.export as export_routes
import health_deid.ui.routes.review as review_routes
import health_deid.ui.routes.runs as run_routes
import health_deid.ui.routes.setup as setup_routes
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.config import PipelineConfig
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.engine import PipelineEngine
from health_deid.pipeline.precheck import PrecheckIssue, PrecheckResult
from health_deid.storage.database import SqliteRunStore
from health_deid.ui.app import create_ui_app
from health_deid.ui.routes import register_routes
from health_deid.ui.state import UiState

NOW = datetime(2026, 7, 31, 14, 0, tzinfo=UTC)


def _token(client: FlaskClient) -> str:
    with client.session_transaction() as session:
        return str(session["csrf_token"])


def _state(app: Flask) -> UiState:
    return cast(UiState, app.config["HEALTH_DEID_UI_STATE"])


def _created_context(
    tmp_path: Path,
    *,
    review_all: bool = False,
    structured_site: bool = False,
) -> RunContext:
    source = tmp_path / "existing.jsonl"
    source.write_text(
        '{"record_id":"R1","text":"Example note.","site":"north"}\n'
        '{"record_id":"R2","text":"Second note.","site":"south"}\n',
        encoding="utf-8",
    )
    config = PipelineConfig.model_validate(
        {
            "run": {"output_dir": tmp_path / "existing-runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
                "metadata_columns": ["site"],
                "structured_phi_columns": {"site": "LOCATION"} if structured_site else {},
            },
            "detection": {"enabled": False},
            "review": {
                "enabled": review_all,
                "review_scope": "all" if review_all else "effective_validation_failures",
            },
        }
    )
    engine = PipelineEngine.create(config, timestamp=NOW)
    if review_all:
        engine.execute()
    return engine.context


def _upload(
    client: FlaskClient,
    content: bytes,
    filename: str,
    *,
    follow_redirects: bool = False,
) -> Any:
    client.get("/runs/new")
    return client.post(
        "/runs/new/source",
        data={"csrf_token": _token(client), "source": (BytesIO(content), filename)},
        content_type="multipart/form-data",
        follow_redirects=follow_redirects,
    )


def _form(client: FlaskClient, tmp_path: Path, **updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "csrf_token": _token(client),
        "run_name": "ui-run",
        "output_dir": str(tmp_path / "new-runs"),
        "record_id_column": "record_id",
        "text_column": "text",
        "entity_id_column": "record_id",
        "metadata_columns": ["site"],
        "structured_columns": [],
        "review_mode": "none",
    }
    payload.update(updates)
    return payload


def test_setup_guards_upload_types_and_replaces_valid_drafts(tmp_path: Path) -> None:
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/runs/new")
    token = _token(client)

    assert client.post("/runs/new/source", data={"csrf_token": token}).status_code == 400
    assert (
        client.post(
            "/runs/new/source",
            data={"csrf_token": token, "source": (BytesIO(b"x"), "notes.csv")},
            content_type="multipart/form-data",
        ).status_code
        == 400
    )
    malformed = _upload(client, b"not-json\n", "broken.jsonl")
    assert malformed.status_code == 400
    assert list((tmp_path / "uploads").iterdir()) == []

    _upload(client, b'{"record_id":"R1","text":"First"}\n', "first.jsonl")
    with client.session_transaction() as session:
        first_id = cast(str, session["setup_draft_id"])
    first = _state(app).draft(first_id)
    assert first.source_path.exists()
    assert _upload(client, b"invalid\n", "invalid.jsonl").status_code == 400
    assert first.source_path.exists()

    buffer = BytesIO()
    pl.DataFrame({"record_id": ["P1"], "text": ["Parquet note"]}).write_parquet(buffer)
    uploaded = _upload(client, buffer.getvalue(), "../../notes.parquet")
    assert uploaded.status_code == 302
    assert b"Parquet note" in client.get(uploaded.headers["Location"]).data
    assert not first.source_path.exists()


def test_setup_configuration_only_uses_referenced_source_without_owning_it(
    tmp_path: Path,
) -> None:
    source = tmp_path / "referenced.jsonl"
    source.write_text('{"record_id":"R1","text":"Referenced note"}\n', encoding="utf-8")
    config = {
        "run": {"output_dir": str(tmp_path / "runs")},
        "input": {
            "path": str(source),
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "record_id"},
            "text_column": "text",
        },
        "detection": {"enabled": False},
    }
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/runs/new")
    response = client.post(
        "/runs/new/source",
        data={
            "csrf_token": _token(client),
            "config_file": (BytesIO(yaml.safe_dump(config).encode()), "config.yaml"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Referenced note" in response.data
    with client.session_transaction() as session:
        draft = _state(app).draft(cast(str, session["setup_draft_id"]))
    assert draft.owns_source_file is False
    _state(app).discard_draft(draft.draft_id)
    assert source.exists()

    missing = dict(config)
    missing["input"] = {**cast(dict[str, object], config["input"]), "path": "missing.jsonl"}
    failed = client.post(
        "/runs/new/source",
        data={
            "csrf_token": _token(client),
            "config_file": (BytesIO(yaml.safe_dump(missing).encode()), "missing.yaml"),
        },
        content_type="multipart/form-data",
    )
    assert failed.status_code == 400
    assert b"input file could not be read" in failed.data


def test_visual_configuration_validation_and_precheck(tmp_path: Path) -> None:
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/runs/new/configure").status_code == 409
    _upload(
        client,
        b'{"record_id":"R1","patient_id":"P1","text":"Note","site":"north"}\n',
        "notes.ndjson",
    )

    invalid_rule = client.post(
        "/runs/new/precheck",
        data=_form(client, tmp_path, rules_enabled="yes", rules_json="{"),
    )
    assert invalid_rule.status_code == 400
    assert b"Configure run" in invalid_rule.data
    invalid_mapping = client.post(
        "/runs/new/precheck",
        data=_form(client, tmp_path, text_column="record_id"),
    )
    assert invalid_mapping.status_code == 400

    success = client.post(
        "/runs/new/precheck",
        data=_form(
            client,
            tmp_path,
            entity_id_source="column",
            entity_id_column="patient_id",
            metadata_columns=["patient_id", "site"],
            structured_columns=["site"],
            **{"structured_category:site": "LOCATION"},
        ),
    )
    assert success.status_code == 200
    assert b"Setup is ready" in success.data
    assert b"Estimated AWS cost" in success.data
    configuration_json = client.post(
        "/runs/new/configuration.json",
        data=_form(
            client,
            tmp_path,
            entity_id_source="column",
            entity_id_column="patient_id",
            metadata_columns=["patient_id", "site"],
            structured_columns=["site"],
            **{"structured_category:site": "LOCATION"},
        ),
    )
    assert configuration_json.status_code == 200
    assert configuration_json.get_json()["config_version"] == 1
    invalid_configuration_json = client.post(
        "/runs/new/configuration.json",
        data=_form(client, tmp_path, rules_enabled="yes", rules_json="{"),
    )
    assert invalid_configuration_json.status_code == 400
    assert "error" in invalid_configuration_json.get_json()
    with client.session_transaction() as session:
        draft = _state(app).draft(cast(str, session["setup_draft_id"]))
    assert draft.config_payload is not None
    input_payload = cast(dict[str, object], draft.config_payload["input"])
    assert input_payload["structured_phi_columns"] == {"site": "LOCATION"}


def test_start_handles_precheck_create_failure_success_and_contention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()
    _upload(
        client,
        b'{"record_id":"R1","text":"No PHI.","site":"north"}\n',
        "original-name.jsonl",
    )
    monkeypatch.setattr(
        common_routes,
        "precheck_config",
        lambda *args, **kwargs: PrecheckResult(
            (PrecheckIssue("error", "blocked", "Blocked for test"),), record_count=1
        ),
    )
    assert client.post("/runs/new/start", data=_form(client, tmp_path)).status_code == 409

    monkeypatch.setattr(
        common_routes,
        "precheck_config",
        lambda *args, **kwargs: PrecheckResult(
            (PrecheckIssue("info", "ready", "Ready"),), record_count=1
        ),
    )
    real_engine = setup_routes.PipelineEngine

    class FailingEngine:
        @classmethod
        def create(cls, *args: object, **kwargs: object) -> None:
            raise ValueError("cannot create run")

    monkeypatch.setattr(setup_routes, "PipelineEngine", FailingEngine)
    failed = client.post("/runs/new/start", data=_form(client, tmp_path))
    assert failed.status_code == 400
    assert b"cannot create run" in failed.data
    monkeypatch.setattr(setup_routes, "PipelineEngine", real_engine)

    with client.session_transaction() as session:
        draft_id = cast(str, session["setup_draft_id"])
    transient_path = _state(app).draft(draft_id).source_path
    started = client.post("/runs/new/start", data=_form(client, tmp_path))
    assert started.status_code == 302
    state = _state(app)
    assert state.jobs.wait(5).state == "completed"
    run_id = started.headers["Location"].rstrip("/").rsplit("/", 1)[-1]
    context = state.context_for(run_id)
    imported = PipelineEngine(context).store.read_input_import()
    assert imported.source_name == "original-name.jsonl"
    assert imported.source_path is None
    assert not transient_path.exists()
    assert context.config.input.path.name == "input-imported-into-run-database"

    second_app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads-2"
    )
    second_app.config["TESTING"] = True
    second_client = second_app.test_client()
    _upload(
        second_client,
        b'{"record_id":"R2","text":"No PHI.","site":"north"}\n',
        "contention.jsonl",
    )
    second_state = _state(second_app)
    entered = threading.Event()
    release = threading.Event()

    def block() -> None:
        entered.set()
        release.wait(2)

    second_state.jobs.start("existing", block)
    assert entered.wait(1)
    blocked = second_client.post("/runs/new/start", data=_form(second_client, tmp_path))
    assert blocked.status_code == 409
    release.set()
    assert second_state.jobs.wait(2).state == "completed"


def test_home_uses_fixed_runs_directory_and_stable_route_guards(tmp_path: Path) -> None:
    context = _created_context(tmp_path)
    app = create_ui_app(
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads",
        runs_dir=context.config.run.output_dir,
    )
    app.config["TESTING"] = True
    client = app.test_client()
    home = client.get("/")
    assert context.run_id.encode() in home.data
    assert b"Recent runs" not in home.data
    assert b"Runs saved in the configured runs folder" in home.data
    assert b"directory-dialog" not in home.data
    assert b"run_path" not in home.data
    assert b"data-local-datetime" in home.data
    assert client.get("/runs/browse").status_code == 404
    assert client.get("/api/directories").status_code == 404
    assert client.get("/runs/missing/api/status").status_code == 404
    for suffix in ("", "/records", "/review", "/export", "/revise"):
        assert client.get(f"/runs/missing{suffix}").status_code == 404
    assert client.post("/runs/open", data={"csrf_token": _token(client)}).status_code == 405


def test_fixed_runs_directory_does_not_import_external_runs(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    context = _created_context(source_root)
    destination = tmp_path / "managed-runs"
    destination.mkdir()
    app = create_ui_app(
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads",
        runs_dir=destination,
    )
    app.config["TESTING"] = True
    client = app.test_client()
    home = client.get("/")
    assert context.run_id.encode() not in home.data
    assert b"No runs yet" in home.data
    assert list(destination.iterdir()) == []


def test_run_configuration_and_rules_downloads(tmp_path: Path) -> None:
    def create_context(
        name: str,
        rules: dict[str, object] | None = None,
        *,
        snapshot_rules: bool = True,
    ) -> RunContext:
        root = tmp_path / name
        root.mkdir()
        source = root / "records.jsonl"
        source.write_text('{"record_id":"R1","text":"Alice"}\n', encoding="utf-8")
        config_payload: dict[str, object] = {
            "run": {"name": name, "output_dir": root / "runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
            },
            "detection": {"enabled": False},
        }
        if rules is not None:
            config_payload["rules"] = rules
        config = PipelineConfig.model_validate(config_payload)
        if snapshot_rules:
            return PipelineEngine.create(config, timestamp=NOW).context
        context = RunContext.from_config(config, timestamp=NOW)
        context.run_dir.mkdir(parents=True)
        context.exports_dir.mkdir()
        SqliteRunStore.create(
            context.database_path,
            run_id=context.run_id,
            config=config,
            created_at=context.created_at,
        )
        return context

    disabled = create_context("disabled")
    rule_payload = {
        "rules": [
            {
                "id": "alice",
                "name": "Alice",
                "category": "NAME",
                "type": "exact",
                "pattern": "Alice",
            }
        ]
    }
    embedded = create_context("embedded", {"enabled": True, "embedded": rule_payload})
    external_path = tmp_path / "external-rules.yaml"
    external_path.write_text(yaml.safe_dump(rule_payload), encoding="utf-8")
    external = create_context(
        "external",
        {"enabled": True, "rules_path": external_path},
        snapshot_rules=False,
    )
    invalid_path = tmp_path / "invalid-rules.yaml"
    invalid_path.write_text("- invalid\n- rules\n", encoding="utf-8")
    invalid = create_context(
        "invalid",
        {"enabled": True, "rules_path": invalid_path},
        snapshot_rules=False,
    )

    app = create_ui_app(
        disabled.run_dir,
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads-downloads",
    )
    app.config["TESTING"] = True
    state = _state(app)
    for context in (embedded, external, invalid):
        state.remember_context(context)
    client = app.test_client()

    configuration = client.get(f"/runs/{disabled.run_id}/configuration.yaml")
    assert configuration.status_code == 200
    assert configuration.mimetype == "application/yaml"
    assert b"config_version: 1" in configuration.data
    assert client.get(f"/runs/{disabled.run_id}/rules.yaml").status_code == 404
    for context in (embedded, external):
        response = client.get(f"/runs/{context.run_id}/rules.yaml")
        assert response.status_code == 200
        assert yaml.safe_load(response.data)["rules"][0]["id"] == "alice"
    embedded_dashboard = client.get(f"/runs/{embedded.run_id}")
    assert embedded_dashboard.status_code == 200
    assert b"Custom rules JSON" in embedded_dashboard.data
    invalid_dashboard = client.get(f"/runs/{invalid.run_id}")
    assert invalid_dashboard.status_code == 200
    assert b"Rules unavailable" in invalid_dashboard.data
    assert client.get(f"/runs/{invalid.run_id}/rules.yaml").status_code == 422
    assert configuration_module.rules_payload(disabled.config) == {"rules": []}
    external_form = configuration_module._form_from_config(external.config)
    assert json.loads(cast(str, external_form["rules_json"]))["rules"][0]["id"] == "alice"
    invalid_form = configuration_module._form_from_config(invalid.config)
    assert json.loads(cast(str, invalid_form["rules_json"])) == {"rules": []}


def test_dashboard_records_audit_and_contextual_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _created_context(tmp_path)
    store = PipelineEngine(context).store
    store.update_run_status("blocked", updated_at=NOW)
    app = create_ui_app(
        context.run_dir,
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads",
    )
    app.config["TESTING"] = True
    client = app.test_client()
    base = f"/runs/{context.run_id}"
    dashboard = client.get(base)
    assert b"Workflow progress" in dashboard.data
    assert b"Continue processing" in dashboard.data
    payload = client.get(f"{base}/api/status").get_json()
    assert payload["report"]["records"]["denominator"] == 2
    assert b"R1" in client.get(f"{base}/records?status=processing").data
    assert b"Source row 1" in client.get(f"{base}/records/R1").data
    assert client.get(f"{base}/records/missing").status_code == 404

    calls: list[object] = []

    class FakeEngine:
        def __init__(self, supplied: object, *, dependencies: object) -> None:
            calls.append((supplied, dependencies))

        def resume(self) -> None:
            calls.append("resume")

    monkeypatch.setattr(run_routes, "PipelineEngine", FakeEngine)
    resumed = client.post(f"{base}/continue", data={"csrf_token": _token(client)})
    assert resumed.status_code == 302
    assert _state(app).jobs.wait(2).state == "completed"
    assert "resume" in calls


def test_review_workspace_timer_preview_draft_decision_and_completion(tmp_path: Path) -> None:
    context = _created_context(tmp_path, review_all=True)
    app = create_ui_app(
        context.run_dir,
        secret_key="test",
        temp_root=tmp_path / "uploads",
        reviewer_id="Dr Test",
    )
    app.config["TESTING"] = True
    client = app.test_client()
    base = f"/runs/{context.run_id}"
    queue = client.get(f"{base}/review")
    assert b"Dr Test" in queue.data
    assert b"R1" in queue.data and b"R2" in queue.data
    record = client.get(f"{base}/review/R1")
    assert b"Entity ID" in record.data
    assert b"Previous" in record.data and b"Next" in record.data
    assert b"Validator results" not in record.data
    assert b'id="source-search"' not in record.data
    assert b'id="timer-restart"' in record.data
    assert b'data-source-text="&#34;Example note.&#34;"' in record.data
    assert b'data-workspace="{&#34;basis_plan_revision&#34;:' in record.data
    token = _token(client)

    preview = client.post(
        f"{base}/review/R1/preview",
        json={"span_events": [], "structured_events": []},
        headers={"X-CSRF-Token": token},
    )
    assert preview.status_code == 200
    assert preview.get_json()["text"] == "Example note."
    assert (
        client.post(
            f"{base}/review/R1/preview",
            json={"span_events": {}},
            headers={"X-CSRF-Token": token},
        ).status_code
        == 400
    )

    paused = client.post(
        f"{base}/review/R1/timer",
        data={"csrf_token": token, "action": "pause"},
    )
    assert paused.status_code == 200
    set_time = client.post(
        f"{base}/review/R1/timer",
        data={"csrf_token": token, "action": "set", "seconds": "120"},
    )
    assert set_time.get_json() == {"review_seconds": 120, "running": False}
    started = client.post(
        f"{base}/review/R1/timer",
        data={"csrf_token": token, "action": "start"},
    )
    assert started.get_json()["running"] is True
    adjusted = client.post(
        f"{base}/review/R1/timer",
        data={"csrf_token": token, "action": "adjust", "delta_seconds": "60"},
    )
    assert adjusted.get_json()["review_seconds"] >= 180
    restarted = client.post(
        f"{base}/review/R1/timer",
        data={"csrf_token": token, "action": "restart"},
    )
    assert restarted.get_json() == {"review_seconds": 0, "running": True}

    draft = client.post(
        f"{base}/review/R1/draft",
        data={
            "csrf_token": token,
            "basis_plan_revision": "1",
            "span_events": "[]",
            "structured_events": "[]",
            "record_comment": "Return later",
        },
        follow_redirects=True,
    )
    assert b"Draft saved" in draft.data
    approved = client.post(
        f"{base}/review/R1/decision",
        data={
            "csrf_token": token,
            "basis_plan_revision": "1",
            "span_events": "[]",
            "structured_events": "[]",
            "action": "approve",
        },
        follow_redirects=True,
    )
    assert b"Review saved" in approved.data
    assert b"R2" in approved.data
    client.post(
        f"{base}/review/R2/decision",
        data={
            "csrf_token": token,
            "basis_plan_revision": "1",
            "span_events": "[]",
            "structured_events": "[]",
            "action": "approve",
        },
    )
    completed = client.post(
        f"{base}/review/complete",
        data={"csrf_token": token},
    )
    assert completed.status_code == 302
    assert _state(app).jobs.wait(5).state == "completed"
    assert PipelineEngine(context).store.read_run_status() == "completed"


def test_structured_review_offers_handling_actions_and_typed_preview(tmp_path: Path) -> None:
    context = _created_context(tmp_path, review_all=True, structured_site=True)
    app = create_ui_app(
        context.run_dir,
        secret_key="test",
        temp_root=tmp_path / "uploads",
        reviewer_id="Dr Test",
    )
    app.config["TESTING"] = True
    client = app.test_client()
    base = f"/runs/{context.run_id}"

    page = client.get(f"{base}/review/R1")
    assert b"Reviewer action" in page.data
    assert b"Use baseline" in page.data
    assert b'data-original="&#34;north&#34;"' in page.data
    assert b'data-baseline="&#34;[R_LOC]&#34;"' in page.data
    assert b">Redact<" in page.data
    assert b">Keep original<" in page.data
    assert b">Custom value<" in page.data

    preview = client.post(
        f"{base}/review/R1/preview",
        json={
            "span_events": [],
            "structured_events": [
                {
                    "event_id": "restore-site",
                    "column_name": "site",
                    "category": "LOCATION",
                    "original_value": "north",
                    "replacement_value": "north",
                }
            ],
        },
        headers={"X-CSRF-Token": _token(client)},
    )
    assert preview.status_code == 200
    assert preview.get_json()["structured_fields"] == {"site": "north"}


def test_retry_and_export_routes_surface_clear_feedback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _created_context(tmp_path)
    app = create_ui_app(
        context.run_dir,
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads",
    )
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/")
    base = f"/runs/{context.run_id}"
    retry_calls: list[str] = []

    class FakeControl:
        def __init__(self, store: object) -> None:
            del store

        def retry(self, *, record_id: str) -> None:
            retry_calls.append(record_id)

    class FakeEngine:
        def __init__(self, supplied: object, *, dependencies: object) -> None:
            del supplied, dependencies

        def resume(self) -> None:
            pass

    monkeypatch.setattr(run_routes, "RunControlService", FakeControl)
    monkeypatch.setattr(run_routes, "PipelineEngine", FakeEngine)
    retried = client.post(f"{base}/records/R1/retry", data={"csrf_token": _token(client)})
    assert retried.status_code == 302
    assert _state(app).jobs.wait(2).state == "completed"
    assert retry_calls == ["R1"]

    missing_destination = client.post(
        f"{base}/export",
        data={
            "csrf_token": _token(client),
            "selected_columns": ["final_text"],
        },
    )
    assert missing_destination.status_code == 400
    assert b"Enter an output filename" in missing_destination.data

    invalid_filename = client.post(
        f"{base}/export",
        data={
            "csrf_token": _token(client),
            "output_filename": "../outside.jsonl",
            "selected_columns": ["final_text"],
        },
    )
    assert invalid_filename.status_code == 400
    assert b"Enter a filename without folders" in invalid_filename.data

    output = context.exports_dir / "all.jsonl"
    exported = client.post(
        f"{base}/export",
        data={
            "csrf_token": _token(client),
            "output_directory": str(tmp_path / "ignored"),
            "output_filename": output.name,
            "format": "jsonl",
            "mode": "all_records",
            "selected_columns": ["record_id", "final_text"],
        },
        follow_redirects=True,
    )
    assert exported.status_code == 200
    assert output.exists()

    class FailingExportService:
        def __init__(self, store: object) -> None:
            del store

        def export(self, request: object) -> None:
            del request
            raise OSError("disk unavailable")

    monkeypatch.setattr(export_routes, "ExportService", FailingExportService)
    failed = client.post(
        f"{base}/export",
        data={
            "csrf_token": _token(client),
            "output_filename": "failure.parquet",
            "selected_columns": "final_text",
        },
    )
    assert failed.status_code == 400
    assert b"disk unavailable" in failed.data


def test_direct_routes_reject_missing_ui_state_configuration() -> None:
    app = Flask(__name__)
    app.config["TESTING"] = True
    register_routes(app)
    with pytest.raises(RuntimeError, match="Unified UI state"):
        app.test_client().get("/")


def test_setup_imports_configuration_rules_and_direct_replacements(tmp_path: Path) -> None:
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()
    imported_payload = {
        "run": {"output_dir": str(tmp_path / "imported-runs")},
        "input": {
            "path": "replaced.jsonl",
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": {"source": "column", "column": "patient_id"},
            "text_column": "text",
        },
        "detection": {"enabled": False},
    }
    client.get("/runs/new")
    imported = client.post(
        "/runs/new/source",
        data={
            "csrf_token": _token(client),
            "source": (
                BytesIO(b'{"record_id":"R1","patient_id":"P1","text":"Alice on 01/02/2020"}\n'),
                "notes.jsonl",
            ),
            "config_file": (
                BytesIO(yaml.safe_dump(imported_payload).encode()),
                "config.yaml",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert imported.status_code == 200
    assert b"Configuration loaded" in imported.data
    assert b"generator_prefix:" not in imported.data
    assert b"generator_id:" not in imported.data
    with client.session_transaction() as session:
        draft = _state(app).draft(cast(str, session["setup_draft_id"]))
    assert draft.imported_config
    assert draft.config_payload is not None
    imported_input = cast(dict[str, object], draft.config_payload["input"])
    assert imported_input["path"] == str(draft.source_path)

    detector_form_payload = imported_payload | {
        "detection": {
            "enabled": True,
            "detectors": [
                {
                    "backend": "aws_comprehend_medical",
                },
                {
                    "backend": "aws_bedrock",
                    "reasoning_effort": "medium",
                },
            ],
        },
        "validation": {"enabled": True},
        "review": {"enabled": True, "review_scope": "all"},
    }
    detector_form = configuration_module._form_from_config(
        PipelineConfig.model_validate(detector_form_payload)
    )
    assert detector_form["detectors"] == ["comprehend", "sonnet"]
    assert detector_form["bedrock_reasoning"] == "medium"
    assert detector_form["validation_enabled"] is True
    assert detector_form["review_mode"] == "all"

    wrong_shape = client.post(
        "/runs/new/source",
        data={
            "csrf_token": _token(client),
            "config_file": (BytesIO(b"- not\n- an-object\n"), "bad.yaml"),
        },
        content_type="multipart/form-data",
    )
    assert wrong_shape.status_code == 400

    rules_payload = {
        "rules": [
            {
                "id": "alice",
                "name": "Alice exact",
                "category": "NAME",
                "type": "exact",
                "pattern": "Alice",
            }
        ]
    }
    missing_rule_download = client.post(
        "/runs/new/rules.yaml",
        data={"csrf_token": _token(client)},
    )
    assert missing_rule_download.status_code == 400
    assert b"at least 1 item" in missing_rule_download.data
    assert (
        client.post(
            "/runs/new/rules/import",
            data={"csrf_token": _token(client)},
        ).status_code
        == 400
    )
    malformed_rule_import = client.post(
        "/runs/new/rules/import",
        data={
            "csrf_token": _token(client),
            "rules_file": (BytesIO(b"- not\n- an-object\n"), "bad-rules.yaml"),
        },
        content_type="multipart/form-data",
    )
    assert malformed_rule_import.status_code == 400
    imported_rules = client.post(
        "/runs/new/rules/import",
        data={
            "csrf_token": _token(client),
            "rules_file": (
                BytesIO(yaml.safe_dump(rules_payload).encode()),
                "editable-rules.yaml",
            ),
        },
        content_type="multipart/form-data",
    )
    assert imported_rules.get_json()["count"] == 1
    assert imported_rules.get_json()["source_name"] == "editable-rules.yaml"
    downloaded_rules = client.post(
        "/runs/new/rules.yaml",
        data={"csrf_token": _token(client)},
    )
    assert downloaded_rules.status_code == 200
    downloaded_rule_payload = yaml.safe_load(downloaded_rules.data)
    assert downloaded_rule_payload["rules"][0]["id"] == "alice"
    assert downloaded_rule_payload["rules"][0]["pattern"] == "Alice"
    downloaded_config = client.post(
        "/runs/new/configuration.yaml",
        data=_form(client, tmp_path, rules_enabled="yes", rules_json=json.dumps(rules_payload)),
    )
    assert downloaded_config.status_code == 200
    assert yaml.safe_load(downloaded_config.data)["config_version"] == 1
    invalid_config_download = client.post(
        "/runs/new/configuration.yaml",
        data=_form(client, tmp_path, rules_enabled="yes", rules_json="{"),
    )
    assert invalid_config_download.status_code == 400

    visual = client.post(
        "/runs/new/precheck",
        data=_form(
            client,
            tmp_path,
            entity_id_source="column",
            entity_id_column="patient_id",
            detectors=["comprehend", "sonnet"],
            bedrock_reasoning="medium",
            validation_enabled="yes",
            validation_input_cost="0.15",
            validation_output_cost="0.60",
            review_mode="all",
            rules_enabled="yes",
            rules_json=json.dumps(rules_payload),
            **{
                "replacement:NAME": "faker",
                "consistency:NAME": "record",
                "replacement:DATE": "date_shift",
                "date_minimum_weeks": "1",
                "date_maximum_weeks": "1",
            },
        ),
    )
    assert visual.status_code == 200
    assert draft.config_payload is not None
    visual_config = PipelineConfig.model_validate(draft.config_payload)
    assert [detector.backend for detector in visual_config.detection.detectors] == [
        "aws_comprehend_medical",
        "aws_bedrock",
    ]
    bedrock = visual_config.detection.detectors[1]
    assert bedrock.backend == "aws_bedrock"
    assert bedrock.reasoning_effort == "medium"
    assert visual_config.validation.model_id == "openai.gpt-oss-safeguard-120b"
    assert visual_config.validation.input_cost_per_million_tokens == 0.15
    assert visual_config.validation.output_cost_per_million_tokens == 0.60
    assert visual_config.review.enabled
    assert visual_config.review.review_scope == "all"
    assert visual_config.rules.embedded is not None
    assert visual_config.policy.categories["NAME"].action == "surrogate"

    policy_values = configuration_module.policy_form(visual_config.policy)

    assert policy_values["date_minimum_weeks"] == "1"
    assert policy_values["consistency:NAME"] == "record"
    assert not any(key.startswith("generator") for key in policy_values)

    name_replacement = visual_config.policy.categories["NAME"].surrogate
    assert name_replacement is not None
    assert name_replacement.method == "faker"
    assert name_replacement.secret_reference.startswith("literal:")

    reused_policy = configuration_module.policy_from_form(
        MultiDict(
            {
                "replacement:NAME": "custom_list",
                "consistency:NAME": "occurrence",
                "custom_values:NAME": "Patient A\nPatient B",
            }
        ),
        base_config=visual_config,
    )
    reused_surrogate = reused_policy.categories["NAME"].surrogate

    assert reused_surrogate is not None
    assert reused_surrogate.method == "custom_list"
    assert reused_surrogate.consistency == "occurrence"
    assert reused_surrogate.secret_reference == name_replacement.secret_reference
    assert (
        configuration_module._secret_reference(
            MultiDict({"secret_reference:NAME": "literal:provided"}),
            PhiCategory.NAME,
            base_config=None,
            defaults=None,
        )
        == "literal:provided"
    )
    assert configuration_module._secret_reference(
        MultiDict(),
        PhiCategory.LOCATION,
        base_config=visual_config,
        defaults=None,
    ).startswith("literal:")

    fallback_rules = client.post(
        "/runs/new/precheck",
        data=_form(client, tmp_path, rules_enabled="yes", rules_json=""),
    )
    assert fallback_rules.status_code == 200
    invalid_ui_rules = client.post(
        "/runs/new/precheck",
        data=_form(client, tmp_path, rules_enabled="yes", rules_json="[]"),
    )
    assert invalid_ui_rules.status_code == 400
    draft.rules_payload = None
    missing_rules = client.post(
        "/runs/new/precheck",
        data=_form(client, tmp_path, rules_enabled="yes", rules_json=""),
    )
    assert missing_rules.status_code == 400


def test_setup_form_helpers_cover_current_detection_review_and_replacements() -> None:
    policy = configuration_module.policy_from_form(
        MultiDict(
            {
                "replacement:NAME": "faker",
                "consistency:NAME": "record",
                "replacement:EMAIL": "custom_list",
                "consistency:EMAIL": "occurrence",
                "custom_values:EMAIL": "one@example.test\ntwo@example.test",
                "replacement:DATE": "date_shift",
                "date_minimum_weeks": "-4",
                "date_maximum_weeks": "8",
                "date_fallback": "redact",
            }
        )
    )
    name = policy.categories[PhiCategory.NAME].surrogate
    email = policy.categories[PhiCategory.EMAIL].surrogate
    date = policy.categories[PhiCategory.DATE].surrogate
    assert name is not None and name.method == "faker" and name.consistency == "record"
    assert email is not None and email.method == "custom_list"
    assert date is not None and date.method == "date_shift"
    assert configuration_module.policy_form(policy)["custom_values:EMAIL"] == (
        "one@example.test\ntwo@example.test"
    )

    assert configuration_module._detection_from_form(MultiDict()) == {
        "enabled": False,
        "detectors": [],
        "execution": {"workers": 2},
    }
    assert configuration_module._review_from_form(MultiDict({"review_mode": "all"})) == {
        "enabled": True,
        "review_scope": "all",
    }
    assert configuration_module._review_from_form(
        MultiDict({"validation_enabled": "yes", "review_mode": "none"})
    ) == {"enabled": True, "review_scope": "effective_validation_failures"}
    assert configuration_module._infer_columns([]) == ("", "", "")
    assert configuration_module._infer_columns(["record_id", "patient_id", "note"]) == (
        "record_id",
        "patient_id",
        "note",
    )


def test_setup_start_and_run_control_error_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    setup_app = create_ui_app(
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "setup-uploads",
    )
    setup_app.config["TESTING"] = True
    setup_client = setup_app.test_client()
    _upload(
        setup_client,
        b'{"record_id":"R1","text":"Note","site":"north"}\n',
        "notes.jsonl",
    )
    invalid = setup_client.post(
        "/runs/new/start",
        data=_form(setup_client, tmp_path, rules_enabled="yes", rules_json="{"),
    )
    assert invalid.status_code == 400

    with monkeypatch.context() as patcher:
        patcher.setattr(
            common_routes,
            "precheck_config",
            lambda *args, **kwargs: PrecheckResult(
                (PrecheckIssue("info", "ready", "Ready"),), record_count=1
            ),
        )

        def race(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError("job race")

        patcher.setattr(_state(setup_app).jobs, "start", race)
        raced = setup_client.post("/runs/new/start", data=_form(setup_client, tmp_path))
    assert raced.status_code == 302, raced.data.decode()

    controls_root = tmp_path / "controls"
    controls_root.mkdir()
    context = _created_context(controls_root)
    app = create_ui_app(
        context.run_dir,
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads",
    )
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/")
    base = f"/runs/{context.run_id}"
    assert client.post(f"{base}/continue", data={"csrf_token": _token(client)}).status_code == 302
    assert client.get(f"{base}/records?page=not-a-number").status_code == 200
    store = PipelineEngine(context).store
    store.update_run_status("blocked", updated_at=NOW)
    with monkeypatch.context() as patcher:
        patcher.setattr(
            _state(app).jobs,
            "start",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("job busy")),
        )
        assert (
            client.post(f"{base}/continue", data={"csrf_token": _token(client)}).status_code == 302
        )

    store.update_record_stage_state("R1", "detection", "retry_exhausted", updated_at=NOW)
    retried: list[str] = []

    class FakeControl:
        def __init__(self, supplied: object) -> None:
            del supplied

        def retry(self, *, record_id: str) -> None:
            retried.append(record_id)

    class FakeEngine:
        def __init__(self, supplied: object, *, dependencies: object) -> None:
            del supplied, dependencies

        def resume(self) -> None:
            return None

    with monkeypatch.context() as patcher:
        patcher.setattr(run_routes, "RunControlService", FakeControl)
        patcher.setattr(run_routes, "PipelineEngine", FakeEngine)
        response = client.post(f"{base}/retry-failed", data={"csrf_token": _token(client)})
        assert response.status_code == 302
        assert _state(app).jobs.wait(2).state == "completed"
    assert retried == ["R1"]

    store.update_record_stage_state("R1", "detection", "skipped", updated_at=NOW)
    assert (
        client.post(f"{base}/retry-failed", data={"csrf_token": _token(client)}).status_code == 302
    )

    class BrokenControl(FakeControl):
        def retry(self, *, record_id: str) -> None:
            raise ValueError(f"cannot retry {record_id}")

    with monkeypatch.context() as patcher:
        patcher.setattr(run_routes, "RunControlService", BrokenControl)
        assert (
            client.post(f"{base}/records/R1/retry", data={"csrf_token": _token(client)}).status_code
            == 302
        )


def test_revised_run_page_handles_unchanged_busy_created_and_start_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _created_context(tmp_path)
    app = create_ui_app(
        context.run_dir,
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads",
        runs_dir=context.config.run.output_dir,
    )
    app.config["TESTING"] = True
    client = app.test_client()
    base = f"/runs/{context.run_id}"

    page = client.get(f"{base}/revise")
    assert page.status_code == 200
    assert b"Revise run" in page.data

    unchanged = client.post(
        f"{base}/revise",
        data=_form(client, tmp_path, reason="no changes"),
    )
    assert unchanged.status_code == 400
    assert b"settings are unchanged" in unchanged.data

    entered = threading.Event()
    release = threading.Event()

    def block() -> None:
        entered.set()
        release.wait(2)

    state = _state(app)
    state.jobs.start("busy", block)
    assert entered.wait(1)
    busy = client.post(
        f"{base}/revise",
        data=_form(
            client,
            tmp_path,
            run_name="busy-child",
            reason="change name handling",
            **{"replacement:NAME": "retain"},
        ),
    )
    assert busy.status_code == 409
    release.set()
    assert state.jobs.wait(2).state == "completed"

    with monkeypatch.context() as patcher:
        patcher.setattr(
            state.jobs,
            "start",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("start race")),
        )
        raced = client.post(
            f"{base}/revise",
            data=_form(
                client,
                tmp_path,
                run_name="raced-child",
                reason="test race",
                **{"replacement:NAME": "retain"},
            ),
        )
    assert raced.status_code == 302
    assert "/runs/" in raced.headers["Location"]

    created = client.post(
        f"{base}/revise",
        data=_form(
            client,
            tmp_path,
            run_name="created-child",
            reason="change name handling",
            **{"replacement:NAME": "retain"},
        ),
    )
    assert created.status_code == 302
    child_id = created.headers["Location"].rstrip("/").rsplit("/", 1)[-1]
    assert state.jobs.wait(5).state == "completed"
    assert state.context_for(child_id).config.run.parent_run_id == context.run_id


def test_review_routes_surface_invalid_edits_pending_work_and_job_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _created_context(tmp_path, review_all=True)
    app = create_ui_app(
        context.run_dir,
        secret_key="test",
        temp_root=tmp_path / "uploads",
        reviewer_id="Reviewer",
    )
    app.config["TESTING"] = True
    client = app.test_client()
    base = f"/runs/{context.run_id}"
    client.get(f"{base}/review")
    token = _token(client)
    store = PipelineEngine(context).store

    assert client.get(f"{base}/review/missing").status_code == 404
    store.update_record_stage_state("R1", "review", "skipped", updated_at=NOW)
    assert client.get(f"{base}/review/R1").status_code == 409
    store.update_record_stage_state("R1", "review", "review_pending", updated_at=NOW)

    assert (
        client.post(
            f"{base}/review/R1/timer",
            data={"csrf_token": token, "action": "invalid"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"{base}/review/missing/timer", data={"csrf_token": token, "action": "pause"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"{base}/review/R1/timer",
            data={"csrf_token": token, "action": "set", "seconds": "-1"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"{base}/review/R1/timer",
            data={"csrf_token": token, "action": "adjust", "delta_seconds": "bad"},
        ).status_code
        == 400
    )
    invalid_preview = client.post(
        f"{base}/review/R1/preview",
        json={
            "span_events": [
                {
                    "event_id": "remove-missing",
                    "operation": "remove",
                    "group_id": "missing-group",
                    "finding_ids": ["missing"],
                }
            ]
        },
        headers={"X-CSRF-Token": token},
    )
    assert invalid_preview.status_code == 400
    assert (
        client.post(
            f"{base}/review/R1/draft",
            data={
                "csrf_token": token,
                "basis_plan_revision": "1",
                "span_events": "{",
            },
        ).status_code
        == 302
    )
    assert (
        client.post(
            f"{base}/review/R1/decision",
            data={
                "csrf_token": token,
                "basis_plan_revision": "1",
                "span_events": "[]",
                "action": "unknown",
            },
        ).status_code
        == 302
    )
    assert (
        client.post(
            f"{base}/review/R1/decision",
            data={
                "csrf_token": token,
                "basis_plan_revision": "1",
                "span_events": "[]",
                "action": "correct",
            },
        ).status_code
        == 302
    )
    assert client.post(f"{base}/review/complete", data={"csrf_token": token}).status_code == 302

    for record_id in ("R1", "R2"):
        assert (
            client.post(
                f"{base}/review/{record_id}/decision",
                data={
                    "csrf_token": token,
                    "basis_plan_revision": "1",
                    "span_events": "[]",
                    "action": "approve",
                },
            ).status_code
            == 302
        )
    with monkeypatch.context() as patcher:
        patcher.setattr(
            _state(app).jobs,
            "start",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("completion busy")),
        )
        assert client.post(f"{base}/review/complete", data={"csrf_token": token}).status_code == 302


def test_review_edit_helper_and_expired_setup_draft(tmp_path: Path) -> None:
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/runs/new")
    with client.session_transaction() as session:
        session["setup_draft_id"] = "expired"
    assert client.get("/runs/new/configure").status_code == 409

    with app.test_request_context(
        "/runs/test/review/R1/draft",
        method="POST",
        data={"span_events": "{}"},
    ):
        with pytest.raises(ValueError, match="JSON list"):
            review_routes.review_edits([], [])
    with app.test_request_context(
        "/runs/test/review/R1/draft",
        method="POST",
        data={"span_events": "[]", "structured_events": "{}"},
    ):
        with pytest.raises(ValueError, match="structured_events must be a JSON list"):
            review_routes.review_edits([], [])
    structured_event = {
        "event_id": "structured-1",
        "column_name": "patient_name",
        "category": "NAME",
        "original_value": "Alice",
        "replacement_value": "Patient A",
    }
    with app.test_request_context(
        "/runs/test/review/R1/draft",
        method="POST",
        data={
            "span_events": "[]",
            "structured_events": json.dumps([structured_event]),
        },
    ):
        with pytest.raises(ValueError, match="Unknown structured PHI fields"):
            review_routes.review_edits([], [])
    with app.test_request_context(
        "/runs/test/review/R1/draft",
        method="POST",
        data={
            "span_events": "[]",
            "structured_events": "[]",
            "outcome:validation-b": "confirmed",
            "comment:validation-b": "Confirmed",
        },
    ):
        events, structured_events, reviews = review_routes.review_edits(
            [
                {"validation_finding_id": "validation-a"},
                {"validation_finding_id": "validation-b"},
            ],
            [],
        )
    assert events == []
    assert structured_events == []
    assert [review.validation_finding_id for review in reviews] == ["validation-b"]
    assert reviews[0].comment == "Confirmed"

    generated_policy = configuration_module.policy_from_form(
        MultiDict({"replacement:DATE": "date_shift"})
    )
    date_replacement = generated_policy.categories[PhiCategory.DATE].surrogate
    assert date_replacement is not None
    assert date_replacement.secret_reference.startswith("literal:")
