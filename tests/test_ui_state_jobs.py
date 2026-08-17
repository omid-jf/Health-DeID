from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from flask import render_template_string

import health_deid.ui.app as app_module
from health_deid.models.config import PipelineConfig
from health_deid.models.input import InputColumnPreview, InputPreview
from health_deid.pipeline.engine import PipelineEngine
from health_deid.ui.app import create_ui_app, run_ui_app
from health_deid.ui.state import BackgroundJobRegistry, JobSnapshot, SetupDraft, UiState


def _preview(path: Path) -> InputPreview:
    return InputPreview(
        path=path,
        format="jsonl",
        total_records=1,
        columns=[InputColumnPreview(name="record_id", dtype="String")],
        sample_records=[{"record_id": "R1"}],
    )


def test_job_registry_success_duplicate_wait_and_snapshot() -> None:
    registry = BackgroundJobRegistry()
    assert registry.wait().as_dict() == {
        "job_id": None,
        "state": "idle",
        "operation": None,
        "started_at": None,
        "finished_at": None,
        "error": None,
    }
    with pytest.raises(ValueError, match="blank"):
        registry.start("  ", lambda: None)

    entered = threading.Event()
    release = threading.Event()

    def blocking_action() -> None:
        entered.set()
        release.wait(2)

    started = registry.start(" process ", blocking_action)
    assert entered.wait(1)
    assert started.state == "running"
    assert started.operation == "process"
    assert registry.wait(0).state == "running"
    with pytest.raises(RuntimeError, match="already running"):
        registry.start("other", lambda: None)
    release.set()
    completed = registry.wait(2)
    assert completed.state == "completed"
    assert completed.finished_at is not None

    unchanged = registry.snapshot()
    registry._run("not-the-current-job", lambda: None)
    assert registry.snapshot() == unchanged


@pytest.mark.parametrize(
    ("exception", "message"),
    [(RuntimeError("backend failed"), "backend failed"), (RuntimeError(), "RuntimeError")],
)
def test_job_registry_surfaces_failures(exception: BaseException, message: str) -> None:
    registry = BackgroundJobRegistry()

    def fail() -> None:
        raise exception

    registry.start("failure", fail)
    failed = registry.wait(2)
    assert failed.state == "failed"
    assert failed.error == message


def test_ui_state_draft_lifecycle_with_supplied_temp_root(tmp_path: Path) -> None:
    temp_root = tmp_path / "uploads"
    state = UiState(
        context=None,
        dependencies=None,
        temp_root=temp_root,
        reviewer_id="Test Reviewer",
    )
    with pytest.raises(KeyError, match="Unknown run"):
        state.context_for("missing")
    context = cast(
        Any,
        SimpleNamespace(
            run_id="run-1",
            config=SimpleNamespace(run=SimpleNamespace(output_dir=tmp_path / "runs")),
        ),
    )
    state.remember_context(context)
    assert state.context_for("run-1") is context

    first_path = temp_root / "first.jsonl"
    first_path.write_text("first", encoding="utf-8")
    state.add_draft(SetupDraft("draft", first_path, "first.jsonl", _preview(first_path)))
    assert state.draft("draft").source_name == "first.jsonl"

    replacement_path = temp_root / "replacement.jsonl"
    replacement_path.write_text("replacement", encoding="utf-8")
    state.add_draft(
        SetupDraft("draft", replacement_path, "replacement.jsonl", _preview(replacement_path))
    )
    assert not first_path.exists()
    with pytest.raises(KeyError, match="expired"):
        state.draft("missing")

    state.discard_draft("missing")
    state.discard_draft("draft")
    assert not replacement_path.exists()
    assert temp_root.exists()

    referenced_path = tmp_path / "referenced.jsonl"
    referenced_path.write_text("referenced", encoding="utf-8")
    state.add_draft(
        SetupDraft(
            "referenced",
            referenced_path,
            "referenced.jsonl",
            _preview(referenced_path),
            owns_source_file=False,
        )
    )
    owned_replacement = temp_root / "owned-replacement.jsonl"
    owned_replacement.write_text("owned", encoding="utf-8")
    state.add_draft(
        SetupDraft(
            "referenced",
            owned_replacement,
            "owned-replacement.jsonl",
            _preview(owned_replacement),
        )
    )
    assert referenced_path.exists()
    state.discard_draft("referenced")
    assert not owned_replacement.exists()

    state.add_draft(
        SetupDraft(
            "external-last",
            referenced_path,
            "referenced.jsonl",
            _preview(referenced_path),
            owns_source_file=False,
        )
    )

    last_path = temp_root / "last.jsonl"
    last_path.write_text("last", encoding="utf-8")
    state.add_draft(SetupDraft("last", last_path, "last.jsonl", _preview(last_path)))
    state.close()
    assert not last_path.exists()
    assert referenced_path.exists()
    assert temp_root.exists()


def test_ui_state_reviewer_and_fixed_runs_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="reviewer_id cannot be blank"):
        UiState(context=None, dependencies=None, temp_root=tmp_path / "blank", reviewer_id=" ")

    source = tmp_path / "records.jsonl"
    source.write_text('{"record_id":"R1","text":"Note"}\n', encoding="utf-8")
    config = PipelineConfig.model_validate(
        {
            "run": {"output_dir": tmp_path / "runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
            },
            "detection": {"enabled": False},
        }
    )
    context = PipelineEngine.create(config).context
    discovered = UiState(
        context=None,
        dependencies=None,
        temp_root=tmp_path / "discovered-root",
        reviewer_id="Test Reviewer",
        runs_dir=context.config.run.output_dir,
    )
    assert discovered.context_for(context.run_id).run_dir == context.run_dir
    assert discovered.context_for(context.run_id).run_dir == context.run_dir
    assert discovered.runs()[0]["run_id"] == context.run_id
    with pytest.raises(KeyError, match="Unknown run"):
        discovered.context_for("missing")

    ordinary_file = context.config.run.output_dir / "ordinary.txt"
    ordinary_file.write_text("not a run", encoding="utf-8")
    nested = context.config.run.output_dir / "nested" / "too-deep" / "run.sqlite"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(context.database_path.read_bytes())
    assert len(discovered.runs()) == 1

    corrupt = context.config.run.output_dir / "corrupt" / "run.sqlite"
    corrupt.parent.mkdir()
    corrupt.write_text("not sqlite", encoding="utf-8")
    assert discovered.runs()[0]["run_id"] == context.run_id


def test_ui_state_removes_owned_temp_root() -> None:
    state = UiState(
        context=None,
        dependencies=None,
        temp_root=None,
        reviewer_id="Test Reviewer",
    )
    owned_root = state.temp_root
    source = owned_root / "draft.jsonl"
    source.write_text("draft", encoding="utf-8")
    state.add_draft(SetupDraft("draft", source, "draft.jsonl", _preview(source)))

    state.close()

    assert not owned_root.exists()


def test_create_app_generates_secret_and_accepts_header_csrf(tmp_path: Path) -> None:
    app = create_ui_app(reviewer_id="Test Reviewer", temp_root=tmp_path / "uploads")

    @app.get("/context-probe/<run_id>")
    def context_probe(run_id: str) -> str:
        del run_id
        return render_template_string("{{ active_run or 'none' }}")

    app.config["TESTING"] = True
    client = app.test_client()
    assert app.secret_key
    assert client.get("/context-probe/missing").data == b"none"
    client.get("/")
    with client.session_transaction() as session:
        token = str(session["csrf_token"])

    response = client.post("/runs/open", headers={"X-CSRF-Token": token}, data={})

    assert response.status_code == 405
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_ui_runner_browser_hosts_and_no_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    runs: list[dict[str, object]] = []
    timers: list[tuple[float, object, tuple[str, ...]]] = []

    class FakeApp:
        def run(self, **kwargs: object) -> None:
            runs.append(kwargs)

    class FakeTimer:
        def __init__(self, interval: float, function: object, args: tuple[str, ...]) -> None:
            timers.append((interval, function, args))

        def start(self) -> None:
            return None

    monkeypatch.setattr(app_module, "create_ui_app", lambda *args, **kwargs: FakeApp())
    monkeypatch.setattr(app_module, "Timer", FakeTimer)
    monkeypatch.setattr(cast(Any, app_module).webbrowser, "open", cast(Any, object()))

    run_ui_app(reviewer_id="Test Reviewer", host="::1", port=5151)
    run_ui_app(reviewer_id="Test Reviewer", host="localhost", port=5152)
    run_ui_app(reviewer_id="Test Reviewer", host="127.0.0.1", port=5153, open_browser=False)

    assert [timer[2][0] for timer in timers] == [
        "http://127.0.0.1:5151/",
        "http://localhost:5152/",
    ]
    assert runs == [
        {"host": "::1", "port": 5151, "debug": False, "use_reloader": False},
        {"host": "localhost", "port": 5152, "debug": False, "use_reloader": False},
        {"host": "127.0.0.1", "port": 5153, "debug": False, "use_reloader": False},
    ]


def test_ui_runner_explains_socket_binding_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingApp:
        def run(self, **kwargs: object) -> None:
            del kwargs
            raise OSError("socket access forbidden")

    monkeypatch.setattr(app_module, "create_ui_app", lambda *args, **kwargs: FailingApp())

    with pytest.raises(RuntimeError, match=r"different port.*--port 8765"):
        run_ui_app(
            reviewer_id="Test Reviewer",
            port=5000,
            open_browser=False,
        )


@pytest.mark.parametrize(
    "kwargs",
    [{"host": "0.0.0.0"}, {"port": 0}, {"port": 65_536}],
)
def test_ui_runner_rejects_nonlocal_or_invalid_bindings(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        run_ui_app(reviewer_id="Test Reviewer", open_browser=False, **kwargs)  # type: ignore[arg-type]


def test_job_snapshot_is_immutable_value() -> None:
    snapshot = JobSnapshot(job_id="job", state="completed", operation="run")
    assert snapshot.as_dict()["operation"] == "run"
