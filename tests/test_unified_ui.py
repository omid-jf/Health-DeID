from __future__ import annotations

from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask.testing import FlaskClient

import health_deid.ui.app as ui_app_module
from health_deid.models.config import PipelineConfig
from health_deid.pipeline.engine import PipelineEngine
from health_deid.ui import create_ui_app, run_ui_app


def _csrf_token(client: FlaskClient) -> str:
    with client.session_transaction() as session:
        return str(session["csrf_token"])


def test_unified_ui_home_security_and_csrf(tmp_path: Path) -> None:
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b'<h1 class="h3 mb-1">Runs</h1>' in response.data
    assert b"Recent runs" not in response.data
    assert b">New run<" in response.data
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    rejected = client.post("/runs/open", data={"run_path": str(tmp_path)})
    assert rejected.status_code == 400


def test_ui_modals_use_bootstrap_contract() -> None:
    project_root = Path(__file__).resolve().parents[1]
    ui_root = project_root / "src" / "health_deid" / "ui"
    templates = ui_root / "templates" / "ui"
    static = ui_root / "static"
    modal_templates = (
        templates / "dashboard.html",
        templates / "export.html",
        templates / "home.html",
        templates / "setup_configure.html",
        templates / "_rules_modal.html",
    )
    markup = "\n".join(path.read_text(encoding="utf-8") for path in modal_templates)

    for obsolete in (
        "<dialog",
        "app-modal",
        "modal-shell",
        "wide-modal",
        "data-open-dialog",
        "data-close-dialog",
        "data-directory-close",
    ):
        assert obsolete not in markup

    for modal_id in (
        "configuration-json-dialog",
        "report-dialog",
        "rule-dialog",
        "rules-dialog",
        "rules-json-dialog",
    ):
        assert f'id="{modal_id}"' in markup
        assert f'aria-labelledby="{modal_id}-title"' in markup

    for target in (
        "#report-dialog",
        "#rule-dialog",
        "#rules-dialog",
        "#rules-json-dialog",
    ):
        assert f'data-bs-target="{target}"' in markup
    setup_script = (static / "setup-ui.js").read_text(encoding="utf-8")
    assert '"configuration-json-dialog"' in setup_script
    assert "bootstrap.Modal.getOrCreateInstance" in setup_script

    assert 'class="modal fade"' in markup
    assert 'class="modal-content"' in markup
    assert 'data-bs-dismiss="modal"' in markup

    base = (templates / "base.html").read_text(encoding="utf-8")
    bundle_name = "bootstrap-5.3.8.bundle.min.js"
    assert bundle_name in base
    assert "local-time.js" in base
    assert "Bootstrap v5.3.8" in (static / "vendor" / bundle_name).read_text(encoding="utf-8")

    local_time = (static / "local-time.js").read_text(encoding="utf-8")
    assert 'querySelectorAll("[data-local-datetime]")' in local_time
    assert "Intl.DateTimeFormat" in local_time

    custom_css = (static / "ui.css").read_text(encoding="utf-8")
    for obsolete_selector in (
        ".app-modal",
        ".modal-shell",
        ".wide-modal",
        ".icon-button",
    ):
        assert obsolete_selector not in custom_css

    application_scripts = "\n".join(
        (static / name).read_text(encoding="utf-8") for name in ("dashboard.js", "setup-ui.js")
    )
    assert "showModal" not in application_scripts
    assert "data-open-dialog" not in application_scripts
    assert "data-close-dialog" not in application_scripts
    assert "bootstrap.Modal.getOrCreateInstance" in application_scripts
    assert "directory-browser" not in application_scripts


def test_unified_ui_uploads_and_previews_jsonl(tmp_path: Path) -> None:
    app = create_ui_app(
        reviewer_id="Test Reviewer", secret_key="test", temp_root=tmp_path / "uploads"
    )
    app.config["TESTING"] = True
    client = app.test_client()
    client.get("/runs/new")

    response = client.post(
        "/runs/new/source",
        data={
            "csrf_token": _csrf_token(client),
            "source": (
                BytesIO(b'{"record_id":"N001","text":"Jane arrived."}\n'),
                "notes.jsonl",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Configure run" in response.data
    assert b"Run name" in response.data
    assert b"Column mapping" in response.data
    assert b"record_id" in response.data
    assert b"Jane arrived." in response.data
    assert b"Preview first" in response.data
    assert b"Check setup" in response.data


def test_unified_ui_opens_run_and_exposes_live_status(tmp_path: Path) -> None:
    source = tmp_path / "records.jsonl"
    source.write_text('{"record_id":"N001","text":"No PHI."}\n', encoding="utf-8")
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
    engine = PipelineEngine.create(config)
    app = create_ui_app(
        engine.context.run_dir,
        reviewer_id="Test Reviewer",
        secret_key="test",
        temp_root=tmp_path / "uploads",
    )
    app.config["TESTING"] = True
    client = app.test_client()

    dashboard = client.get(f"/runs/{engine.context.run_id}")
    status = client.get(f"/runs/{engine.context.run_id}/api/status")

    assert dashboard.status_code == 200
    assert engine.context.run_id.encode() in dashboard.data
    assert b"Validator output" not in dashboard.data
    assert status.status_code == 200
    assert status.get_json()["report"]["records"]["denominator"] == 1
    assert status.get_json()["job"]["state"] == "idle"


@pytest.mark.parametrize("kwargs", [{"host": "0.0.0.0"}, {"port": 0}])
def test_unified_ui_runner_is_loopback_only(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        run_ui_app(reviewer_id="Test Reviewer", open_browser=False, **kwargs)  # type: ignore[arg-type]


def test_unified_ui_runner_enables_development_reload(monkeypatch: pytest.MonkeyPatch) -> None:
    run_arguments: dict[str, object] = {}

    class FakeApp:
        def __init__(self) -> None:
            self.config: dict[str, object] = {}
            self.jinja_env = SimpleNamespace(auto_reload=False)

        def run(self, **kwargs: object) -> None:
            run_arguments.update(kwargs)

    app = FakeApp()
    monkeypatch.setattr(ui_app_module, "create_ui_app", lambda *args, **kwargs: app)

    ui_app_module.run_ui_app(
        reviewer_id="Test Reviewer",
        open_browser=False,
        reload=True,
    )

    assert app.config["TEMPLATES_AUTO_RELOAD"] is True
    assert app.jinja_env.auto_reload is True
    assert run_arguments == {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False,
        "use_reloader": True,
    }
