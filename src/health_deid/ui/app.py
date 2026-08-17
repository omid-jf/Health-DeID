from __future__ import annotations

import logging
import os
import secrets
import weakref
import webbrowser
from pathlib import Path
from threading import Timer

from flask import Flask, Response, abort, request, session

from health_deid import __version__
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.engine import EngineDependencies
from health_deid.ui.routes import register_routes
from health_deid.ui.state import UiState

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_PHI_COLORS = {
    "NAME": "primary",
    "DATE": "info",
    "AGE": "secondary",
    "ID": "dark",
    "LOCATION": "success",
    "PHONE_OR_FAX": "warning",
    "EMAIL": "danger",
    "URL": "info",
    "IP_ADDRESS": "secondary",
    "BIOMETRIC": "danger",
    "PHOTO": "dark",
    "OTHER_ID": "warning",
    "PROFESSION": "primary",
    "UNMAPPED": "danger",
}


def _format_duration(value: int | float) -> str:
    total = max(0, round(value))
    hours, remainder = divmod(total, 3_600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def create_ui_app(
    run_path: str | Path | None = None,
    *,
    secret_key: str | None = None,
    dependencies: EngineDependencies | None = None,
    temp_root: str | Path | None = None,
    reviewer_id: str,
    runs_dir: str | Path = "runs",
) -> Flask:
    """Create the unified local setup, processing, review, and reporting app."""

    context = RunContext.from_run_path(run_path) if run_path is not None else None
    state = UiState(
        context=context,
        dependencies=dependencies,
        temp_root=temp_root,
        reviewer_id=reviewer_id,
        runs_dir=runs_dir,
    )
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.jinja_env.filters["duration"] = _format_duration
    app.config.update(
        SECRET_KEY=secret_key or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024 * 1024,
        HEALTH_DEID_UI_STATE=state,
    )
    weakref.finalize(app, state.close)
    register_routes(app)

    @app.before_request
    def protect_post_requests() -> None:
        token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
        if request.method != "POST":
            return
        supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(supplied, token):
            abort(400, description="Invalid or missing CSRF token.")

    @app.context_processor
    def inject_ui_context() -> dict[str, object]:
        run_id = (request.view_args or {}).get("run_id")
        try:
            active = state.context_for(str(run_id)) if run_id is not None else None
        except KeyError:
            active = None
        return {
            "csrf_token": session.setdefault("csrf_token", secrets.token_urlsafe(32)),
            "active_run": active,
            "job": state.jobs.snapshot(),
            "reviewer_id": state.reviewer_id,
            "app_version": __version__,
            "active_endpoint": request.endpoint,
            "phi_colors": _PHI_COLORS,
        }

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

    return app


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
    """Run the unified app on a loopback interface."""

    if host not in _LOOPBACK_HOSTS:
        raise ValueError("The local UI only supports loopback hosts.")
    if not 1 <= port <= 65_535:
        raise ValueError("port must be between 1 and 65535.")
    app = create_ui_app(
        run_path,
        dependencies=dependencies,
        reviewer_id=reviewer_id,
        runs_dir=runs_dir,
    )
    if reload:
        app.config["TEMPLATES_AUTO_RELOAD"] = True
        app.jinja_env.auto_reload = True

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    initial_reloader_process = os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    if open_browser and (not reload or initial_reloader_process):
        browser_host = "127.0.0.1" if host == "::1" else host
        Timer(0.75, webbrowser.open, args=(f"http://{browser_host}:{port}/",)).start()
    try:
        app.run(host=host, port=port, debug=False, use_reloader=reload)
    except OSError as exc:
        raise RuntimeError(
            f"Could not start the local UI on {host}:{port}. The port may be reserved or "
            "already in use; retry with a different port, for example --port 8765. "
            f"Original socket error: {exc}"
        ) from exc


__all__ = ["create_ui_app", "run_ui_app"]
