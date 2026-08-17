"""Register local routes directly on the Flask application."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask

from health_deid.ui.routes import export as export_routes
from health_deid.ui.routes import setup as setup_routes
from health_deid.ui.routes.home import home
from health_deid.ui.routes.review import (
    complete_review,
    decide_review,
    review_preview,
    review_queue,
    review_record,
    review_timer,
    save_review_draft,
)
from health_deid.ui.routes.runs import (
    dashboard,
    download_run_configuration,
    download_run_rules,
    record_audit,
    records,
    resume_run,
    retry_failed,
    retry_record,
    settings,
    status_api,
)

type ViewFunction = Callable[..., Any]

_ROUTES: tuple[tuple[str, str, ViewFunction, tuple[str, ...]], ...] = (
    ("/", "home", home, ("GET",)),
    ("/runs/new", "setup", setup_routes.setup, ("GET",)),
    ("/runs/new/source", "upload_source", setup_routes.upload_source, ("POST",)),
    ("/runs/new/configure", "configure", setup_routes.configure, ("GET",)),
    ("/runs/new/rules/import", "import_rules", setup_routes.import_rules, ("POST",)),
    (
        "/runs/new/rules.yaml",
        "download_draft_rules",
        setup_routes.download_draft_rules,
        ("POST",),
    ),
    (
        "/runs/new/configuration.yaml",
        "download_draft_configuration",
        setup_routes.download_draft_configuration,
        ("POST",),
    ),
    (
        "/runs/new/configuration.json",
        "preview_draft_configuration",
        setup_routes.preview_draft_configuration,
        ("POST",),
    ),
    ("/runs/new/precheck", "precheck", setup_routes.precheck, ("POST",)),
    ("/runs/new/start", "start_run", setup_routes.start_run, ("POST",)),
    ("/runs/<run_id>", "dashboard", dashboard, ("GET",)),
    (
        "/runs/<run_id>/configuration.yaml",
        "download_run_configuration",
        download_run_configuration,
        ("GET",),
    ),
    ("/runs/<run_id>/rules.yaml", "download_run_rules", download_run_rules, ("GET",)),
    ("/runs/<run_id>/api/status", "status_api", status_api, ("GET",)),
    ("/runs/<run_id>/continue", "resume_run", resume_run, ("POST",)),
    ("/runs/<run_id>/retry-failed", "retry_failed", retry_failed, ("POST",)),
    ("/runs/<run_id>/records", "records", records, ("GET",)),
    (
        "/runs/<run_id>/records/<path:record_id>",
        "record_audit",
        record_audit,
        ("GET",),
    ),
    (
        "/runs/<run_id>/records/<path:record_id>/retry",
        "retry_record",
        retry_record,
        ("POST",),
    ),
    ("/runs/<run_id>/revise", "settings", settings, ("GET", "POST")),
    ("/runs/<run_id>/review", "review_queue", review_queue, ("GET",)),
    (
        "/runs/<run_id>/review/<path:record_id>",
        "review_record",
        review_record,
        ("GET",),
    ),
    (
        "/runs/<run_id>/review/<path:record_id>/timer",
        "review_timer",
        review_timer,
        ("POST",),
    ),
    (
        "/runs/<run_id>/review/<path:record_id>/preview",
        "review_preview",
        review_preview,
        ("POST",),
    ),
    (
        "/runs/<run_id>/review/<path:record_id>/draft",
        "save_review_draft",
        save_review_draft,
        ("POST",),
    ),
    (
        "/runs/<run_id>/review/<path:record_id>/decision",
        "decide_review",
        decide_review,
        ("POST",),
    ),
    (
        "/runs/<run_id>/review/complete",
        "complete_review",
        complete_review,
        ("POST",),
    ),
    ("/runs/<run_id>/export", "export", export_routes.export, ("GET", "POST")),
)


def register_routes(app: Flask) -> None:
    for rule, endpoint, view, methods in _ROUTES:
        app.add_url_rule(
            rule,
            endpoint=f"ui.{endpoint}",
            view_func=view,
            methods=list(methods),
        )


__all__ = ["register_routes"]
