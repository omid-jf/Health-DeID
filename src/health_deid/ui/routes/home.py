"""Home page."""

from __future__ import annotations

from flask import render_template

from health_deid.ui.route_helpers import state


def home() -> str:
    return render_template(
        "ui/home.html",
        runs=state().runs(),
    )
