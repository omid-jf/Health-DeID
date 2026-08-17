"""Human-review queue, workspace, timer, and decision routes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

from flask import abort, flash, jsonify, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from pydantic import ValidationError

from health_deid.core.taxonomy import PHI_CATEGORY_TO_PLACEHOLDER, PhiCategory
from health_deid.models.review import (
    ReviewDecision,
    ReviewSpanEvent,
    ReviewStructuredEvent,
    ReviewWorkspace,
    ValidationFindingReview,
)
from health_deid.pipeline.engine import PipelineEngine
from health_deid.pipeline.review import ReviewService, build_review_decision_id
from health_deid.ui.route_helpers import require_context, review_service, state, store


def review_queue(run_id: str) -> str:
    context = require_context(run_id)
    summary = review_service(context).queue_summary()
    return render_template("ui/review_queue.html", context=context, summary=summary)


def review_record(run_id: str, record_id: str) -> str:
    context = require_context(run_id)
    service = review_service(context)
    reviewer_id = state().reviewer_id

    try:
        record = service.record(record_id)
        workspace = service.open_workspace(record_id, reviewer_id)
    except KeyError:
        abort(404)

    identifiers = _queue_record_ids(service)
    try:
        index = identifiers.index(record_id)
    except ValueError:
        abort(409, description="This record is not part of the current review.")

    run_store = store(context)
    row = run_store.read_record(record_id)
    _, policy = run_store.read_active_policy()
    return render_template(
        "ui/review_record.html",
        context=context,
        record=record,
        workspace=workspace,
        workspace_payload=workspace.model_dump(mode="json"),
        validation_review_map={
            item.validation_finding_id: item.model_dump(mode="json")
            for item in workspace.validation_finding_reviews
        },
        metadata=json.loads(str(row["metadata_json"])),
        span_groups=[group.model_dump(mode="json") for group in record.span_groups],
        categories=[category.value for category in PhiCategory],
        placeholders={
            category.value: PHI_CATEGORY_TO_PLACEHOLDER[category] for category in PhiCategory
        },
        policy=policy.model_dump(mode="json"),
        position=index + 1,
        total=len(identifiers),
        previous_id=identifiers[index - 1] if index else None,
        next_id=identifiers[index + 1] if index + 1 < len(identifiers) else None,
    )


def review_timer(run_id: str, record_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    action = request.form.get("action", "")
    if action not in {"start", "pause", "restart", "adjust", "set"}:
        return jsonify({"error": "Unknown timer action."}), 400

    try:
        workspace = _update_timer(
            review_service(context),
            record_id=record_id,
            reviewer_id=state().reviewer_id,
            action=action,
        )
    except (KeyError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(
        {
            "review_seconds": workspace.review_seconds,
            "running": workspace.timer_started_at is not None,
        }
    )


def review_preview(run_id: str, record_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("span_events"), list):
        return jsonify({"error": "span_events must be a JSON list."}), 400

    try:
        events = [ReviewSpanEvent.model_validate(item) for item in payload["span_events"]]
        structured_events = [
            ReviewStructuredEvent.model_validate(item)
            for item in payload.get("structured_events", [])
        ]
        service = review_service(context)
        text = service.preview(
            record_id,
            events,
            reviewer_id=state().reviewer_id,
        )
        structured_fields = service.preview_structured(record_id, structured_events)
    except (KeyError, ValidationError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

    return jsonify({"text": text, "structured_fields": structured_fields})


def save_review_draft(run_id: str, record_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    service = review_service(context)
    reviewer_id = state().reviewer_id

    try:
        current = service.record(record_id)
        events, structured_events, validation_reviews = review_edits(
            current.validation_findings,
            current.structured_fields,
        )
        service.save_workspace(
            record_id=record_id,
            reviewer_id=reviewer_id,
            basis_plan_revision=_basis_plan_revision(current.plan_revision),
            span_events=events,
            structured_events=structured_events,
            validation_finding_reviews=validation_reviews,
            record_comment=request.form.get("record_comment") or None,
        )
        service.set_timer(record_id, reviewer_id, running=False)
    except (json.JSONDecodeError, KeyError, ValidationError, ValueError) as error:
        flash(str(error), "error")
        return redirect(url_for("ui.review_record", run_id=run_id, record_id=record_id))

    flash("Draft saved. This record remains in the review queue.", "success")
    return redirect(url_for("ui.review_queue", run_id=run_id))


def decide_review(run_id: str, record_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    service = review_service(context)

    try:
        decision = _review_decision(service, record_id=record_id)
        service.decide(decision)
    except (json.JSONDecodeError, KeyError, ValidationError, ValueError) as error:
        flash(str(error), "error")
        return redirect(url_for("ui.review_record", run_id=run_id, record_id=record_id))

    flash("Review saved.", "success")
    next_pending = service.queue()
    if next_pending:
        return redirect(url_for("ui.review_record", run_id=run_id, record_id=next_pending[0]))

    return redirect(url_for("ui.review_queue", run_id=run_id))


def complete_review(run_id: str) -> ResponseReturnValue:
    context = require_context(run_id)
    summary = review_service(context).queue_summary()
    pending = summary["pending"]
    assert isinstance(pending, int)
    if pending > 0:
        flash("Complete or exclude every required record before continuing.", "warning")
        return redirect(url_for("ui.review_queue", run_id=run_id))

    ui_state = state()
    try:
        ui_state.jobs.start(
            "complete-review",
            PipelineEngine(context, dependencies=ui_state.dependencies).resume,
        )
    except RuntimeError as error:
        flash(str(error), "error")
        return redirect(url_for("ui.review_queue", run_id=run_id))

    return redirect(url_for("ui.dashboard", run_id=run_id))


def review_edits(
    validation_findings: list[dict[str, object]],
    structured_fields: list[dict[str, object]],
) -> tuple[
    list[ReviewSpanEvent],
    list[ReviewStructuredEvent],
    list[ValidationFindingReview],
]:
    events = _span_events()
    structured_events = _structured_events()
    _validate_structured_columns(structured_events, structured_fields)
    validation_reviews = _validation_reviews(validation_findings)
    return events, structured_events, validation_reviews


def _json_list(field_name: str) -> list[object]:
    raw_items = json.loads(request.form.get(field_name, "[]"))
    if not isinstance(raw_items, list):
        raise ValueError(f"{field_name} must be a JSON list.")

    return raw_items


def _span_events() -> list[ReviewSpanEvent]:
    return [ReviewSpanEvent.model_validate(item) for item in _json_list("span_events")]


def _structured_events() -> list[ReviewStructuredEvent]:
    return [ReviewStructuredEvent.model_validate(item) for item in _json_list("structured_events")]


def _validate_structured_columns(
    events: list[ReviewStructuredEvent],
    structured_fields: list[dict[str, object]],
) -> None:
    allowed_columns = {str(item["column_name"]) for item in structured_fields}
    unknown_columns = {event.column_name for event in events} - allowed_columns
    if unknown_columns:
        raise ValueError("Unknown structured PHI fields: " + ", ".join(sorted(unknown_columns)))


def _validation_reviews(
    findings: list[dict[str, object]],
) -> list[ValidationFindingReview]:
    reviews: list[ValidationFindingReview] = []
    reviewer_id = state().reviewer_id

    for finding in findings:
        finding_id = str(finding["validation_finding_id"])
        outcome = request.form.get(f"outcome:{finding_id}", "").strip()
        if not outcome:
            continue

        reviews.append(
            ValidationFindingReview.model_validate(
                {
                    "validation_finding_id": finding_id,
                    "outcome": outcome,
                    "reviewer_id": reviewer_id,
                    "comment": request.form.get(f"comment:{finding_id}") or None,
                }
            )
        )

    return reviews


def _queue_record_ids(service: ReviewService) -> list[str]:
    items = cast(list[dict[str, object]], service.queue_summary()["items"])
    return [str(item["record_id"]) for item in items]


def _update_timer(
    service: ReviewService,
    *,
    record_id: str,
    reviewer_id: str,
    action: str,
) -> ReviewWorkspace:
    if action in {"start", "pause"}:
        return service.set_timer(
            record_id,
            reviewer_id,
            running=action == "start",
        )

    current = service.open_workspace(record_id, reviewer_id, start_timer=False)
    running = current.timer_started_at is not None
    if action == "restart":
        seconds = 0
        running = True
    elif action == "adjust":
        seconds = max(
            0,
            current.review_seconds + int(request.form.get("delta_seconds", "0")),
        )
    else:
        seconds = int(request.form.get("seconds", ""))

    return service.set_elapsed_time(
        record_id,
        reviewer_id,
        seconds=seconds,
        running=running,
    )


def _basis_plan_revision(default: int) -> int:
    return int(request.form.get("basis_plan_revision", default))


def _review_decision(service: ReviewService, *, record_id: str) -> ReviewDecision:
    current = service.record(record_id)
    events, structured_events, validation_reviews = review_edits(
        current.validation_findings,
        current.structured_fields,
    )
    disposition = _disposition()
    if disposition == "corrected" and not (events or structured_events):
        raise ValueError("Save corrections requires at least one PHI change.")

    reviewer_id = state().reviewer_id
    workspace = service.save_workspace(
        record_id=record_id,
        reviewer_id=reviewer_id,
        basis_plan_revision=_basis_plan_revision(current.plan_revision),
        span_events=events,
        structured_events=structured_events,
        validation_finding_reviews=validation_reviews,
        record_comment=request.form.get("record_comment") or None,
    )
    workspace = service.finish_workspace(record_id, reviewer_id)
    decided_at = datetime.now(UTC)

    return ReviewDecision.model_validate(
        {
            "decision_id": build_review_decision_id(record_id, decided_at),
            "record_id": record_id,
            "basis_plan_revision": workspace.basis_plan_revision,
            "disposition": disposition,
            "reviewer_id": reviewer_id,
            "decided_at": decided_at,
            "review_seconds": workspace.review_seconds,
            "span_events": events if disposition == "corrected" else [],
            "structured_events": structured_events if disposition == "corrected" else [],
            "validation_finding_reviews": validation_reviews,
            "record_comment": workspace.record_comment,
        }
    )


def _disposition() -> str:
    action = request.form.get("action", "")
    disposition = {
        "approve": "approved_unchanged",
        "correct": "corrected",
        "exclude": "excluded",
    }.get(action)
    if disposition is None:
        raise ValueError("Choose Approve unchanged, Save corrections, or Exclude record.")

    return disposition
