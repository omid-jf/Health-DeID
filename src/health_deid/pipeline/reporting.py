from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from math import ceil
from typing import Any

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.config import PipelineConfig
from health_deid.models.ledger import STAGE_NAMES
from health_deid.storage.database import SqliteRunStore

_RECORD_STATUS_ORDER = (
    "processing",
    "awaiting_review",
    "reviewed",
    "ready",
    "excluded",
    "failed",
)
_RECORD_STAGE_STATUS_ORDER = (
    "pending",
    "running",
    "review_pending",
    "retry_pending",
    "succeeded",
    "skipped",
    "excluded",
    "blocked",
    "retry_exhausted",
    "permanent_error",
)
_RUN_STAGE_STATUS_ORDER = (
    "pending",
    "running",
    "blocked",
    "completed",
    "completed_with_errors",
    "skipped",
    "failed",
)
_ATTEMPT_STATUS_ORDER = (
    "running",
    "succeeded",
    "retryable_error",
    "truncated",
    "cancelled",
    "permanent_error",
)
_REVIEW_DISPOSITION_ORDER = ("approved_unchanged", "corrected", "excluded")
_SOURCE_KIND_ORDER = ("aws", "llm", "rule", "review")


class LiveReportService:
    def __init__(self, store: SqliteRunStore) -> None:
        self.store = store

    def build(self) -> dict[str, Any]:
        as_of = datetime.now(UTC).isoformat()
        with self.store.read_snapshot() as connection:
            run_row = connection.execute("SELECT * FROM runs").fetchone()
            if run_row is None:
                raise RuntimeError("Run database does not contain a run.")
            run = dict(run_row)
            run_id = str(run["run_id"])
            config = PipelineConfig.model_validate_json(str(run["config_json"]))
            lineage = json.loads(str(run["reuse_json"]))
            reused_stages = (
                {"input", "detection"}
                if lineage.get("detection") == "reuse"
                else {"input"}
                if run["parent_run_id"]
                else set()
            )
            total_records = int(
                connection.execute(
                    "SELECT count(*) FROM records WHERE run_id = ?", (run_id,)
                ).fetchone()[0]
            )
            record_counts = _ordered_counts(
                connection.execute(
                    "SELECT status, count(*) FROM records WHERE run_id = ? GROUP BY status",
                    (run_id,),
                ),
                _RECORD_STATUS_ORDER,
            )
            stages = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM run_stages WHERE run_id = ?", (run_id,)
                )
            ]
            stages.sort(key=lambda row: _order_key(str(row["stage_name"]), STAGE_NAMES))
            for stage in stages:
                stage_name = str(stage["stage_name"])
                if stage_name in reused_stages:
                    provenance = "reused_from_parent"
                elif stage["status"] == "skipped":
                    provenance = "skipped"
                elif stage["status"] in {"completed", "completed_with_errors"}:
                    provenance = "completed_in_this_run"
                else:
                    provenance = "scheduled_in_this_run"
                stage["provenance"] = provenance
            record_stage_counts = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT stage_name, status, count(*) AS count
                    FROM record_stage_states WHERE run_id = ?
                    GROUP BY stage_name, status
                    """,
                    (run_id,),
                )
            ]
            record_stage_counts.sort(
                key=lambda row: (
                    _order_key(str(row["stage_name"]), STAGE_NAMES),
                    _order_key(str(row["status"]), _RECORD_STAGE_STATUS_ORDER),
                )
            )
            finding_counts = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT source_kind, canonical_category, count(*) AS raw_count,
                           coalesce(sum(is_eligible), 0) AS active_span_count,
                           count(DISTINCT CASE
                               WHEN is_eligible = 1 THEN findings.record_id
                           END) AS active_record_count
                    FROM findings
                    WHERE findings.run_id = ?
                    GROUP BY source_kind, canonical_category
                    """,
                    (run_id,),
                )
            ]
            category_order = tuple(category.value for category in PhiCategory)
            finding_counts.sort(
                key=lambda row: (
                    _order_key(str(row["source_kind"]), _SOURCE_KIND_ORDER),
                    _order_key(str(row["canonical_category"]), category_order),
                )
            )
            validation = dict(
                connection.execute(
                    """
                    SELECT coalesce(sum(status = 'succeeded'), 0) AS completed,
                           coalesce(sum(raw_violation), 0) AS raw_violations,
                           coalesce(sum(effective_violation), 0) AS effective_violations,
                           coalesce(sum(status = 'technical_error'), 0) AS technical_errors,
                           coalesce(sum(status = 'truncated'), 0) AS truncated
                    FROM validation_results WHERE run_id = ? AND is_stale = 0
                    """,
                    (run_id,),
                ).fetchone()
            )
            validation["ignored_findings"] = int(
                connection.execute(
                    """
                    SELECT count(*) FROM validation_findings
                    JOIN validation_results USING (validation_id)
                    WHERE validation_results.run_id = ?
                      AND validation_results.is_stale = 0
                      AND ignored_by_policy = 1
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
            review_counts = _ordered_counts(
                connection.execute(
                    """
                    SELECT disposition, count(*) FROM review_decisions
                    WHERE run_id = ? AND is_current = 1 AND is_stale = 0
                    GROUP BY disposition
                    """,
                    (run_id,),
                ),
                _REVIEW_DISPOSITION_ORDER,
            )
            review_seconds = int(
                connection.execute(
                    """
                    SELECT coalesce(sum(review_seconds), 0) FROM review_decisions
                    WHERE run_id = ? AND is_current = 1 AND is_stale = 0
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
            review_records = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT records.record_id, records.entity_id, records.source_index,
                           review_decisions.disposition, review_decisions.reviewer_id,
                           review_decisions.review_seconds, review_decisions.created_at
                    FROM review_decisions
                    JOIN records USING (run_id, record_id)
                    WHERE review_decisions.run_id = ? AND is_current = 1 AND is_stale = 0
                    ORDER BY records.source_index, review_decisions.created_at,
                             review_decisions.decision_id
                    """,
                    (run_id,),
                )
            ]
            structured_counts = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT structured_transform_events.column_name,
                           structured_transform_events.canonical_category,
                           structured_transform_events.purpose,
                           count(*) AS count
                    FROM structured_transform_events
                    JOIN transformation_plans USING (run_id, record_id, plan_revision)
                    WHERE structured_transform_events.run_id = ?
                      AND transformation_plans.status = 'active'
                    GROUP BY structured_transform_events.column_name,
                             structured_transform_events.canonical_category,
                             structured_transform_events.purpose
                    ORDER BY structured_transform_events.column_name,
                             structured_transform_events.purpose
                    """,
                    (run_id,),
                )
            ]
            errors = self._errors(connection, run_id=run_id, unresolved_only=False)
            attempt_counts = _ordered_counts(
                connection.execute(
                    """
                    SELECT status, count(*) FROM backend_attempts
                    WHERE run_id = ? GROUP BY status
                    """,
                    (run_id,),
                ),
                _ATTEMPT_STATUS_ORDER,
            )
            attempt_rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT backend_attempts.*, backend_definitions.backend_kind,
                           backend_definitions.backend_name, backend_definitions.model_id,
                           backend_definitions.settings_json
                    FROM backend_attempts
                    JOIN backend_definitions USING (run_id, backend_id)
                    WHERE backend_attempts.run_id = ?
                    ORDER BY backend_definitions.backend_kind,
                             backend_attempts.backend_id,
                             backend_attempts.started_at,
                             backend_attempts.attempt_number
                    """,
                    (run_id,),
                )
            ]
            findings_by_attempt = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    """
                    SELECT backend_attempt_id, count(*) FROM findings
                    WHERE run_id = ? AND backend_attempt_id IS NOT NULL
                    GROUP BY backend_attempt_id
                    """,
                    (run_id,),
                )
            }
            exports = [
                _export_row(dict(row))
                for row in connection.execute(
                    """
                    SELECT * FROM exports WHERE run_id = ?
                    ORDER BY created_at DESC, export_id
                    """,
                    (run_id,),
                )
            ]

        is_final = run["status"] in {"completed", "completed_with_errors", "failed"}
        pending_review = record_counts.get("awaiting_review", 0)
        reviewed_count = sum(review_counts.values())
        unresolved_errors = [item for item in errors if not item["resolved"]]
        usage = _aggregate_backend_usage(
            attempt_rows,
            findings_by_attempt,
            detection_reused="detection" in reused_stages,
        )
        return {
            "as_of": as_of,
            "is_final": is_final,
            "run": {
                "run_id": run_id,
                "name": run["name"],
                "parent_run_id": run["parent_run_id"],
                "status": run["status"],
                "created_at": run["created_at"],
                "updated_at": run["updated_at"],
            },
            "lineage": lineage,
            "configured_sections": {
                "detection": bool(config.detection.enabled or config.rules.enabled),
                "transformation": True,
                "validation": config.validation.enabled,
                "review": bool(config.review.enabled or pending_review or reviewed_count),
                "finalization": True,
            },
            "records": {
                "as_of": as_of,
                "denominator": total_records,
                "is_final": is_final,
                "counts": record_counts,
                "exportable": record_counts.get("ready", 0),
            },
            "stages": {
                "as_of": as_of,
                "denominator": total_records,
                "is_final": is_final,
                "run": stages,
                "records": record_stage_counts,
            },
            "findings": {
                "as_of": as_of,
                "denominator": total_records,
                "is_final": is_final,
                "counts": finding_counts,
            },
            "validation": {
                "as_of": as_of,
                "denominator": total_records,
                "is_final": is_final,
                **validation,
            },
            "review": {
                "as_of": as_of,
                "denominator": pending_review + reviewed_count,
                "is_final": is_final,
                "pending": pending_review,
                "completed": reviewed_count,
                "review_seconds": review_seconds,
                "average_seconds": (
                    round(review_seconds / reviewed_count, 1) if reviewed_count else 0.0
                ),
                "counts": review_counts,
                "records": review_records,
            },
            "structured_fields": {
                "as_of": as_of,
                "denominator": total_records,
                "is_final": is_final,
                "mappings": {
                    column: category.value
                    for column, category in config.input.structured_phi_columns.items()
                },
                "counts": structured_counts,
            },
            "errors": {
                "as_of": as_of,
                "denominator": total_records,
                "is_final": is_final,
                "unresolved": len(unresolved_errors),
                "retryable": sum(
                    not item["resolved"] and bool(item["retryable"]) for item in errors
                ),
                "items": errors,
                "groups": _group_errors(errors),
            },
            "attempts": {
                "as_of": as_of,
                "denominator": sum(attempt_counts.values()),
                "is_final": is_final,
                "counts": attempt_counts,
            },
            "usage": {
                "as_of": as_of,
                "denominator": total_records,
                "is_final": is_final,
                "backends": usage,
            },
            "exports": {
                "as_of": as_of,
                "denominator": len(exports),
                "is_final": is_final,
                "history": exports,
            },
            "action": _next_action(
                run_status=str(run["status"]),
                pending_review=pending_review,
                retryable_errors=sum(
                    not item["resolved"] and bool(item["retryable"]) for item in errors
                ),
            ),
        }

    def errors(
        self,
        *,
        record_id: str | None = None,
        stage: str | None = None,
        unresolved_only: bool = True,
    ) -> list[dict[str, Any]]:
        with self.store.read_snapshot() as connection:
            return self._errors(
                connection,
                run_id=self.store.run_id(connection),
                record_id=record_id,
                stage=stage,
                unresolved_only=unresolved_only,
            )

    def _errors(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        record_id: str | None = None,
        stage: str | None = None,
        unresolved_only: bool,
    ) -> list[dict[str, Any]]:
        clauses = ["processing_errors.run_id = ?"]
        parameters: list[object] = [run_id]
        if record_id is not None:
            clauses.append("processing_errors.record_id = ?")
            parameters.append(record_id)
        if stage is not None:
            clauses.append("processing_errors.stage_name = ?")
            parameters.append(stage)
        if unresolved_only:
            clauses.append("processing_errors.resolved = 0")
        rows = [
            dict(row)
            for row in connection.execute(
                f"""
                SELECT processing_errors.*, records.source_index
                FROM processing_errors
                LEFT JOIN records
                  ON records.run_id = processing_errors.run_id
                 AND records.record_id = processing_errors.record_id
                WHERE {" AND ".join(clauses)}
                """,
                parameters,
            )
        ]
        rows.sort(
            key=lambda row: (
                bool(row["resolved"]),
                row["source_index"] is None,
                int(row["source_index"] or 0),
                _order_key(str(row["stage_name"]), ("run", *STAGE_NAMES)),
                str(row["created_at"]),
                str(row["error_id"]),
            )
        )
        return rows

    def records(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        status: str | None = None,
    ) -> dict[str, Any]:
        if page < 1 or not 1 <= page_size <= 500:
            raise ValueError("page must be positive and page_size must be between 1 and 500.")
        config = self.store.read_config()
        where = "WHERE run_id = ?"
        parameters: list[object] = [self.store.run_id()]
        if status:
            where += " AND status = ?"
            parameters.append(status)
        with self.store.read_snapshot() as connection:
            total = int(
                connection.execute(f"SELECT count(*) FROM records {where}", parameters).fetchone()[
                    0
                ]
            )
            parameters.extend((page_size, (page - 1) * page_size))
            rows = [
                dict(row)
                for row in connection.execute(
                    f"""
                    SELECT record_id, entity_id, source_index, status, metadata_json
                    FROM records {where} ORDER BY source_index LIMIT ? OFFSET ?
                    """,
                    parameters,
                )
            ]
        for row in rows:
            row["metadata"] = json.loads(str(row.pop("metadata_json")))
        return {
            "page": page,
            "page_size": page_size,
            "total": total,
            "metadata_columns": config.input.metadata_columns,
            "records": rows,
        }

    def record_audit(self, record_id: str) -> dict[str, Any]:
        run_id = self.store.run_id()
        mappings = self.store.read_config().input.structured_phi_columns
        with self.store.read_snapshot() as connection:
            record = connection.execute(
                "SELECT * FROM records WHERE run_id = ? AND record_id = ?", (run_id, record_id)
            ).fetchone()
            if record is None:
                raise KeyError(f"Unknown record_id: {record_id}")
            findings = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM findings WHERE run_id = ? AND record_id = ?
                    ORDER BY start_char, end_char, canonical_category, source_kind, finding_id
                    """,
                    (run_id, record_id),
                )
            ]
            renderings = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM renderings WHERE run_id = ? AND record_id = ?
                    ORDER BY created_at, rendering_id
                    """,
                    (run_id, record_id),
                )
            ]
            validation_findings = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT validation_findings.*,
                           validation_results.status AS validation_status,
                           validation_results.is_stale AS validation_is_stale
                    FROM validation_findings
                    JOIN validation_results USING (validation_id)
                    WHERE validation_results.run_id = ? AND validation_results.record_id = ?
                    ORDER BY validation_finding_id
                    """,
                    (run_id, record_id),
                )
            ]
            reviews = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM review_decisions WHERE run_id = ? AND record_id = ?
                    ORDER BY created_at, decision_id
                    """,
                    (run_id, record_id),
                )
            ]
            structured_events = [
                {
                    **dict(row),
                    "original_value": json.loads(str(row["original_value_json"])),
                    "replacement_value": json.loads(str(row["replacement_value_json"])),
                }
                for row in connection.execute(
                    """
                    SELECT * FROM structured_transform_events
                    WHERE run_id = ? AND record_id = ?
                    ORDER BY plan_revision, purpose, column_name, structured_event_id
                    """,
                    (run_id, record_id),
                )
            ]
            review_structured_events = [
                {**event, "decision_id": review["decision_id"]}
                for review in reviews
                for event in json.loads(str(review["structured_events_json"]))
            ]
        metadata = json.loads(str(record["metadata_json"]))
        final_metadata = (
            json.loads(str(record["final_metadata_json"]))
            if record["final_metadata_json"] is not None
            else None
        )
        return {
            "record": dict(record),
            "metadata": metadata,
            "source_structured_fields": {column: metadata.get(column) for column in mappings},
            "final_structured_fields": (
                {column: final_metadata.get(column) for column in mappings}
                if final_metadata is not None
                else None
            ),
            "findings": findings,
            "renderings": renderings,
            "validation_findings": validation_findings,
            "review_decisions": reviews,
            "structured_transform_events": structured_events,
            "review_structured_events": review_structured_events,
            "validation_highlights": [],
        }


def _ordered_counts(rows: Any, order: tuple[str, ...]) -> dict[str, int]:
    raw = {str(row[0]): int(row[1]) for row in rows}
    return {key: raw[key] for key in sorted(raw, key=lambda item: _order_key(item, order))}


def _order_key(value: str, order: tuple[str, ...]) -> tuple[int, str]:
    try:
        return order.index(value), value
    except ValueError:
        return len(order), value


def _aggregate_backend_usage(
    attempts: list[dict[str, Any]],
    findings_by_attempt: dict[str, int],
    *,
    detection_reused: bool = False,
) -> list[dict[str, Any]]:
    grouped = _group_attempts(attempts)
    output: list[dict[str, Any]] = []

    for backend_id, rows in grouped.items():
        first = rows[0]
        settings = json.loads(str(first["settings_json"]))
        backend_type = str(settings.get("backend") or first["backend_name"])
        usage_rows = _usage_rows(rows, settings=settings)
        request_count = sum(int(item.get("request_count") or 0) for item in usage_rows)
        latency_ms = sum(float(item.get("latency_ms") or 0.0) for item in usage_rows)
        reused = detection_reused and first["backend_kind"] == "detector"

        item = _base_backend_usage(
            backend_id,
            first=first,
            rows=rows,
            backend_type=backend_type,
            usage_rows=usage_rows,
            request_count=request_count,
            latency_ms=latency_ms,
            reused=reused,
            findings_by_attempt=findings_by_attempt,
        )
        item.update(_backend_usage_details(backend_type, rows, usage_rows))
        item.update(_cost_totals(usage_rows))
        output.append(item)

    output.sort(key=lambda item: (str(item["kind"]), str(item["backend_id"])))
    return output


def _group_attempts(
    attempts: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        grouped.setdefault(str(attempt["backend_id"]), []).append(attempt)
    return grouped


def _usage_rows(
    rows: list[dict[str, Any]],
    *,
    settings: dict[str, Any],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        if row["usage_json"] is None:
            continue
        usage = json.loads(str(row["usage_json"]))
        input_tokens = int(usage.get("input_tokens") or 0)
        output_tokens = int(usage.get("output_tokens") or 0)
        if usage.get("input_cost_usd") is None and input_tokens:
            rate = settings.get("input_cost_per_million_tokens")
            if rate is not None:
                usage["input_cost_usd"] = input_tokens * float(rate) / 1_000_000
        if usage.get("output_cost_usd") is None and output_tokens:
            rate = settings.get("output_cost_per_million_tokens")
            if rate is not None:
                usage["output_cost_usd"] = output_tokens * float(rate) / 1_000_000
        costs = [usage.get("input_cost_usd"), usage.get("output_cost_usd")]
        if usage.get("cost_usd") is None and any(value is not None for value in costs):
            usage["cost_usd"] = sum(float(value or 0.0) for value in costs)
        output.append(usage)
    return output


def _base_backend_usage(
    backend_id: str,
    *,
    first: dict[str, Any],
    rows: list[dict[str, Any]],
    backend_type: str,
    usage_rows: list[dict[str, Any]],
    request_count: int,
    latency_ms: float,
    reused: bool,
    findings_by_attempt: dict[str, int],
) -> dict[str, Any]:
    return {
        "backend_id": backend_id,
        "kind": first["backend_kind"],
        "backend": backend_type,
        "name": first["backend_name"],
        "model_versions": _model_versions(rows),
        "attempts": len(rows),
        "successful_requests": sum(row["status"] == "succeeded" for row in rows),
        "error_requests": sum(row["status"] != "succeeded" for row in rows),
        "request_count": request_count,
        "requests_in_this_run": 0 if reused else request_count,
        "requests_reused_from_parent": request_count if reused else 0,
        "provenance": "reused_from_parent" if reused else "this_run",
        "input_characters": sum(int(usage.get("input_chars") or 0) for usage in usage_rows),
        "input_bytes": sum(int(usage.get("input_bytes") or 0) for usage in usage_rows),
        "latency_ms": round(latency_ms, 6),
        "average_latency_ms": (round(latency_ms / request_count, 6) if request_count else 0.0),
        "findings_returned": sum(
            findings_by_attempt.get(str(row["attempt_id"]), 0) for row in rows
        ),
    }


def _model_versions(rows: list[dict[str, Any]]) -> list[str]:
    first = rows[0]
    versions = {str(first["model_id"])} if first["model_id"] else set()

    for row in rows:
        raw_response = row["raw_response"]
        if raw_response is None:
            continue

        try:
            parsed = json.loads(str(raw_response))
        except json.JSONDecodeError:
            continue

        if isinstance(parsed, dict) and parsed.get("ModelVersion"):
            versions.add(str(parsed["ModelVersion"]))

    return sorted(versions)


def _backend_usage_details(
    backend_type: str,
    rows: list[dict[str, Any]],
    usage_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    if backend_type == "aws_comprehend_medical":
        return {
            "billable_100_character_units": sum(
                max(1, ceil(int(usage.get("input_chars") or 0) / 100))
                for usage in usage_rows
                if int(usage.get("request_count") or 0)
            )
        }

    stop_reasons = Counter(
        str(row["stop_reason"]) for row in rows if row["stop_reason"] is not None
    )
    return {
        "input_tokens": sum(int(usage.get("input_tokens") or 0) for usage in usage_rows),
        "output_tokens": sum(int(usage.get("output_tokens") or 0) for usage in usage_rows),
        "total_tokens": sum(int(usage.get("total_tokens") or 0) for usage in usage_rows),
        "stop_reasons": dict(sorted(stop_reasons.items())),
    }


def _cost_totals(usage_rows: list[dict[str, Any]]) -> dict[str, float]:
    fields = {
        "cost_usd": "actual_cost_usd",
        "input_cost_usd": "actual_input_cost_usd",
        "output_cost_usd": "actual_output_cost_usd",
    }
    totals: dict[str, float] = {}

    for field, output_name in fields.items():
        values = [float(usage[field]) for usage in usage_rows if usage.get(field) is not None]
        if values:
            totals[output_name] = round(sum(values), 8)

    return totals


def _aggregate_usage(payloads: list[str | None]) -> dict[str, float | int]:
    """Aggregate token-shaped usage payloads for compatibility and focused tests."""

    totals: dict[str, float | int] = {
        "request_count": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "latency_ms": 0.0,
        "cost_usd": 0.0,
    }
    has_cost = False
    for payload in payloads:
        if not payload:
            continue
        usage = json.loads(payload)
        for key in ("request_count", "input_tokens", "output_tokens", "total_tokens"):
            totals[key] = int(totals[key]) + int(usage.get(key) or 0)
        totals["latency_ms"] = float(totals["latency_ms"]) + float(usage.get("latency_ms") or 0.0)
        if usage.get("cost_usd") is not None:
            has_cost = True
            totals["cost_usd"] = float(totals["cost_usd"]) + float(usage["cost_usd"])
    if not has_cost:
        totals.pop("cost_usd")
    return totals


def _group_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[object, ...], dict[str, Any]] = {}
    for item in errors:
        key = (
            bool(item["resolved"]),
            item["stage_name"],
            item["error_class"],
            item["error_code"],
            item["message"],
            bool(item["retryable"]),
        )
        group = grouped.setdefault(
            key,
            {
                "resolved": bool(item["resolved"]),
                "stage_name": item["stage_name"],
                "error_class": item["error_class"],
                "error_code": item["error_code"],
                "message": item["message"],
                "retryable": bool(item["retryable"]),
                "occurrences": 0,
                "record_ids": [],
            },
        )
        group["occurrences"] = int(group["occurrences"]) + 1
        record_id = item["record_id"]
        record_ids = group["record_ids"]
        if record_id is not None and record_id not in record_ids:
            record_ids.append(record_id)
    return list(grouped.values())


def _export_row(row: dict[str, Any]) -> dict[str, Any]:
    row["selected_columns"] = json.loads(str(row.pop("selected_columns_json")))
    return row


def _next_action(
    *,
    run_status: str,
    pending_review: int,
    retryable_errors: int,
) -> dict[str, str] | None:
    if pending_review:
        return {"kind": "review", "label": "Review records"}
    if retryable_errors:
        return {"kind": "retry", "label": "Retry failed records"}
    if run_status in {"blocked", "failed"}:
        return {"kind": "continue", "label": "Continue processing"}
    return None
