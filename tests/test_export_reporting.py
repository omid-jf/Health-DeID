from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

import polars as pl
import pytest

from health_deid.backends.runtime import BackendExecutionError, TextChunk
from health_deid.core.resolution import RESOLVER_VERSION, resolve_findings
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import DetectionCandidate
from health_deid.models.config import PipelineConfig
from health_deid.models.export import ExportRequest
from health_deid.models.ledger import RenderedText
from health_deid.pipeline.engine import PipelineEngine
from health_deid.pipeline.exports import ExportService
from health_deid.pipeline.reporting import (
    LiveReportService,
    _aggregate_backend_usage,
    _aggregate_usage,
    _export_row,
    _group_errors,
    _next_action,
    _order_key,
    _usage_rows,
)
from health_deid.storage.database import SqliteRunStore
from health_deid.storage.findings import BackendDefinition, FindingRepository
from health_deid.storage.transformations import TransformationRepository

NOW = datetime(2026, 7, 31, 13, 0, tzinfo=UTC)


def _reporting_store(tmp_path: Path) -> SqliteRunStore:
    source = tmp_path / "records.jsonl"
    source.write_text(
        """{"record_id":"R1","text":"Alice admitted.","site":"north","entity_id":"meta-1"}
{"record_id":"R2","text":"No identifier.","site":"south","entity_id":"meta-2"}
{"record_id":"R3","text":"Excluded note.","site":"west","entity_id":"meta-3"}
""",
        encoding="utf-8",
    )
    config = PipelineConfig.model_validate(
        {
            "run": {"output_dir": tmp_path / "runs"},
            "input": {
                "path": source,
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
                "metadata_columns": ["site", "entity_id"],
                "structured_phi_columns": {"site": "LOCATION"},
            },
            "detection": {"enabled": False},
        }
    )
    store = PipelineEngine.create(config, timestamp=NOW).store
    finding_repository = FindingRepository(store)
    findings = finding_repository.insert_rule_findings(
        record_id="R1",
        source_name="fixture_rule",
        candidates=[
            DetectionCandidate(
                category=PhiCategory.NAME,
                native_category="NAME",
                text="Alice",
                start_char=0,
                end_char=5,
            )
        ],
        created_at=NOW,
    )
    resolved = resolve_findings("Alice admitted.", findings, record_id="R1")
    transformations = TransformationRepository(store)
    resolution_revision = transformations.save_resolution(
        record_id="R1",
        findings_sha256=resolved.findings_sha256,
        resolver_version=RESOLVER_VERSION,
        groups=resolved.groups,
        reason="test fixture",
        created_at=NOW,
    )
    transformations.save_plan(
        record_id="R1",
        plan_revision=1,
        resolution_revision=resolution_revision,
        policy_revision=1,
        purpose="final",
        events=[],
        created_at=NOW,
    )
    final_rendering = transformations.save_rendering(
        record_id="R1",
        plan_revision=1,
        kind="final",
        rendered=RenderedText(text="[R_NAME] admitted.", events=[]),
        created_at=NOW,
    )
    store.set_record_status(
        "R1",
        "ready",
        final_rendering_id=final_rendering.rendering_id,
        final_metadata={"site": "generalized-north"},
        updated_at=NOW,
    )
    store.set_record_status("R3", "excluded", updated_at=NOW)

    transformations.save_plan(
        record_id="R1",
        plan_revision=2,
        resolution_revision=resolution_revision,
        policy_revision=1,
        purpose="draft",
        events=[],
        created_at=NOW,
    )
    validation_rendering = transformations.save_rendering(
        record_id="R1",
        plan_revision=2,
        kind="draft",
        rendered=RenderedText(text="[R_NAME] admitted.", events=[]),
        created_at=NOW,
    )
    with store.connection() as connection:
        connection.execute(
            """
            INSERT INTO validation_results(
                validation_id, run_id, record_id, rendering_id, status,
                raw_violation, effective_violation, rationale, is_stale, created_at
            ) VALUES ('validation-report', ?, 'R1', ?, 'succeeded', 1, 1,
                      'Possible residual name', 0, ?)
            """,
            (store.run_id(), validation_rendering.rendering_id, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO validation_findings(
                validation_finding_id, run_id, record_id, validation_id,
                canonical_category, evidence, rule_ids_json, confidence,
                rationale, ignored_by_policy
            ) VALUES ('vf-report', ?, 'R1', 'validation-report', 'NAME', 'Alice',
                      '[]', 'medium', 'Potential name', 0)
            """,
            (store.run_id(),),
        )
    store.record_processing_error(
        record_id="R2",
        stage_name="validation",
        error=RuntimeError("temporary validator error"),
        retryable=True,
        created_at=NOW,
    )
    finding_repository.register_backend(
        BackendDefinition(
            backend_id="report-detector",
            kind="detector",
            name="report-detector",
            version="1",
            model_id=None,
            settings={},
        ),
        created_at=NOW,
    )
    work = finding_repository.prepare_work(
        record_id="R2",
        backend_id="report-detector",
        stage_name="detection",
        chunks=[TextChunk(0, 0, 14, "No identifier.")],
        created_at=NOW,
    )[0]
    attempt_id, attempt_number = finding_repository.begin_attempt(work, started_at=NOW)
    finding_repository.fail_attempt(
        attempt_id=attempt_id,
        work_item=work,
        error=BackendExecutionError("timeout", "temporary detector timeout", True),
        attempt_number=attempt_number,
        maximum_attempts=3,
        finished_at=NOW,
    )
    return store


def test_export_completed_and_all_records_with_explicit_warnings(tmp_path: Path) -> None:
    store = _reporting_store(tmp_path)
    service = ExportService(store)

    completed = service.export(
        ExportRequest(
            output_path=tmp_path / "completed.parquet",
            mode="ready_only",
            selected_columns=["record_id", "final_text", "site"],
        ),
        created_at=NOW,
    )
    completed_frame = pl.read_parquet(completed.output_path)
    assert completed.record_count == 1
    assert completed_frame.to_dicts() == [
        {
            "record_id": "R1",
            "final_text": "[R_NAME] admitted.",
            "site": "generalized-north",
        }
    ]
    with store.connection() as connection:
        completed_states = {
            str(row["record_id"]): str(row["status"])
            for row in connection.execute(
                """
                SELECT record_id, status FROM record_stage_states
                WHERE stage_name = 'export' ORDER BY record_id
                """
            )
        }
        assert completed_states == {"R1": "succeeded", "R2": "skipped", "R3": "skipped"}
        assert (
            connection.execute(
                "SELECT status FROM run_stages WHERE stage_name = 'export'"
            ).fetchone()[0]
            == "completed"
        )

    all_records = service.export(
        ExportRequest(
            output_path=tmp_path / "all.jsonl",
            format="jsonl",
            mode="all_records",
            selected_columns=[
                "record_id",
                "deid_status",
                "final_text",
                "raw_source_text",
                "metadata.site",
                "raw_site",
            ],
        ),
        created_at=NOW.replace(second=1),
    )
    rows = pl.read_ndjson(all_records.output_path).to_dicts()
    assert all_records.record_count == 3
    assert [row["deid_status"] for row in rows] == [
        "ready",
        "processing",
        "excluded",
    ]
    assert rows[0]["metadata.site"] == "generalized-north"
    assert rows[0]["raw_site"] == "north"
    assert rows[1]["final_text"] is None
    with store.connection() as connection:
        assert {
            str(row["record_id"]): str(row["status"])
            for row in connection.execute(
                """
                SELECT record_id, status FROM record_stage_states
                WHERE stage_name = 'export' ORDER BY record_id
                """
            )
        } == {"R1": "succeeded", "R2": "succeeded", "R3": "succeeded"}
        history = connection.execute(
            "SELECT format, mode, status, record_count FROM exports ORDER BY created_at"
        ).fetchall()
    assert [tuple(row) for row in history] == [
        ("parquet", "ready_only", "completed", 1),
        ("jsonl", "all_records", "completed", 3),
    ]


def test_export_failure_is_atomic_and_retained_in_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _reporting_store(tmp_path)
    destination = tmp_path / "existing.parquet"
    destination.write_bytes(b"previous-export")

    def fail_write(frame: pl.DataFrame, path: Path) -> None:
        del frame, path
        raise OSError("simulated write failure")

    monkeypatch.setattr(pl.DataFrame, "write_parquet", fail_write)
    with pytest.raises(OSError, match="simulated write failure"):
        ExportService(store).export(
            ExportRequest(
                output_path=destination,
                selected_columns=["record_id", "final_text"],
            ),
            created_at=NOW,
        )

    assert destination.read_bytes() == b"previous-export"
    assert list(tmp_path.glob(".existing.parquet.*.parquet")) == []
    with store.connection() as connection:
        failed = connection.execute(
            "SELECT status, record_count, output_sha256, error_message, finished_at FROM exports"
        ).fetchone()
    assert failed["status"] == "failed"
    assert failed["record_count"] == 0
    assert failed["output_sha256"] is None
    assert failed["error_message"] == "simulated write failure"
    assert failed["finished_at"] is not None


def test_export_rejects_unknown_and_ambiguous_columns_and_exports_empty_frame(
    tmp_path: Path,
) -> None:
    store = _reporting_store(tmp_path)
    service = ExportService(store)

    with pytest.raises(ValueError, match="Unknown export columns"):
        service.export(
            ExportRequest(
                output_path=tmp_path / "unknown.parquet",
                selected_columns=["not_a_column"],
            ),
            created_at=NOW,
        )
    with pytest.raises(ValueError, match="require metadata"):
        service.export(
            ExportRequest(
                output_path=tmp_path / "ambiguous.parquet",
                selected_columns=["entity_id"],
            ),
            created_at=NOW.replace(second=1),
        )

    store.set_record_status("R1", "processing", updated_at=NOW)
    empty = service.export(
        ExportRequest(
            output_path=tmp_path / "empty.parquet",
            selected_columns=["final_text"],
        ),
        created_at=NOW.replace(second=2),
    )
    assert empty.record_count == 0
    assert pl.read_parquet(empty.output_path).columns == ["final_text"]
    with store.connection() as connection:
        failed = connection.execute(
            "SELECT status, error_message FROM exports WHERE status = 'failed' ORDER BY created_at"
        ).fetchall()
    assert [row["status"] for row in failed] == ["failed", "failed"]
    assert "not_a_column" in failed[0]["error_message"]
    assert "entity_id" in failed[1]["error_message"]


def test_export_rejects_naive_created_timestamp_before_history(tmp_path: Path) -> None:
    store = _reporting_store(tmp_path)

    with pytest.raises(ValueError, match="timezone"):
        ExportService(store).export(
            ExportRequest(output_path=tmp_path / "naive.parquet"),
            created_at=datetime(2026, 7, 31, 13, 0),
        )

    with store.connection() as connection:
        assert connection.execute("SELECT count(*) FROM exports").fetchone()[0] == 0


def test_live_report_denominators_final_state_and_record_audit(tmp_path: Path) -> None:
    store = _reporting_store(tmp_path)
    service = LiveReportService(store)

    report = service.build()

    assert report["is_final"] is False
    for section in ("records", "stages", "findings", "validation", "errors", "usage"):
        assert report[section]["denominator"] == 3
        assert report[section]["as_of"] == report["as_of"]
        assert report[section]["is_final"] is False
    assert report["exports"] == {
        "as_of": report["as_of"],
        "denominator": 0,
        "is_final": False,
        "history": [],
    }
    assert report["records"]["counts"] == {
        "processing": 1,
        "excluded": 1,
        "ready": 1,
    }
    assert report["records"]["exportable"] == 1
    assert report["findings"]["counts"] == [
        {
            "source_kind": "rule",
            "canonical_category": "NAME",
            "raw_count": 1,
            "active_span_count": 1,
            "active_record_count": 1,
        }
    ]
    assert report["validation"]["completed"] == 1
    assert report["validation"]["effective_violations"] == 1
    assert report["errors"]["unresolved"] == 2
    assert report["errors"]["retryable"] == 2
    assert [item["message"] for item in report["errors"]["items"]] == [
        "temporary detector timeout",
        "temporary validator error",
    ]
    assert report["attempts"] == {
        "as_of": report["as_of"],
        "denominator": 1,
        "is_final": False,
        "counts": {"retryable_error": 1},
    }

    first_page = service.records(page=1, page_size=2)
    assert first_page["total"] == 3
    assert first_page["metadata_columns"] == ["site", "entity_id"]
    assert [row["record_id"] for row in first_page["records"]] == ["R1", "R2"]
    assert first_page["records"][0]["metadata"] == {"site": "north", "entity_id": "meta-1"}
    excluded = service.records(status="excluded")
    assert [row["record_id"] for row in excluded["records"]] == ["R3"]
    with pytest.raises(ValueError, match="page must be positive"):
        service.records(page=0)

    audit = service.record_audit("R1")
    assert audit["record"]["record_id"] == "R1"
    assert audit["metadata"] == {"site": "north", "entity_id": "meta-1"}
    assert audit["findings"][0]["exact_text"] == "Alice"
    assert audit["validation_findings"][0]["evidence"] == "Alice"
    assert audit["validation_findings"][0]["validation_status"] == "succeeded"
    assert audit["validation_findings"][0]["validation_is_stale"] == 0
    assert "start_char" not in audit["validation_findings"][0]
    assert "end_char" not in audit["validation_findings"][0]
    assert audit["validation_highlights"] == []
    with pytest.raises(KeyError, match="Unknown record_id"):
        service.record_audit("missing")

    store.update_run_status("completed", updated_at=NOW)
    final_report = service.build()
    assert final_report["is_final"] is True
    assert final_report["records"]["is_final"] is True
    assert final_report["exports"]["is_final"] is True

    with store.connection() as connection:
        connection.execute(
            "UPDATE findings SET is_eligible = 0, eligibility_reason = 'test' WHERE finding_id = ?",
            (audit["findings"][0]["finding_id"],),
        )
    retried_report = service.build()
    assert retried_report["findings"]["counts"][0]["raw_count"] == 1
    assert retried_report["findings"]["counts"][0]["active_span_count"] == 0
    assert retried_report["findings"]["counts"][0]["active_record_count"] == 0


def test_usage_aggregation_skips_empty_payloads_and_accumulates_optional_cost() -> None:
    usage = _aggregate_usage(
        [
            None,
            "",
            '{"request_count":2,"input_tokens":3,"output_tokens":4,'
            '"total_tokens":7,"latency_ms":1.5}',
            '{"request_count":1,"input_tokens":5,"output_tokens":6,'
            '"total_tokens":11,"latency_ms":2.5,"cost_usd":0.125}',
        ]
    )

    assert usage == {
        "request_count": 3,
        "input_tokens": 8,
        "output_tokens": 10,
        "total_tokens": 18,
        "latency_ms": 4.0,
        "cost_usd": 0.125,
    }
    assert "cost_usd" not in _aggregate_usage(['{"request_count":1}'])

    priced = _usage_rows(
        [{"usage_json": ('{"request_count":1,"input_tokens":10,"output_tokens":20}')}],
        settings={
            "input_cost_per_million_tokens": 2.0,
            "output_cost_per_million_tokens": 3.0,
        },
    )[0]
    assert priced["input_cost_usd"] == 0.00002
    assert priced["output_cost_usd"] == 0.00006
    assert priced["cost_usd"] == 0.00008

    unpriced = _usage_rows(
        [{"usage_json": '{"input_tokens":10,"output_tokens":20}'}],
        settings={},
    )[0]
    assert "cost_usd" not in unpriced


def test_backend_specific_usage_and_reporting_helpers() -> None:
    attempts = [
        {
            "attempt_id": "c1",
            "backend_id": "comprehend",
            "backend_kind": "detector",
            "backend_name": "Comprehend Medical",
            "settings_json": '{"backend":"aws_comprehend_medical"}',
            "usage_json": (
                '{"request_count":1,"input_chars":150,"input_bytes":155,'
                '"latency_ms":12.5,"cost_usd":0.01}'
            ),
            "stop_reason": None,
            "model_id": None,
            "raw_response": '{"ModelVersion":"3.0"}',
            "status": "succeeded",
        },
        {
            "attempt_id": "c2",
            "backend_id": "comprehend",
            "backend_kind": "detector",
            "backend_name": "Comprehend Medical",
            "settings_json": '{"backend":"aws_comprehend_medical"}',
            "usage_json": '{"request_count":1,"input_chars":0,"input_bytes":0}',
            "stop_reason": None,
            "model_id": None,
            "raw_response": "not-json",
            "status": "permanent_error",
        },
        {
            "attempt_id": "b1",
            "backend_id": "sonnet",
            "backend_kind": "detector",
            "backend_name": "Sonnet",
            "settings_json": '{"backend":"aws_bedrock"}',
            "usage_json": (
                '{"request_count":1,"input_tokens":10,"output_tokens":5,'
                '"total_tokens":15,"latency_ms":4,'
                '"input_cost_usd":0.03,"output_cost_usd":0.08}'
            ),
            "stop_reason": "end_turn",
            "model_id": "sonnet-4.6",
            "raw_response": None,
            "status": "succeeded",
        },
    ]
    usage = _aggregate_backend_usage(attempts, {"c1": 2, "b1": 1})

    comprehend = next(item for item in usage if item["backend_id"] == "comprehend")
    assert comprehend["billable_100_character_units"] == 3
    assert comprehend["requests_in_this_run"] == 2
    assert comprehend["requests_reused_from_parent"] == 0
    assert comprehend["provenance"] == "this_run"
    assert comprehend["model_versions"] == ["3.0"]
    assert comprehend["actual_cost_usd"] == 0.01
    assert "total_tokens" not in comprehend
    sonnet = next(item for item in usage if item["backend_id"] == "sonnet")
    assert sonnet["total_tokens"] == 15
    assert sonnet["actual_input_cost_usd"] == 0.03
    assert sonnet["actual_output_cost_usd"] == 0.08
    assert sonnet["actual_cost_usd"] == 0.11
    assert sonnet["stop_reasons"] == {"end_turn": 1}
    reused = _aggregate_backend_usage(attempts, {"c1": 2, "b1": 1}, detection_reused=True)
    reused_sonnet = next(item for item in reused if item["backend_id"] == "sonnet")
    assert reused_sonnet["requests_in_this_run"] == 0
    assert reused_sonnet["requests_reused_from_parent"] == 1
    assert reused_sonnet["provenance"] == "reused_from_parent"

    errors = [
        {
            "resolved": 0,
            "stage_name": "detection",
            "error_class": "BackendExecutionError",
            "error_code": "timeout",
            "message": "timed out",
            "retryable": 1,
            "record_id": "R1",
        },
        {
            "resolved": 0,
            "stage_name": "detection",
            "error_class": "BackendExecutionError",
            "error_code": "timeout",
            "message": "timed out",
            "retryable": 1,
            "record_id": "R1",
        },
        {
            "resolved": 1,
            "stage_name": "run",
            "error_class": "RuntimeError",
            "error_code": "run_error",
            "message": "stopped",
            "retryable": 0,
            "record_id": None,
        },
    ]
    grouped = _group_errors(errors)
    assert grouped[0]["record_ids"] == ["R1"]
    assert grouped[0]["occurrences"] == 2
    assert grouped[1]["record_ids"] == []
    assert _export_row({"selected_columns_json": '["final_text"]'})["selected_columns"] == [
        "final_text"
    ]
    assert _order_key("unknown", ("known",)) == (1, "unknown")
    assert (
        _next_action(run_status="completed", pending_review=1, retryable_errors=1)["kind"]
        == "review"
    )
    assert (
        _next_action(run_status="completed", pending_review=0, retryable_errors=1)["kind"]
        == "retry"
    )
    assert (
        _next_action(run_status="blocked", pending_review=0, retryable_errors=0)["kind"]
        == "continue"
    )
    assert _next_action(run_status="completed", pending_review=0, retryable_errors=0) is None


def test_report_error_filters_and_missing_run_guard(tmp_path: Path) -> None:
    store = _reporting_store(tmp_path)
    service = LiveReportService(store)

    assert [item["record_id"] for item in service.errors(record_id="R2")] == ["R2", "R2"]
    assert [item["stage_name"] for item in service.errors(stage="validation")] == ["validation"]
    assert len(service.errors(unresolved_only=False)) == 2

    empty_database = tmp_path / "empty.sqlite"
    with closing(sqlite3.connect(empty_database)) as connection:
        connection.execute("CREATE TABLE runs(run_id TEXT)")
        connection.commit()

    class EmptyStore:
        @contextmanager
        def read_snapshot(self):
            connection = sqlite3.connect(empty_database)
            connection.row_factory = sqlite3.Row
            try:
                yield connection
            finally:
                connection.close()

    with pytest.raises(RuntimeError, match="does not contain a run"):
        LiveReportService(EmptyStore()).build()  # type: ignore[arg-type]
