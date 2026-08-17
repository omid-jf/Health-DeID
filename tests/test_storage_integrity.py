from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from health_deid.models.config import PipelineConfig
from health_deid.models.input import (
    InputImportSummary,
    NormalizedInputRecord,
)
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.input import load_normalized_input
from health_deid.storage import database as database_module
from health_deid.storage.database import (
    RunDatabaseError,
    SqliteRunStore,
    UnsupportedRunDatabaseVersionError,
)
from health_deid.storage.schema import (
    SQLITE_SCHEMA_VERSION,
)

NOW = datetime(2026, 7, 31, 15, 0, tzinfo=UTC)
SHA = hashlib.sha256(b"source").hexdigest()


def _config(tmp_path: Path, *, name: str | None = "store / audit") -> PipelineConfig:
    return PipelineConfig.model_validate(
        {
            "run": {"name": name, "output_dir": tmp_path / "runs"},
            "input": {
                "path": tmp_path / "notes.jsonl",
                "format": "jsonl",
                "record_id_column": "record_id",
                "entity_id": {"source": "column", "column": "entity_id"},
                "text_column": "text",
            },
            "detection": {"enabled": False},
        }
    )


def _record(
    index: int,
    record_id: str,
    text: str | None,
    *,
    status: str = "active",
) -> NormalizedInputRecord:
    raw = text
    digest = hashlib.sha256((text or "").encode()).hexdigest() if text is not None else None
    return NormalizedInputRecord.model_validate(
        {
            "source_index": index,
            "record_id": record_id,
            "entity_id": f"entity-{index}",
            "raw_source_text": raw,
            "source_text": text,
            "text_normalization": {
                "normalizer_version": "6.3.1",
                "changed": False,
                "raw_sha256": digest,
                "normalized_sha256": digest,
            },
            "metadata": {"index": index, "tags": ["audit"]},
            "status": status,
            "exclusion": (
                {
                    "stage": "input",
                    "code": "empty_source_text",
                    "message": "source_text is null, empty, or whitespace-only.",
                }
                if status == "excluded"
                else None
            ),
        }
    )


def _summary(
    count: int,
    *,
    active: int | None = None,
    excluded: int = 0,
    imported_at: datetime = NOW,
) -> InputImportSummary:
    return InputImportSummary(
        source_name="notes.jsonl",
        source_path=Path("/input/notes.jsonl"),
        source_format="jsonl",
        source_size_bytes=6,
        source_sha256=SHA,
        record_count=count,
        active_count=count - excluded if active is None else active,
        excluded_count=excluded,
        normalized_count=count,
        imported_at=imported_at,
    )


def _create_store(tmp_path: Path, *, import_data: bool = True) -> SqliteRunStore:
    store = SqliteRunStore.create(
        tmp_path / "run.sqlite",
        run_id="run-1",
        config=_config(tmp_path),
        created_at=NOW,
    )
    if import_data:
        store.import_records(
            [_record(0, "r1", "Alice"), _record(1, "r2", None, status="excluded")],
            _summary(2, excluded=1),
        )
    return store


def _execute_unvalidated(path: Path, sql: str, parameters: tuple[object, ...] = ()) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(sql, parameters)
        connection.commit()


def test_create_open_context_and_transaction_boundaries(tmp_path: Path) -> None:
    config = _config(tmp_path)
    context = RunContext.from_config(config, timestamp=NOW)
    assert context.run_id == "20260731T150000_store-audit"
    assert context.created_at == NOW
    assert context.database_path == context.run_dir / "run.sqlite"
    assert context.exports_dir == context.run_dir / "exports"

    store = SqliteRunStore.create(
        context.database_path,
        run_id=context.run_id,
        config=config,
        created_at=NOW,
    )
    assert store.schema_version() == SQLITE_SCHEMA_VERSION
    assert store.run_id() == context.run_id
    assert store.read_config() == config
    assert store.read_active_policy() == (1, config.policy)
    assert SqliteRunStore.open(store.path) == store

    loaded_from_file = RunContext.from_run_path(store.path)
    loaded_from_dir = RunContext.from_run_dir(context.run_dir)
    assert loaded_from_file == loaded_from_dir
    assert loaded_from_file.run_id == context.run_id

    with pytest.raises(RuntimeError, match="rollback"):
        with store.connection() as connection:
            connection.execute("UPDATE runs SET name = 'not committed'")
            raise RuntimeError("rollback")
    with store.connection() as connection:
        assert connection.execute("SELECT name FROM runs").fetchone()[0] == "store / audit"

    with store.immediate_transaction() as connection:
        connection.execute("UPDATE runs SET name = 'committed'")
    with pytest.raises(RuntimeError, match="immediate rollback"):
        with store.immediate_transaction() as connection:
            connection.execute("UPDATE runs SET name = 'not committed'")
            raise RuntimeError("immediate rollback")
    with store.read_snapshot() as connection:
        assert connection.execute("SELECT name FROM runs").fetchone()[0] == "committed"


def test_context_name_sanitization_and_utc_conversion(tmp_path: Path) -> None:
    unnamed = RunContext.from_config(_config(tmp_path, name="..."), timestamp=datetime(2026, 1, 2))
    assert unnamed.run_id == "20260102T000000"
    assert unnamed.created_at.tzinfo is UTC

    offset = datetime.fromisoformat("2026-01-02T04:00:00+04:00")
    context = RunContext.from_config(_config(tmp_path, name=None), timestamp=offset)
    assert context.run_id == "20260102T000000"
    assert context.created_at == datetime(2026, 1, 2, tzinfo=UTC)


def test_create_and_open_reject_invalid_paths_and_remove_failed_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "run.sqlite"
    path.write_text("exists", encoding="utf-8")
    with pytest.raises(FileExistsError):
        SqliteRunStore.create(path, run_id="run", config=_config(tmp_path), created_at=NOW)

    with pytest.raises(ValueError, match="run_id"):
        SqliteRunStore.create(
            tmp_path / "blank.sqlite", run_id="  ", config=_config(tmp_path), created_at=NOW
        )
    with pytest.raises(ValueError, match="timezone"):
        SqliteRunStore.create(
            tmp_path / "naive.sqlite",
            run_id="run",
            config=_config(tmp_path),
            created_at=datetime(2026, 1, 1),
        )

    failed_path = tmp_path / "failed.sqlite"

    def fail_validation(self: SqliteRunStore) -> None:
        raise RuntimeError("synthetic validation failure")

    monkeypatch.setattr(SqliteRunStore, "validate", fail_validation)
    with pytest.raises(RuntimeError, match="synthetic"):
        SqliteRunStore.create(failed_path, run_id="run", config=_config(tmp_path), created_at=NOW)
    assert not failed_path.exists()

    with pytest.raises(FileNotFoundError):
        SqliteRunStore.open(tmp_path / "missing.sqlite")
    with pytest.raises(ValueError, match="not a file"):
        SqliteRunStore.open(tmp_path)


@pytest.mark.parametrize(
    ("mutation", "error_type", "message"),
    [
        (
            lambda path: _execute_unvalidated(path, "PRAGMA application_id = 0"),
            RunDatabaseError,
            "not a health-deid",
        ),
        (
            lambda path: _execute_unvalidated(path, "PRAGMA user_version = 999"),
            UnsupportedRunDatabaseVersionError,
            "Unsupported",
        ),
        (
            lambda path: _execute_unvalidated(
                path, "UPDATE schema_metadata SET value = '999' WHERE key = 'schema_version'"
            ),
            RunDatabaseError,
            "metadata",
        ),
        (
            lambda path: _execute_unvalidated(path, "DROP TABLE exports"),
            RunDatabaseError,
            "missing tables",
        ),
        (
            lambda path: _execute_unvalidated(path, "DELETE FROM runs"),
            RunDatabaseError,
            "run record",
        ),
        (
            lambda path: _execute_unvalidated(
                path, "UPDATE runs SET config_sha256 = ?", ("0" * 64,)
            ),
            RunDatabaseError,
            "config hash",
        ),
    ],
)
def test_open_detects_database_corruption(
    tmp_path: Path,
    mutation,
    error_type: type[Exception],
    message: str,
) -> None:
    store = _create_store(tmp_path, import_data=False)
    mutation(store.path)
    with pytest.raises(error_type, match=message):
        SqliteRunStore.open(store.path)


def test_read_payload_metadata_integrity_checks(tmp_path: Path) -> None:
    store = _create_store(tmp_path, import_data=False)
    _execute_unvalidated(store.path, "UPDATE runs SET config_version = 999")
    with pytest.raises(RunDatabaseError, match="Configuration version"):
        store.read_config()


def test_payload_readers_report_missing_rows(tmp_path: Path) -> None:
    store = _create_store(tmp_path, import_data=False)
    store.update_run_status("completed", updated_at=NOW)
    for stage in ("detection", "transformation", "validation", "finalization", "export"):
        store.update_stage_status(stage, "completed", updated_at=NOW)
    assert store.read_run_status() == "completed"
    assert store.read_stage_status("transformation") == "completed"
    assert store.read_stage_status("detection") == "completed"
    with pytest.raises(RunDatabaseError, match="completed input import"):
        store.read_input_import()

    missing_run = _create_store(tmp_path / "missing-run", import_data=False)
    _execute_unvalidated(missing_run.path, "DELETE FROM runs")
    with pytest.raises(RunDatabaseError, match="run record"):
        missing_run.run_id()
    with pytest.raises(RunDatabaseError, match="configuration"):
        missing_run.read_config()
    with pytest.raises(RunDatabaseError, match="run record"):
        missing_run.read_run_status()
    with pytest.raises(RunDatabaseError, match="exactly one"):
        missing_run.update_run_status("running", updated_at=NOW)


def test_schema_integrity_failure_has_domain_specific_error(tmp_path: Path) -> None:
    store = _create_store(tmp_path, import_data=False)
    real = sqlite3.connect(store.path)

    class _IntegrityCursor:
        def fetchone(self):
            return ("database disk image is malformed",)

    class _IntegrityConnection:
        def execute(self, sql: str):
            if sql == "PRAGMA integrity_check":
                return _IntegrityCursor()
            return real.execute(sql)

    try:
        with pytest.raises(RunDatabaseError, match="integrity check failed"):
            database_module._validate_schema(_IntegrityConnection())  # type: ignore[arg-type]
    finally:
        real.close()


def test_import_records_round_trip_stage_states_and_rollback(tmp_path: Path) -> None:
    store = _create_store(tmp_path, import_data=False)
    records = [_record(0, "r1", "Alice"), _record(1, "r2", None, status="excluded")]
    store.import_records(records, _summary(2, excluded=1))

    assert store.read_input_import() == _summary(2, excluded=1)
    loaded = store.read_input_records()
    assert loaded[0] == records[0]
    assert loaded[1].status == "excluded"
    assert loaded[1].exclusion is not None
    assert loaded[1].exclusion.code == "empty_source_text"
    assert store.read_stage_status("input") == "completed"
    assert store.record_ids_for_stage("transformation") == ["r1"]
    assert store.record_ids_for_stage("transformation", statuses=()) == []
    assert store.record_ids_for_stage("detection") == []
    assert store.read_record("r1")["entity_id"] == "entity-0"
    with pytest.raises(KeyError, match="missing"):
        store.read_record("missing")
    with pytest.raises(RunDatabaseError, match="already"):
        store.import_records(records, _summary(2, excluded=1))

    rollback_store = _create_store(tmp_path / "rollback", import_data=False)
    with pytest.raises(sqlite3.IntegrityError):
        rollback_store.import_records(records, _summary(2, active=2, excluded=1))
    with rollback_store.connection() as connection:
        assert connection.execute("SELECT imported_at FROM runs").fetchone()[0] is None
        assert connection.execute("SELECT count(*) FROM records").fetchone()[0] == 0


def test_load_normalized_input_reads_the_sqlite_ledger(tmp_path: Path) -> None:
    store = _create_store(tmp_path)
    context = RunContext.from_run_path(store.path)
    without_raw = load_normalized_input(context)
    with_raw = load_normalized_input(context, include_raw_source_text=True)
    assert without_raw["record_id"].to_list() == ["r1", "r2"]
    assert "raw_source_text" not in without_raw.columns
    assert with_raw["raw_source_text"].to_list() == ["Alice", None]


def test_context_defensively_rejects_missing_run_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)

    class _Cursor:
        @staticmethod
        def fetchone():
            return None

    class _Connection:
        @staticmethod
        def execute(sql: str):
            assert "SELECT run_id" in sql
            return _Cursor()

    class _Store:
        @staticmethod
        def read_config() -> PipelineConfig:
            return config

        @staticmethod
        @contextmanager
        def connection():
            yield _Connection()

    monkeypatch.setattr(SqliteRunStore, "open", lambda path: _Store())
    with pytest.raises(RuntimeError, match="run metadata"):
        RunContext.from_run_path(tmp_path / "synthetic.sqlite")


@pytest.mark.parametrize(
    ("records", "summary", "message"),
    [
        ([], _summary(1), "At least one"),
        ([_record(0, "r1", "a")], _summary(2), "count"),
        (
            [_record(0, "r1", "a"), _record(1, "r1", "b")],
            _summary(2),
            "unique",
        ),
        (
            [_record(1, "r1", "a")],
            _summary(1),
            "contiguous",
        ),
    ],
)
def test_import_payload_validation(
    tmp_path: Path,
    records: list[NormalizedInputRecord],
    summary: InputImportSummary,
    message: str,
) -> None:
    store = _create_store(tmp_path, import_data=False)
    with pytest.raises(ValueError, match=message):
        store.import_records(records, summary)


def test_run_record_and_stage_status_updates(tmp_path: Path) -> None:
    store = _create_store(tmp_path)
    store.update_run_status("running", updated_at=NOW)
    assert store.read_run_status() == "running"

    store.update_stage_status("transformation", "running", updated_at=NOW)
    store.update_stage_status("transformation", "completed", updated_at=NOW + timedelta(seconds=1))
    assert store.read_stage_status("transformation") == "completed"
    with store.connection() as connection:
        stage = connection.execute(
            "SELECT * FROM run_stages WHERE stage_name = 'transformation'"
        ).fetchone()
        assert stage["started_at"] is not None
        assert stage["finished_at"] is not None

    store.update_record_stage_state(
        "r1", "transformation", "running", updated_at=NOW, increment_attempt=True
    )
    store.update_record_stage_state(
        "r1", "transformation", "succeeded", updated_at=NOW + timedelta(seconds=1)
    )
    with store.connection() as connection:
        state = connection.execute(
            "SELECT * FROM record_stage_states WHERE record_id='r1' AND stage_name='transformation'"
        ).fetchone()
        assert state["attempt_count"] == 1
        assert state["started_at"] is not None
        assert state["finished_at"] is not None

    store.set_record_status(
        "r1",
        "ready",
        updated_at=NOW,
        final_rendering_id="rendering-1",
        final_metadata={"safe": True},
    )
    row = store.read_record("r1")
    assert row["status"] == "ready"
    assert row["final_rendering_id"] == "rendering-1"
    assert row["final_metadata_json"] == '{"safe":true}'

    with pytest.raises(KeyError, match="missing/transformation"):
        store.update_record_stage_state("missing", "transformation", "running", updated_at=NOW)
    with pytest.raises(KeyError, match="missing"):
        store.set_record_status("missing", "processing", updated_at=NOW)


def test_missing_run_and_stage_rows_are_reported(tmp_path: Path) -> None:
    store = _create_store(tmp_path, import_data=False)
    _execute_unvalidated(store.path, "DELETE FROM run_stages WHERE stage_name = 'transformation'")
    with pytest.raises(RunDatabaseError, match="transformation"):
        store.read_stage_status("transformation")
    with pytest.raises(RunDatabaseError, match="transformation"):
        store.update_stage_status("transformation", "running", updated_at=NOW)


def test_processing_error_ledger_record_and_run_scopes(tmp_path: Path) -> None:
    store = _create_store(tmp_path)

    class CodedError(RuntimeError):
        code = "custom-code"

    record_error = store.record_processing_error(
        record_id="r1",
        stage_name="transformation",
        error=CodedError("bad record"),
        created_at=NOW,
        retryable=True,
    )
    run_error = store.record_processing_error(
        record_id=None,
        stage_name="run",
        error=RuntimeError(),
        created_at=NOW,
        error_code="run-failed",
    )
    assert record_error != run_error
    assert store.resolve_processing_errors("r1", "transformation", resolved_at=NOW) == 1
    assert store.resolve_processing_errors(None, "run", resolved_at=NOW) == 1
    assert store.resolve_processing_errors(None, "run", resolved_at=NOW) == 0
    with store.connection() as connection:
        rows = connection.execute(
            "SELECT error_code, message, resolved FROM processing_errors ORDER BY error_code"
        ).fetchall()
    assert [(row["error_code"], row["resolved"]) for row in rows] == [
        ("custom-code", 1),
        ("run-failed", 1),
    ]
    assert dict(rows[1])["message"] == "RuntimeError"
