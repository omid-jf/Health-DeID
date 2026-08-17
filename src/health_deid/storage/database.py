from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from health_deid.core.ids import build_content_id
from health_deid.models.config import PipelineConfig
from health_deid.models.input import (
    InputImportSummary,
    NormalizedInputRecord,
    StageError,
    TextNormalizationAudit,
)
from health_deid.models.ledger import (
    STAGE_NAMES,
    ProcessingErrorStage,
    RecordStageStatus,
    RecordStatus,
    RunStageStatus,
    RunStatus,
    StageName,
)
from health_deid.models.policy import TransformationPolicy
from health_deid.storage.schema import (
    REQUIRED_SQLITE_TABLES,
    SQLITE_APPLICATION_ID,
    SQLITE_SCHEMA,
    SQLITE_SCHEMA_VERSION,
)

_BUSY_TIMEOUT_MS = 5_000


class RunDatabaseError(RuntimeError):
    """Base class for run-database integrity and compatibility failures."""


class UnsupportedRunDatabaseVersionError(RunDatabaseError):
    """Raised when a run database requires an unsupported schema version."""


@dataclass(frozen=True, slots=True)
class SqliteRunStore:
    """Versioned transactional state store for one resumable run."""

    path: Path

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        run_id: str,
        config: PipelineConfig,
        created_at: datetime,
    ) -> SqliteRunStore:
        database_path = Path(path)
        if database_path.exists():
            raise FileExistsError(f"Run database already exists: {database_path}")
        run_id = _required_text(run_id, "run_id")
        timestamp = _utc_text(created_at, field_name="created_at")
        config_json, config_sha256 = _serialize_and_hash(config.model_dump(mode="json"))
        database_path.parent.mkdir(parents=True, exist_ok=True)
        store = cls(database_path)
        try:
            with closing(sqlite3.connect(database_path)) as connection:
                _configure_connection(connection)
                connection.executescript(SQLITE_SCHEMA)
                connection.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
                connection.executemany(
                    "INSERT INTO schema_metadata(key, value) VALUES (?, ?)",
                    (("schema_version", str(SQLITE_SCHEMA_VERSION)), ("created_at", timestamp)),
                )
                connection.execute(
                    """
                    INSERT INTO runs(
                        run_id, name, status, created_at, updated_at, parent_run_id,
                        config_version, config_json, config_sha256
                    ) VALUES (?, ?, 'initialized', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        config.run.name,
                        timestamp,
                        timestamp,
                        config.run.parent_run_id,
                        config.config_version,
                        config_json,
                        config_sha256,
                    ),
                )
                connection.executemany(
                    "INSERT INTO run_stages(run_id, stage_name, status) VALUES (?, ?, 'pending')",
                    ((run_id, stage) for stage in STAGE_NAMES),
                )
                connection.commit()
            store.validate()
        except BaseException:
            database_path.unlink(missing_ok=True)
            raise
        return store

    @classmethod
    def open(cls, path: str | Path) -> SqliteRunStore:
        database_path = Path(path)
        if not database_path.exists():
            raise FileNotFoundError(f"Run database does not exist: {database_path}")
        if not database_path.is_file():
            raise ValueError(f"Run database path is not a file: {database_path}")
        store = cls(database_path)
        store.validate()
        return store

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield one short write transaction; rollback is automatic on failure."""

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            _configure_connection(connection)
            _validate_schema(connection)
            with connection:
                yield connection

    @contextmanager
    def immediate_transaction(self) -> Iterator[sqlite3.Connection]:
        """Hold a reserved write transaction for an optimistic read/modify/write unit."""

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            _configure_connection(connection)
            _validate_schema(connection)
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    @contextmanager
    def read_snapshot(self) -> Iterator[sqlite3.Connection]:
        """Yield a consistent read transaction for reports and UI queries."""

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            _configure_connection(connection)
            _validate_schema(connection)
            connection.execute("BEGIN")
            try:
                yield connection
            finally:
                connection.rollback()

    def validate(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            _configure_connection(connection)
            _validate_schema(connection)
            row = connection.execute("SELECT config_json, config_sha256 FROM runs").fetchone()
            if row is None:
                raise RunDatabaseError("Run database does not contain a run record.")
            _verify_hash(str(row["config_json"]), str(row["config_sha256"]), "Run config")
            PipelineConfig.model_validate_json(str(row["config_json"]))

    def schema_version(self) -> int:
        with self.connection() as connection:
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    def run_id(self, connection: sqlite3.Connection | None = None) -> str:
        if connection is None:
            with self.connection() as owned_connection:
                row = owned_connection.execute("SELECT run_id FROM runs").fetchone()
        else:
            row = connection.execute("SELECT run_id FROM runs").fetchone()
        if row is None:
            raise RunDatabaseError("Run database does not contain a run record.")
        return str(row[0])

    def read_config(self) -> PipelineConfig:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT config_version, config_json, config_sha256 FROM runs"
            ).fetchone()
        if row is None:
            raise RunDatabaseError("Run database does not contain a configuration.")
        _verify_hash(str(row["config_json"]), str(row["config_sha256"]), "Run config")
        config = PipelineConfig.model_validate_json(str(row["config_json"]))
        if config.config_version != int(row["config_version"]):
            raise RunDatabaseError("Configuration version does not match database metadata.")
        return config

    def read_active_policy(self) -> tuple[int, TransformationPolicy]:
        return 1, self.read_config().policy

    def read_run_status(self) -> RunStatus:
        with self.connection() as connection:
            row = connection.execute("SELECT status FROM runs").fetchone()
        if row is None:
            raise RunDatabaseError("Run database does not contain a run record.")
        return str(row[0])  # type: ignore[return-value]

    def update_run_status(self, status: RunStatus, *, updated_at: datetime) -> None:
        timestamp = _utc_text(updated_at, field_name="updated_at")
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE runs SET status = ?, updated_at = ?", (status, timestamp)
            )
            if cursor.rowcount != 1:
                raise RunDatabaseError("Run database does not contain exactly one run record.")

    def read_stage_status(self, stage_name: StageName) -> RunStageStatus:
        run_id = self.run_id()
        with self.connection() as connection:
            row = connection.execute(
                "SELECT status FROM run_stages WHERE run_id = ? AND stage_name = ?",
                (run_id, stage_name),
            ).fetchone()
        if row is None:
            raise RunDatabaseError(f"Run database does not contain stage {stage_name!r}.")
        return str(row[0])  # type: ignore[return-value]

    def update_stage_status(
        self,
        stage_name: StageName,
        status: RunStageStatus,
        *,
        updated_at: datetime,
    ) -> None:
        run_id = self.run_id()
        timestamp = _utc_text(updated_at, field_name="updated_at")
        with self.connection() as connection:
            row = connection.execute(
                "SELECT started_at FROM run_stages WHERE run_id = ? AND stage_name = ?",
                (run_id, stage_name),
            ).fetchone()
            if row is None:
                raise RunDatabaseError(f"Run database does not contain stage {stage_name!r}.")
            started = timestamp if status == "running" else row["started_at"]
            finished = timestamp if status not in {"pending", "running"} else None
            connection.execute(
                """
                UPDATE run_stages SET status = ?, started_at = ?, finished_at = ?
                WHERE run_id = ? AND stage_name = ?
                """,
                (status, started, finished, run_id, stage_name),
            )

    def import_records(
        self,
        records: list[NormalizedInputRecord],
        summary: InputImportSummary,
    ) -> None:
        _validate_import_payload(records, summary)
        run_id = self.run_id()
        config = self.read_config()
        timestamp = _utc_text(summary.imported_at, field_name="imported_at")
        enabled = _enabled_stages(config)
        with self.connection() as connection:
            if (
                connection.execute(
                    "SELECT imported_at FROM runs WHERE run_id = ?", (run_id,)
                ).fetchone()[0]
                is not None
            ):
                raise RunDatabaseError("Input records have already been imported for this run.")
            connection.execute(
                """
                UPDATE runs SET
                    input_source_name = ?, input_source_path = ?, input_format = ?,
                    input_size_bytes = ?, input_sha256 = ?, record_count = ?,
                    active_count = ?, excluded_count = ?, normalized_count = ?, imported_at = ?
                WHERE run_id = ?
                """,
                (
                    summary.source_name,
                    str(summary.source_path) if summary.source_path else None,
                    summary.source_format,
                    summary.source_size_bytes,
                    summary.source_sha256,
                    summary.record_count,
                    summary.active_count,
                    summary.excluded_count,
                    summary.normalized_count,
                    timestamp,
                    run_id,
                ),
            )
            for record in records:
                connection.execute(
                    """
                    INSERT INTO records(
                        run_id, record_id, entity_id, source_index, raw_source_text,
                        normalized_text, normalization_json, metadata_json, status,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        record.record_id,
                        record.entity_id,
                        record.source_index,
                        record.raw_source_text,
                        record.source_text,
                        _serialize_json(record.text_normalization.model_dump(mode="json")),
                        _serialize_json(record.metadata),
                        "excluded" if record.status == "excluded" else "processing",
                        timestamp,
                        timestamp,
                    ),
                )
                for stage in STAGE_NAMES:
                    state = _initial_record_stage_state(record, stage, enabled=enabled[stage])
                    connection.execute(
                        """
                        INSERT INTO record_stage_states(
                            run_id, record_id, stage_name, status, attempt_count,
                            started_at, finished_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            record.record_id,
                            stage,
                            state,
                            0,
                            timestamp if stage == "input" else None,
                            timestamp if state in {"succeeded", "excluded", "skipped"} else None,
                            timestamp,
                        ),
                    )
            connection.execute(
                """
                UPDATE run_stages
                SET status = 'completed', started_at = ?, finished_at = ?
                WHERE run_id = ? AND stage_name = 'input'
                """,
                (timestamp, timestamp, run_id),
            )

    def read_input_import(self) -> InputImportSummary:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM runs").fetchone()
        if row is None or row["imported_at"] is None:
            raise RunDatabaseError("Run database does not contain a completed input import.")
        return InputImportSummary.model_validate(
            {
                "source_name": row["input_source_name"],
                "source_path": row["input_source_path"],
                "source_format": row["input_format"],
                "source_size_bytes": row["input_size_bytes"],
                "source_sha256": row["input_sha256"],
                "record_count": row["record_count"],
                "active_count": row["active_count"],
                "excluded_count": row["excluded_count"],
                "normalized_count": row["normalized_count"],
                "imported_at": row["imported_at"],
            }
        )

    def read_input_records(self) -> list[NormalizedInputRecord]:
        run_id = self.run_id()
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT records.*, record_stage_states.status AS input_status
                FROM records
                JOIN record_stage_states USING (run_id, record_id)
                WHERE records.run_id = ? AND record_stage_states.stage_name = 'input'
                ORDER BY records.source_index
                """,
                (run_id,),
            ).fetchall()
        result: list[NormalizedInputRecord] = []
        for row in rows:
            excluded = str(row["input_status"]) == "excluded"
            result.append(
                NormalizedInputRecord(
                    source_index=int(row["source_index"]),
                    record_id=str(row["record_id"]),
                    entity_id=str(row["entity_id"]),
                    raw_source_text=row["raw_source_text"],
                    source_text=row["normalized_text"],
                    text_normalization=TextNormalizationAudit.model_validate_json(
                        str(row["normalization_json"])
                    ),
                    metadata=json.loads(str(row["metadata_json"])),
                    status="excluded" if excluded else "active",
                    exclusion=(
                        StageError(
                            stage="input",
                            code="empty_source_text",
                            message="source_text is null, empty, or whitespace-only.",
                        )
                        if excluded
                        else None
                    ),
                )
            )
        return result

    def read_record(self, record_id: str) -> sqlite3.Row:
        run_id = self.run_id()
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM records WHERE run_id = ? AND record_id = ?",
                (run_id, record_id),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown record_id: {record_id}")
        return cast(sqlite3.Row, row)

    def record_ids_for_stage(
        self,
        stage_name: StageName,
        *,
        statuses: tuple[RecordStageStatus, ...] = ("pending", "retry_pending"),
    ) -> list[str]:
        if not statuses:
            return []
        run_id = self.run_id()
        placeholders = ",".join("?" for _ in statuses)
        with self.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT record_stage_states.record_id
                FROM record_stage_states
                JOIN records USING (run_id, record_id)
                WHERE run_id = ? AND stage_name = ?
                  AND record_stage_states.status IN ({placeholders})
                ORDER BY records.source_index
                """,
                (run_id, stage_name, *statuses),
            ).fetchall()
        return [str(row[0]) for row in rows]

    def update_record_stage_state(
        self,
        record_id: str,
        stage_name: StageName,
        status: RecordStageStatus,
        *,
        updated_at: datetime,
        increment_attempt: bool = False,
    ) -> None:
        run_id = self.run_id()
        timestamp = _utc_text(updated_at, field_name="updated_at")
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT started_at, attempt_count FROM record_stage_states
                WHERE run_id = ? AND record_id = ? AND stage_name = ?
                """,
                (run_id, record_id, stage_name),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown record/stage: {record_id}/{stage_name}")
            started = (
                timestamp
                if status == "running" and row["started_at"] is None
                else row["started_at"]
            )
            finished = (
                timestamp
                if status
                in {
                    "succeeded",
                    "retry_exhausted",
                    "permanent_error",
                    "blocked",
                    "excluded",
                    "skipped",
                }
                else None
            )
            attempt_count = int(row["attempt_count"]) + int(increment_attempt)
            connection.execute(
                """
                UPDATE record_stage_states
                SET status = ?, attempt_count = ?, started_at = ?, finished_at = ?, updated_at = ?
                WHERE run_id = ? AND record_id = ? AND stage_name = ?
                """,
                (
                    status,
                    attempt_count,
                    started,
                    finished,
                    timestamp,
                    run_id,
                    record_id,
                    stage_name,
                ),
            )

    def set_record_status(
        self,
        record_id: str,
        status: RecordStatus,
        *,
        updated_at: datetime,
        final_rendering_id: str | None = None,
        final_metadata: dict[str, Any] | None = None,
    ) -> None:
        run_id = self.run_id()
        timestamp = _utc_text(updated_at, field_name="updated_at")
        with self.connection() as connection:
            cursor = connection.execute(
                """
                UPDATE records
                SET status = ?, final_rendering_id = coalesce(?, final_rendering_id),
                    final_metadata_json = coalesce(?, final_metadata_json), updated_at = ?
                WHERE run_id = ? AND record_id = ?
                """,
                (
                    status,
                    final_rendering_id,
                    _serialize_json(final_metadata) if final_metadata is not None else None,
                    timestamp,
                    run_id,
                    record_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown record_id: {record_id}")

    def set_draft_metadata(
        self,
        record_id: str,
        metadata: dict[str, Any],
        *,
        updated_at: datetime,
    ) -> None:
        with self.connection() as connection:
            cursor = connection.execute(
                """
                UPDATE records SET draft_metadata_json = ?, updated_at = ?
                WHERE run_id = ? AND record_id = ?
                """,
                (
                    _serialize_json(metadata),
                    _utc_text(updated_at, field_name="updated_at"),
                    self.run_id(connection),
                    record_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown record_id: {record_id}")

    def record_processing_error(
        self,
        *,
        record_id: str | None,
        stage_name: ProcessingErrorStage,
        error: BaseException,
        created_at: datetime,
        retryable: bool = False,
        error_code: str | None = None,
        backend_attempt_id: str | None = None,
    ) -> str:
        """Persist a non-backend stage failure in the append-only error ledger."""

        run_id = self.run_id()
        timestamp = _utc_text(created_at, field_name="created_at")
        error_class = type(error).__name__
        raw_code = error_code or getattr(error, "code", None) or error_class
        code = str(raw_code).strip()
        message = str(error) or error_class
        error_id = build_content_id(
            "processing-error",
            run_id,
            record_id,
            stage_name,
            backend_attempt_id,
            error_class,
            code,
            timestamp,
            message,
        )
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO processing_errors(
                    error_id, run_id, record_id, stage_name, backend_attempt_id,
                    error_class, error_code, message, retryable, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(error_id) DO NOTHING
                """,
                (
                    error_id,
                    run_id,
                    record_id,
                    stage_name,
                    backend_attempt_id,
                    error_class,
                    code,
                    message,
                    int(retryable),
                    timestamp,
                ),
            )
        return error_id

    def resolve_processing_errors(
        self,
        record_id: str | None,
        stage_name: ProcessingErrorStage,
        *,
        resolved_at: datetime,
    ) -> int:
        """Mark historical stage errors resolved after an explicit successful retry."""

        run_id = self.run_id()
        timestamp = _utc_text(resolved_at, field_name="resolved_at")
        record_clause = "record_id IS NULL" if record_id is None else "record_id = ?"
        parameters: tuple[object, ...] = (
            (timestamp, run_id, stage_name)
            if record_id is None
            else (timestamp, run_id, record_id, stage_name)
        )
        with self.connection() as connection:
            return connection.execute(
                f"""
                UPDATE processing_errors SET resolved = 1, resolved_at = ?
                WHERE run_id = ? AND {record_clause} AND stage_name = ? AND resolved = 0
                """,
                parameters,
            ).rowcount

    def recover_interrupted_work(self, *, updated_at: datetime) -> int:
        timestamp = _utc_text(updated_at, field_name="updated_at")
        run_id = self.run_id()
        with self.connection() as connection:
            work = connection.execute(
                """
                UPDATE backend_work_items SET status = 'retry_pending', updated_at = ?
                WHERE run_id = ? AND status = 'running'
                """,
                (timestamp, run_id),
            ).rowcount
            connection.execute(
                """
                UPDATE record_stage_states SET status = 'retry_pending', updated_at = ?
                WHERE run_id = ? AND status = 'running'
                """,
                (timestamp, run_id),
            )
            connection.execute(
                """
                UPDATE backend_attempts SET status = 'cancelled', finished_at = ?,
                    error_class = 'Interrupted', error_code = 'interrupted',
                    error_message = 'The process ended before this attempt completed.', retryable = 1
                WHERE run_id = ? AND status = 'running'
                """,
                (timestamp, run_id),
            )
        return work


def _configure_connection(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")


def _validate_schema(connection: sqlite3.Connection) -> None:
    application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
    if application_id != SQLITE_APPLICATION_ID:
        raise RunDatabaseError("File is not a health-deid run database.")
    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if user_version != SQLITE_SCHEMA_VERSION:
        raise UnsupportedRunDatabaseVersionError(
            f"Unsupported run database schema {user_version}; expected {SQLITE_SCHEMA_VERSION}."
        )
    metadata = connection.execute(
        "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
    ).fetchone()
    if metadata is None or int(metadata[0]) != user_version:
        raise RunDatabaseError("Schema metadata does not match SQLite user_version.")
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    missing = REQUIRED_SQLITE_TABLES.difference(tables)
    if missing:
        raise RunDatabaseError("Run database is missing tables: " + ", ".join(sorted(missing)))
    integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    if integrity != "ok":
        raise RunDatabaseError(f"SQLite integrity check failed: {integrity}")


def _enabled_stages(config: PipelineConfig) -> dict[StageName, bool]:
    return {
        "input": True,
        "detection": config.detection.enabled or config.rules.enabled,
        "transformation": True,
        "validation": config.validation.enabled,
        "review": config.review.enabled or config.validation.enabled,
        "finalization": True,
        "export": True,
    }


def _initial_record_stage_state(
    record: NormalizedInputRecord,
    stage: StageName,
    *,
    enabled: bool,
) -> RecordStageStatus:
    if record.status == "excluded":
        return "excluded"
    if stage == "input":
        return "succeeded"
    return "pending" if enabled else "skipped"


def _validate_import_payload(
    records: list[NormalizedInputRecord], summary: InputImportSummary
) -> None:
    if not records:
        raise ValueError("At least one input record is required.")
    if len(records) != summary.record_count:
        raise ValueError("Input record count does not match its import summary.")
    if len({record.record_id for record in records}) != len(records):
        raise ValueError("Input record IDs must be unique.")
    if [record.source_index for record in records] != list(range(len(records))):
        raise ValueError("Input source indexes must be contiguous and start at zero.")


def _serialize_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _serialize_and_hash(value: Any) -> tuple[str, str]:
    payload = _serialize_json(value)
    return payload, hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _verify_hash(payload: str, expected: str, label: str) -> None:
    actual = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if actual != expected:
        raise RunDatabaseError(f"{label} hash does not match its stored digest.")


def _required_text(value: str, field_name: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{field_name} cannot be blank.")
    return value


def _utc_text(value: datetime, *, field_name: str) -> str:
    if value.tzinfo is None:
        raise ValueError(f"{field_name} must include timezone information.")
    return value.astimezone(UTC).isoformat()
