from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import polars as pl

from health_deid.core.ids import build_content_id
from health_deid.models.export import ExportRequest, ExportResult
from health_deid.storage.database import SqliteRunStore

_CORE_COLUMNS = {
    "record_id",
    "entity_id",
    "input_row_number",
    "deid_status",
    "final_text",
    "raw_source_text",
    "normalized_text",
}


class ExportService:
    def __init__(self, store: SqliteRunStore) -> None:
        self.store = store

    def export(
        self,
        request: ExportRequest,
        *,
        created_at: datetime | None = None,
    ) -> ExportResult:
        started = created_at or datetime.now(UTC)
        run_id = self.store.run_id()
        export_id = build_content_id(
            "export", run_id, str(request.output_path), started.astimezone(UTC).isoformat()
        )
        with self.store.connection() as connection:
            connection.execute(
                """
                INSERT INTO exports(
                    export_id, run_id, format, mode, status, output_path,
                    selected_columns_json, record_count, created_at
                ) VALUES (?, ?, ?, ?, 'running', ?, ?, 0, ?)
                """,
                (
                    export_id,
                    run_id,
                    request.format,
                    request.mode,
                    str(request.output_path),
                    json.dumps(request.selected_columns),
                    _utc_text(started),
                ),
            )
        temporary: Path | None = None
        try:
            rows, exported_record_ids = self._rows(request)
            frame = pl.DataFrame(rows) if rows else _empty_frame(request.selected_columns)
            request.output_path.parent.mkdir(parents=True, exist_ok=True)
            suffix = ".parquet" if request.format == "parquet" else ".jsonl"
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{request.output_path.name}.",
                suffix=suffix,
                dir=request.output_path.parent,
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            if request.format == "parquet":
                frame.write_parquet(temporary)
            else:
                frame.write_ndjson(temporary)
            os.replace(temporary, request.output_path)
            digest = _file_sha256(request.output_path)
            finished = datetime.now(UTC)
            with self.store.connection() as connection:
                connection.execute(
                    """
                    UPDATE exports SET status = 'completed', output_sha256 = ?,
                        record_count = ?, finished_at = ? WHERE export_id = ?
                    """,
                    (digest, frame.height, _utc_text(finished), export_id),
                )
                finished_text = _utc_text(finished)
                connection.execute(
                    """
                    UPDATE record_stage_states
                    SET status = 'skipped', started_at = NULL, finished_at = ?, updated_at = ?
                    WHERE run_id = ? AND stage_name = 'export'
                    """,
                    (finished_text, finished_text, run_id),
                )
                connection.executemany(
                    """
                    UPDATE record_stage_states
                    SET status = 'succeeded', started_at = ?, finished_at = ?, updated_at = ?
                    WHERE run_id = ? AND record_id = ? AND stage_name = 'export'
                    """,
                    (
                        (finished_text, finished_text, finished_text, run_id, record_id)
                        for record_id in exported_record_ids
                    ),
                )
                connection.execute(
                    """
                    UPDATE run_stages
                    SET status = 'completed', started_at = ?, finished_at = ?
                    WHERE run_id = ? AND stage_name = 'export'
                    """,
                    (_utc_text(started), finished_text, run_id),
                )
            return ExportResult(
                export_id=export_id,
                output_path=request.output_path,
                format=request.format,
                mode=request.mode,
                selected_columns=request.selected_columns,
                record_count=frame.height,
                output_sha256=digest,
                created_at=started,
                finished_at=finished,
            )
        except BaseException as exc:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            with self.store.connection() as connection:
                connection.execute(
                    """
                    UPDATE exports SET status = 'failed', error_message = ?, finished_at = ?
                    WHERE export_id = ?
                    """,
                    (str(exc) or type(exc).__name__, _utc_text(datetime.now(UTC)), export_id),
                )
            raise

    def _rows(self, request: ExportRequest) -> tuple[list[dict[str, Any]], list[str]]:
        run_id = self.store.run_id()
        config = self.store.read_config()
        metadata_names = set(config.input.metadata_columns)
        raw_structured_names = {f"raw_{column}" for column in config.input.structured_phi_columns}
        unknown = [
            column
            for column in request.selected_columns
            if column not in _CORE_COLUMNS
            and column not in raw_structured_names
            and not (column.startswith("metadata.") and column[9:] in metadata_names)
            and column not in metadata_names
        ]
        if unknown:
            raise ValueError("Unknown export columns: " + ", ".join(unknown))
        collisions = metadata_names.intersection(_CORE_COLUMNS)
        ambiguous = collisions.intersection(request.selected_columns)
        if ambiguous:
            raise ValueError(
                "Metadata columns that collide with core columns require metadata.<name>: "
                + ", ".join(sorted(ambiguous))
            )
        mode_clause = "AND records.status = 'ready'" if request.mode == "ready_only" else ""
        with self.store.read_snapshot() as connection:
            rows = connection.execute(
                f"""
                SELECT records.*, renderings.rendered_text AS final_text
                FROM records
                LEFT JOIN renderings ON renderings.rendering_id = records.final_rendering_id
                WHERE records.run_id = ? {mode_clause}
                ORDER BY records.source_index
                """,
                (run_id,),
            ).fetchall()
        output: list[dict[str, Any]] = []
        record_ids: list[str] = []
        for row in rows:
            record_ids.append(str(row["record_id"]))
            original_metadata = json.loads(row["metadata_json"])
            metadata = json.loads(row["final_metadata_json"] or row["metadata_json"])
            available: dict[str, Any] = {
                "record_id": row["record_id"],
                "entity_id": row["entity_id"],
                "input_row_number": int(row["source_index"]) + 1,
                "deid_status": row["status"],
                "final_text": row["final_text"],
                "raw_source_text": row["raw_source_text"],
                "normalized_text": row["normalized_text"],
            }
            rendered: dict[str, Any] = {}
            for column in request.selected_columns:
                if column in _CORE_COLUMNS:
                    rendered[column] = available[column]
                elif column in raw_structured_names:
                    rendered[column] = original_metadata.get(column.removeprefix("raw_"))
                else:
                    metadata_name = column.removeprefix("metadata.")
                    rendered[column] = metadata.get(metadata_name)
            output.append(rendered)
        return output, record_ids


def _empty_frame(columns: list[str]) -> pl.DataFrame:
    return pl.DataFrame({column: pl.Series(column, [], dtype=pl.String) for column in columns})


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Timestamps must include timezone information.")
    return value.astimezone(UTC).isoformat()
