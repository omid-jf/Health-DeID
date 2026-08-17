from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import ftfy
import polars as pl
from pydantic import ConfigDict, JsonValue, TypeAdapter

from health_deid.models.config import InputConfig
from health_deid.models.input import (
    InputColumnPreview,
    InputFormat,
    InputImportSummary,
    InputPreview,
    NormalizedInputRecord,
    StageError,
    TextNormalizationAudit,
)
from health_deid.storage.database import SqliteRunStore

if TYPE_CHECKING:
    from health_deid.pipeline.context import RunContext

FTFY_VERSION = version("ftfy")

STAGE_ERRORS_DTYPE = pl.List(
    pl.Struct(
        {
            "stage": pl.String,
            "code": pl.String,
            "message": pl.String,
        }
    )
)

TEXT_NORMALIZATION_DTYPE = pl.Struct(
    {
        "normalizer": pl.String,
        "normalizer_version": pl.String,
        "changed": pl.Boolean,
        "raw_sha256": pl.String,
        "normalized_sha256": pl.String,
    }
)

_JSON_OBJECT_ADAPTER = TypeAdapter(
    dict[str, Any],
    config=ConfigDict(ser_json_bytes="base64"),
)

_MAX_SAMPLE_RECORDS = 100


def read_input_file(config: InputConfig) -> pl.DataFrame:
    return read_input_source(config.path, config.format)


def read_input_source(path: str | Path, input_format: InputFormat) -> pl.DataFrame:
    """Read a supported input file eagerly after validating its path."""

    source_path = _validated_input_path(path)
    if input_format == "parquet":
        return pl.read_parquet(source_path)
    if input_format == "jsonl":
        return pl.read_ndjson(source_path, infer_schema_length=None)
    raise ValueError(f"Unsupported input format: {input_format}")


def scan_input_source(path: str | Path, input_format: InputFormat) -> pl.LazyFrame:
    """Create a lazy scan suitable for bounded input previews."""

    source_path = _validated_input_path(path)
    if input_format == "parquet":
        return pl.scan_parquet(source_path)
    if input_format == "jsonl":
        return pl.scan_ndjson(source_path, infer_schema_length=None)
    raise ValueError(f"Unsupported input format: {input_format}")


def _validated_input_path(path: str | Path) -> Path:
    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {source_path}")
    if not source_path.is_file():
        raise ValueError(f"Input path is not a file: {source_path}")
    return source_path


def preview_input_file(
    path: str | Path,
    input_format: InputFormat,
    *,
    sample_size: int = 20,
) -> InputPreview:
    """Inspect an input file without loading all rows into memory."""

    if sample_size < 1 or sample_size > _MAX_SAMPLE_RECORDS:
        raise ValueError(f"sample_size must be between 1 and {_MAX_SAMPLE_RECORDS}.")

    source_path = Path(path)
    lazy_frame = scan_input_source(source_path, input_format)
    schema = lazy_frame.collect_schema()
    total_records = int(lazy_frame.select(pl.len()).collect().item())
    sample = lazy_frame.head(sample_size).collect()

    return InputPreview(
        path=source_path.resolve(),
        format=input_format,
        total_records=total_records,
        columns=[InputColumnPreview(name=name, dtype=str(dtype)) for name, dtype in schema.items()],
        sample_records=[json_compatible_object(record) for record in sample.iter_rows(named=True)],
    )


def normalize_input_frame(
    raw_frame: pl.DataFrame,
    context: RunContext,
) -> pl.DataFrame:
    """Validate, normalize, and canonicalize one imported input frame."""

    records = normalize_input_records(raw_frame, context.config.input)
    return normalized_records_to_frame(records, include_raw_source_text=True)


def normalize_input_records(
    raw_frame: pl.DataFrame,
    input_config: InputConfig,
) -> list[NormalizedInputRecord]:
    """Convert source rows into the canonical records persisted in SQLite."""

    if raw_frame.is_empty():
        raise ValueError("Input file must contain at least one record.")

    entity_id_column = input_config.entity_id.source_column(
        record_id_column=input_config.record_id_column
    )
    required_columns = {
        input_config.record_id_column,
        entity_id_column,
        input_config.text_column,
        *input_config.metadata_columns,
    }

    missing_columns = sorted(required_columns.difference(raw_frame.columns))
    if missing_columns:
        missing_text = ", ".join(missing_columns)
        raise ValueError(f"Input file is missing required columns: {missing_text}")

    record_ids = _normalized_ids(
        raw_frame,
        input_config.record_id_column,
        error_message="Input record_id_column contains null or blank record IDs.",
    )
    if len(record_ids) != len(set(record_ids)):
        raise ValueError("Input record_id_column must be unique after conversion to string.")

    entity_ids = _normalized_ids(
        raw_frame,
        entity_id_column,
        error_message="Input entity_id source contains null or blank entity IDs.",
    )
    raw_source_texts = raw_frame.get_column(input_config.text_column).cast(pl.String).to_list()
    source_texts = [ftfy.fix_text(text) if text is not None else None for text in raw_source_texts]
    metadata_values = _metadata_values(raw_frame, input_config.metadata_columns)

    records: list[NormalizedInputRecord] = []
    for source_index, (record_id, entity_id, raw_text, source_text, metadata) in enumerate(
        zip(
            record_ids,
            entity_ids,
            raw_source_texts,
            source_texts,
            metadata_values,
            strict=True,
        )
    ):
        exclusion = None
        status: Literal["active", "excluded"] = "active"
        if source_text is None or not source_text.strip():
            status = "excluded"
            exclusion = StageError(
                stage="input",
                code="empty_source_text",
                message="source_text is null, empty, or whitespace-only.",
            )

        records.append(
            NormalizedInputRecord(
                source_index=source_index,
                record_id=record_id,
                entity_id=entity_id,
                raw_source_text=raw_text,
                source_text=source_text,
                text_normalization=TextNormalizationAudit(
                    normalizer_version=FTFY_VERSION,
                    changed=raw_text != source_text,
                    raw_sha256=_text_sha256(raw_text),
                    normalized_sha256=_text_sha256(source_text),
                ),
                metadata=metadata,
                status=status,
                exclusion=exclusion,
            )
        )

    return records


def normalized_records_to_frame(
    records: list[NormalizedInputRecord],
    *,
    include_raw_source_text: bool,
) -> pl.DataFrame:
    """Render canonical input records as a stable dataframe view."""

    frame = pl.DataFrame(
        {
            "record_id": pl.Series(
                "record_id",
                [record.record_id for record in records],
                dtype=pl.String,
            ),
            "entity_id": pl.Series(
                "entity_id",
                [record.entity_id for record in records],
                dtype=pl.String,
            ),
            "raw_source_text": pl.Series(
                "raw_source_text",
                [record.raw_source_text for record in records],
                dtype=pl.String,
            ),
            "source_text": pl.Series(
                "source_text",
                [record.source_text for record in records],
                dtype=pl.String,
            ),
            "text_normalization": pl.Series(
                "text_normalization",
                [record.text_normalization.model_dump(mode="json") for record in records],
                dtype=TEXT_NORMALIZATION_DTYPE,
            ),
            "metadata": pl.Series(
                "metadata",
                [record.metadata or None for record in records],
                strict=False,
            ),
            "pipeline_status": pl.Series(
                "pipeline_status",
                [record.status for record in records],
                dtype=pl.String,
            ),
            "stage_errors": pl.Series(
                "stage_errors",
                [
                    [] if record.exclusion is None else [record.exclusion.model_dump(mode="json")]
                    for record in records
                ],
                dtype=STAGE_ERRORS_DTYPE,
            ),
        }
    )

    columns = [
        "record_id",
        "entity_id",
        "raw_source_text",
        "source_text",
        "text_normalization",
        "metadata",
        "pipeline_status",
        "stage_errors",
    ]
    if not include_raw_source_text:
        columns.remove("raw_source_text")
    return frame.select(columns)


def load_normalized_input(
    context: RunContext,
    *,
    include_raw_source_text: bool = False,
) -> pl.DataFrame:
    """Load the canonical imported records from the run's SQLite ledger."""

    records = SqliteRunStore.open(context.database_path).read_input_records()
    return normalized_records_to_frame(
        records,
        include_raw_source_text=include_raw_source_text,
    )


def build_input_import_summary(
    input_config: InputConfig,
    records: list[NormalizedInputRecord],
    *,
    imported_at: datetime | None = None,
) -> InputImportSummary:
    """Build immutable file provenance and normalization counts for an import."""

    source_path = Path(input_config.path).resolve()
    timestamp = imported_at or datetime.now(UTC)
    return InputImportSummary(
        source_name=source_path.name,
        source_path=source_path,
        source_format=input_config.format,
        source_size_bytes=source_path.stat().st_size,
        source_sha256=_file_sha256(source_path),
        record_count=len(records),
        active_count=sum(record.status == "active" for record in records),
        excluded_count=sum(record.status == "excluded" for record in records),
        normalized_count=sum(record.text_normalization.changed for record in records),
        imported_at=timestamp,
    )


def json_compatible_object(value: dict[str, Any]) -> dict[str, JsonValue]:
    """Convert supported source values to deterministic JSON-compatible values."""

    converted = _JSON_OBJECT_ADAPTER.dump_python(value, mode="json")
    return cast(dict[str, JsonValue], converted)


def _normalized_ids(
    frame: pl.DataFrame,
    column: str,
    *,
    error_message: str,
) -> list[str]:
    values = frame.get_column(column).cast(pl.String).to_list()
    if any(value is None or not value.strip() for value in values):
        raise ValueError(error_message)

    return [cast(str, value).strip() for value in values]


def _metadata_values(
    frame: pl.DataFrame,
    metadata_columns: list[str],
) -> list[dict[str, JsonValue]]:
    if not metadata_columns:
        return [{} for _ in range(frame.height)]

    return [
        json_compatible_object(row) for row in frame.select(metadata_columns).iter_rows(named=True)
    ]


def _text_sha256(text: str | None) -> str | None:
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
