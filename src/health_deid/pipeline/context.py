from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from health_deid.models.config import PipelineConfig
from health_deid.storage.database import SqliteRunStore


@dataclass(frozen=True, slots=True)
class RunContext:
    config: PipelineConfig
    run_id: str
    created_at: datetime
    run_dir: Path
    database_path: Path
    exports_dir: Path

    @classmethod
    def from_config(
        cls,
        config: PipelineConfig,
        *,
        timestamp: datetime | None = None,
    ) -> RunContext:
        created_at = _as_utc(timestamp or datetime.now(UTC))
        stamp = created_at.strftime("%Y%m%dT%H%M%S")
        run_name = _sanitize_run_name(config.run.name)
        run_id = f"{stamp}_{run_name}" if run_name else stamp
        return cls._build(
            config=config,
            run_id=run_id,
            created_at=created_at,
            run_dir=config.run.output_dir / run_id,
        )

    @classmethod
    def from_run_path(cls, path: str | Path) -> RunContext:
        supplied = Path(path)
        database_path = supplied if supplied.is_file() else supplied / "run.sqlite"
        store = SqliteRunStore.open(database_path)
        config = store.read_config()
        with store.connection() as connection:
            row = connection.execute("SELECT run_id, created_at FROM runs").fetchone()
        if row is None:
            raise RuntimeError("Run database does not contain run metadata.")
        created_at = datetime.fromisoformat(str(row["created_at"]))
        return cls._build(
            config=config,
            run_id=str(row["run_id"]),
            created_at=created_at,
            run_dir=database_path.parent,
        )

    @classmethod
    def from_run_dir(cls, run_dir: str | Path) -> RunContext:
        return cls.from_run_path(run_dir)

    @classmethod
    def _build(
        cls,
        *,
        config: PipelineConfig,
        run_id: str,
        created_at: datetime,
        run_dir: Path,
    ) -> RunContext:
        return cls(
            config=config,
            run_id=run_id,
            created_at=_as_utc(created_at),
            run_dir=run_dir,
            database_path=run_dir / "run.sqlite",
            exports_dir=run_dir / "exports",
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _sanitize_run_name(name: str | None) -> str | None:
    if name is None:
        return None
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-._")
    return sanitized or None
