from __future__ import annotations

import shutil
import sqlite3
import tempfile
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from health_deid.models.input import InputPreview
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.engine import EngineDependencies
from health_deid.storage.database import SqliteRunStore

type JobState = Literal["idle", "running", "completed", "failed"]


@dataclass(frozen=True, slots=True)
class JobSnapshot:
    job_id: str | None
    state: JobState
    operation: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)


class BackgroundJobRegistry:
    """Run at most one background pipeline job in the local UI process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot = JobSnapshot(job_id=None, state="idle")
        self._thread: threading.Thread | None = None

    def start(self, operation: str, action: Callable[[], object]) -> JobSnapshot:
        operation = operation.strip()
        if not operation:
            raise ValueError("operation cannot be blank.")
        with self._lock:
            if self._snapshot.state == "running":
                raise RuntimeError("A processing job is already running in this UI process.")
            started = datetime.now(UTC)
            job_id = f"{operation}:{started.strftime('%Y%m%dT%H%M%S.%fZ')}"
            self._snapshot = JobSnapshot(
                job_id=job_id,
                state="running",
                operation=operation,
                started_at=started.isoformat(),
            )
            thread = threading.Thread(
                target=self._run,
                args=(job_id, action),
                name=f"health-deid-ui-{operation}",
                daemon=True,
            )
            self._thread = thread
            thread.start()
            return self._snapshot

    def snapshot(self) -> JobSnapshot:
        with self._lock:
            return self._snapshot

    def wait(self, timeout: float | None = None) -> JobSnapshot:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
        return self.snapshot()

    def _run(self, job_id: str, action: Callable[[], object]) -> None:
        error: str | None = None
        state: JobState = "completed"
        try:
            action()
        except BaseException as exc:
            state = "failed"
            error = str(exc).strip() or type(exc).__name__
        finished = datetime.now(UTC).isoformat()
        with self._lock:
            if self._snapshot.job_id == job_id:
                self._snapshot = JobSnapshot(
                    job_id=job_id,
                    state=state,
                    operation=self._snapshot.operation,
                    started_at=self._snapshot.started_at,
                    finished_at=finished,
                    error=error,
                )


@dataclass(slots=True)
class SetupDraft:
    draft_id: str
    source_path: Path
    source_name: str
    preview: InputPreview
    config_payload: dict[str, object] | None = None
    imported_config: bool = False
    rules_payload: dict[str, object] | None = None
    rules_source_name: str | None = None
    surrogate_secrets: dict[str, str] = field(default_factory=dict)
    owns_source_file: bool = True


class UiState:
    """Process-local state for one loopback-only UI session."""

    def __init__(
        self,
        *,
        context: RunContext | None,
        dependencies: EngineDependencies | None,
        temp_root: str | Path | None,
        reviewer_id: str,
        runs_dir: str | Path = "runs",
    ) -> None:
        self._lock = threading.RLock()
        self._contexts: dict[str, RunContext] = {}
        self.dependencies = dependencies or EngineDependencies()
        self.jobs = BackgroundJobRegistry()
        self.drafts: dict[str, SetupDraft] = {}
        self.reviewer_id = reviewer_id.strip()
        if not self.reviewer_id:
            raise ValueError("reviewer_id cannot be blank.")
        self.runs_dir = Path(runs_dir).resolve()
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._owned_temp_root: Path | None
        if temp_root is None:
            self._owned_temp_root = Path(tempfile.mkdtemp(prefix="health-deid-ui-"))
            self.temp_root = self._owned_temp_root
        else:
            self._owned_temp_root = None
            self.temp_root = Path(temp_root)
            self.temp_root.mkdir(parents=True, exist_ok=True)
        if context is not None:
            self.remember_context(context)

    def remember_context(self, context: RunContext) -> None:
        with self._lock:
            self._contexts[context.run_id] = context

    def context_for(self, run_id: str) -> RunContext:
        with self._lock:
            cached = self._contexts.get(run_id)
        if cached is not None:
            return cached
        for item in self.runs():
            if item["run_id"] == run_id:
                context = RunContext.from_run_path(str(item["run_path"]))
                self.remember_context(context)
                return context
        raise KeyError(f"Unknown run: {run_id}")

    def add_draft(self, draft: SetupDraft) -> None:
        with self._lock:
            old = self.drafts.pop(draft.draft_id, None)
            if old is not None and old.owns_source_file:
                old.source_path.unlink(missing_ok=True)
            self.drafts[draft.draft_id] = draft

    def draft(self, draft_id: str) -> SetupDraft:
        with self._lock:
            try:
                return self.drafts[draft_id]
            except KeyError as exc:
                raise KeyError("The setup draft expired; upload the input file again.") from exc

    def discard_draft(self, draft_id: str) -> None:
        with self._lock:
            draft = self.drafts.pop(draft_id, None)
        if draft is not None and draft.owns_source_file:
            draft.source_path.unlink(missing_ok=True)

    def runs(self) -> list[dict[str, Any]]:
        candidates = {path for path in self.runs_dir.glob("*/run.sqlite") if path.is_file()}
        candidates.update(context.database_path for context in self._contexts.values())
        items: list[dict[str, Any]] = []
        for database_path in candidates:
            try:
                context = RunContext.from_run_path(database_path)
                store = SqliteRunStore.open(context.database_path)
                with store.read_snapshot() as connection:
                    row = connection.execute(
                        "SELECT name, status, updated_at, parent_run_id FROM runs WHERE run_id = ?",
                        (context.run_id,),
                    ).fetchone()
                    total = int(connection.execute("SELECT count(*) FROM records").fetchone()[0])
                    ready = int(
                        connection.execute(
                            "SELECT count(*) FROM records WHERE status = 'ready'"
                        ).fetchone()[0]
                    )
                assert row is not None
                items.append(
                    {
                        "run_id": context.run_id,
                        "name": row["name"],
                        "status": row["status"],
                        "updated_at": row["updated_at"],
                        "record_count": total,
                        "ready_count": ready,
                        "parent_run_id": row["parent_run_id"],
                        "run_path": str(context.run_dir),
                    }
                )
            except (OSError, RuntimeError, ValueError, sqlite3.DatabaseError):
                continue
        items.sort(key=lambda item: (str(item["updated_at"]), str(item["run_id"])), reverse=True)
        return items

    def close(self) -> None:
        with self._lock:
            drafts = list(self.drafts.values())
            self.drafts.clear()
        for draft in drafts:
            if draft.owns_source_file:
                draft.source_path.unlink(missing_ok=True)
        if self._owned_temp_root is not None:
            shutil.rmtree(self._owned_temp_root, ignore_errors=True)


__all__ = ["SetupDraft", "UiState"]
