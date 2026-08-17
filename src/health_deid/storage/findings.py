from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from health_deid.backends.runtime import BackendExecutionError, TextChunk, rebase_candidate
from health_deid.core.ids import build_content_id
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import DetectionCandidate, DetectionResult
from health_deid.models.ledger import Finding, StageName
from health_deid.storage.database import SqliteRunStore


@dataclass(frozen=True, slots=True)
class BackendDefinition:
    backend_id: str
    kind: Literal["detector", "validator"]
    name: str
    version: str | None
    model_id: str | None
    settings: dict[str, Any]
    taxonomy_version: str | None = None
    prompt_text: str | None = None
    schema: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class BackendWorkItem:
    work_item_id: str
    record_id: str
    backend_id: str
    stage_name: StageName
    chunk_index: int
    start_char: int
    end_char: int
    input_sha256: str
    status: str


class FindingRepository:
    def __init__(self, store: SqliteRunStore) -> None:
        self.store = store

    def register_backend(self, definition: BackendDefinition, *, created_at: datetime) -> None:
        run_id = self.store.run_id()
        settings_json, settings_hash = _json_and_hash(definition.settings)
        schema_json, schema_hash = (
            _json_and_hash(definition.schema) if definition.schema is not None else (None, None)
        )
        prompt_hash = (
            hashlib.sha256(definition.prompt_text.encode("utf-8")).hexdigest()
            if definition.prompt_text is not None
            else None
        )
        timestamp = _utc_text(created_at)
        with self.store.connection() as connection:
            current = connection.execute(
                """
                SELECT settings_sha256, prompt_sha256, schema_sha256
                FROM backend_definitions WHERE run_id = ? AND backend_id = ?
                """,
                (run_id, definition.backend_id),
            ).fetchone()
            expected = (settings_hash, prompt_hash, schema_hash)
            if current is not None:
                actual = tuple(current)
                if actual != expected:
                    raise ValueError(
                        f"Backend {definition.backend_id!r} was already registered differently."
                    )
                return
            connection.execute(
                """
                INSERT INTO backend_definitions(
                    run_id, backend_id, backend_kind, backend_name, backend_version,
                    model_id, settings_json, settings_sha256, taxonomy_version,
                    prompt_text, prompt_sha256, schema_json, schema_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    definition.backend_id,
                    definition.kind,
                    definition.name,
                    definition.version,
                    definition.model_id,
                    settings_json,
                    settings_hash,
                    definition.taxonomy_version,
                    definition.prompt_text,
                    prompt_hash,
                    schema_json,
                    schema_hash,
                    timestamp,
                ),
            )

    def prepare_work(
        self,
        *,
        record_id: str,
        backend_id: str,
        stage_name: Literal["detection", "validation"],
        chunks: list[TextChunk],
        created_at: datetime,
    ) -> list[BackendWorkItem]:
        run_id = self.store.run_id()
        timestamp = _utc_text(created_at)
        with self.store.connection() as connection:
            for chunk in chunks:
                work_id = build_content_id(
                    "work",
                    run_id,
                    record_id,
                    backend_id,
                    chunk.index,
                    chunk.start_char,
                    chunk.end_char,
                    hashlib.sha256(chunk.text.encode("utf-8")).hexdigest(),
                )
                connection.execute(
                    """
                    INSERT INTO backend_work_items(
                        work_item_id, run_id, record_id, backend_id, stage_name,
                        chunk_index, start_char, end_char, input_sha256,
                        status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                    ON CONFLICT(run_id, record_id, backend_id, chunk_index) DO NOTHING
                    """,
                    (
                        work_id,
                        run_id,
                        record_id,
                        backend_id,
                        stage_name,
                        chunk.index,
                        chunk.start_char,
                        chunk.end_char,
                        hashlib.sha256(chunk.text.encode("utf-8")).hexdigest(),
                        timestamp,
                        timestamp,
                    ),
                )
        return self.work_items(record_id=record_id, backend_id=backend_id)

    def work_items(self, *, record_id: str, backend_id: str) -> list[BackendWorkItem]:
        run_id = self.store.run_id()
        with self.store.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM backend_work_items
                WHERE run_id = ? AND record_id = ? AND backend_id = ?
                ORDER BY chunk_index
                """,
                (run_id, record_id, backend_id),
            ).fetchall()
        return [
            BackendWorkItem(
                work_item_id=str(row["work_item_id"]),
                record_id=str(row["record_id"]),
                backend_id=str(row["backend_id"]),
                stage_name=str(row["stage_name"]),  # type: ignore[arg-type]
                chunk_index=int(row["chunk_index"]),
                start_char=int(row["start_char"]),
                end_char=int(row["end_char"]),
                input_sha256=str(row["input_sha256"]),
                status=str(row["status"]),
            )
            for row in rows
        ]

    def begin_attempt(self, work_item: BackendWorkItem, *, started_at: datetime) -> tuple[str, int]:
        run_id = self.store.run_id()
        timestamp = _utc_text(started_at)
        with self.store.connection() as connection:
            attempt_number = int(
                connection.execute(
                    """
                    SELECT coalesce(max(attempt_number), 0) + 1 FROM backend_attempts
                    WHERE run_id = ? AND work_item_id = ?
                    """,
                    (run_id, work_item.work_item_id),
                ).fetchone()[0]
            )
            attempt_id = build_content_id("attempt", run_id, work_item.work_item_id, attempt_number)
            connection.execute(
                """
                INSERT INTO backend_attempts(
                    attempt_id, run_id, record_id, backend_id, work_item_id,
                    stage_name, attempt_number, status, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?)
                """,
                (
                    attempt_id,
                    run_id,
                    work_item.record_id,
                    work_item.backend_id,
                    work_item.work_item_id,
                    work_item.stage_name,
                    attempt_number,
                    timestamp,
                ),
            )
            connection.execute(
                "UPDATE backend_work_items SET status = 'running', updated_at = ? WHERE work_item_id = ?",
                (timestamp, work_item.work_item_id),
            )
        return attempt_id, attempt_number

    def finish_detection_attempt(
        self,
        *,
        attempt_id: str,
        work_item: BackendWorkItem,
        result: DetectionResult,
        source_kind: Literal["aws", "llm"],
        source_name: str,
        minimum_confidence: float,
        finished_at: datetime,
    ) -> list[Finding]:
        run_id = self.store.run_id()
        timestamp = _utc_text(finished_at)
        findings: list[Finding] = []
        with self.store.connection() as connection:
            _require_running_attempt(connection, attempt_id)
            for candidate in result.candidates:
                rebased = rebase_candidate(candidate, chunk_start=work_item.start_char)
                finding_id = build_content_id(
                    "finding",
                    run_id,
                    work_item.record_id,
                    source_name,
                    rebased.start_char,
                    rebased.end_char,
                    rebased.category.value,
                    rebased.backend_span_id,
                    rebased.text,
                )
                finding = Finding(
                    finding_id=finding_id,
                    record_id=work_item.record_id,
                    source_kind=source_kind,
                    source_name=source_name,
                    source_version=result.model_version,
                    backend_type=rebased.native_category,
                    category=rebased.category,
                    detector_subtype=rebased.subtype,
                    exact_text=rebased.text,
                    start_char=rebased.start_char,
                    end_char=rebased.end_char,
                    confidence=rebased.confidence,
                    backend_attempt_id=attempt_id,
                    source_group_id=rebased.source_group_id,
                    created_at=finished_at,
                )
                findings.append(finding)
                _insert_finding(
                    connection,
                    run_id=run_id,
                    finding=finding,
                    candidate=rebased,
                    eligible=(
                        rebased.confidence is None or rebased.confidence >= minimum_confidence
                    ),
                    created_at=timestamp,
                )
            connection.execute(
                """
                UPDATE backend_attempts
                SET status = 'succeeded', stop_reason = ?, finished_at = ?,
                    raw_response = ?, usage_json = ?, retryable = 0
                WHERE attempt_id = ?
                """,
                (
                    result.stop_reason,
                    timestamp,
                    _serialize_json(result.raw_output),
                    _serialize_json(result.usage.model_dump(mode="json")),
                    attempt_id,
                ),
            )
            connection.execute(
                "UPDATE backend_work_items SET status = 'succeeded', updated_at = ? WHERE work_item_id = ?",
                (timestamp, work_item.work_item_id),
            )
        return findings

    def fail_attempt(
        self,
        *,
        attempt_id: str,
        work_item: BackendWorkItem,
        error: BackendExecutionError,
        attempt_number: int,
        maximum_attempts: int,
        finished_at: datetime,
        connection: sqlite3.Connection | None = None,
    ) -> str:
        if connection is None:
            with self.store.connection() as owned_connection:
                return self.fail_attempt(
                    attempt_id=attempt_id,
                    work_item=work_item,
                    error=error,
                    attempt_number=attempt_number,
                    maximum_attempts=maximum_attempts,
                    finished_at=finished_at,
                    connection=owned_connection,
                )
        run_id = self.store.run_id(connection)
        timestamp = _utc_text(finished_at)
        can_retry = error.retryable and attempt_number < maximum_attempts
        attempt_status = (
            "truncated"
            if error.truncated
            else "retryable_error"
            if error.retryable
            else "permanent_error"
        )
        work_status = (
            "retry_pending"
            if can_retry
            else "truncated"
            if error.truncated
            else "retry_exhausted"
            if error.retryable
            else "permanent_error"
        )
        error_id = build_content_id("error", run_id, attempt_id, error.code)
        _require_running_attempt(connection, attempt_id)
        connection.execute(
            """
            UPDATE backend_attempts
            SET status = ?, finished_at = ?, raw_response = ?, error_class = ?,
                error_code = ?, error_message = ?, usage_json = ?, retryable = ?
            WHERE attempt_id = ?
            """,
            (
                attempt_status,
                timestamp,
                _serialize_json(error.raw_response) if error.raw_response is not None else None,
                type(error).__name__,
                error.code,
                error.message,
                _usage_from_error(error),
                int(error.retryable),
                attempt_id,
            ),
        )
        connection.execute(
            "UPDATE backend_work_items SET status = ?, updated_at = ? WHERE work_item_id = ?",
            (work_status, timestamp, work_item.work_item_id),
        )
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
                work_item.record_id,
                work_item.stage_name,
                attempt_id,
                type(error).__name__,
                error.code,
                error.message,
                int(error.retryable),
                timestamp,
            ),
        )
        return work_status

    def truncated_attempt_count(self, work_item_id: str) -> int:
        """Return prior truncations for token-tier selection.

        Retryable transport and service errors deliberately do not affect this
        count, so they cannot increase a validator's output-token allowance.
        """

        run_id = self.store.run_id()
        with self.store.connection() as connection:
            return int(
                connection.execute(
                    """
                    SELECT count(*) FROM backend_attempts
                    WHERE run_id = ? AND work_item_id = ? AND status = 'truncated'
                    """,
                    (run_id, work_item_id),
                ).fetchone()[0]
            )

    def insert_rule_findings(
        self,
        *,
        record_id: str,
        source_name: str,
        candidates: list[DetectionCandidate],
        created_at: datetime,
    ) -> list[Finding]:
        run_id = self.store.run_id()
        timestamp = _utc_text(created_at)
        findings: list[Finding] = []
        with self.store.connection() as connection:
            for candidate in candidates:
                finding = Finding(
                    finding_id=build_content_id(
                        "finding",
                        run_id,
                        record_id,
                        source_name,
                        candidate.start_char,
                        candidate.end_char,
                        candidate.category.value,
                        candidate.backend_span_id,
                        candidate.text,
                    ),
                    record_id=record_id,
                    source_kind="rule",
                    source_name=source_name,
                    backend_type=candidate.native_category,
                    category=candidate.category,
                    detector_subtype=candidate.subtype,
                    exact_text=candidate.text,
                    start_char=candidate.start_char,
                    end_char=candidate.end_char,
                    confidence=candidate.confidence,
                    source_group_id=candidate.source_group_id,
                    created_at=created_at,
                )
                findings.append(finding)
                _insert_finding(
                    connection,
                    run_id=run_id,
                    finding=finding,
                    candidate=candidate,
                    eligible=True,
                    created_at=timestamp,
                )
        return findings

    def insert_review_finding(
        self,
        *,
        record_id: str,
        reviewer_id: str,
        candidate: DetectionCandidate,
        created_at: datetime,
        connection: sqlite3.Connection | None = None,
    ) -> Finding:
        if connection is None:
            with self.store.connection() as owned_connection:
                return self.insert_review_finding(
                    record_id=record_id,
                    reviewer_id=reviewer_id,
                    candidate=candidate,
                    created_at=created_at,
                    connection=owned_connection,
                )
        run_id = self.store.run_id(connection)
        timestamp = _utc_text(created_at)
        finding = Finding(
            finding_id=build_content_id(
                "finding",
                run_id,
                record_id,
                "review",
                reviewer_id,
                candidate.start_char,
                candidate.end_char,
                candidate.category.value,
                candidate.text,
            ),
            record_id=record_id,
            source_kind="review",
            source_name=reviewer_id,
            backend_type="MANUAL",
            category=candidate.category,
            detector_subtype="manual",
            exact_text=candidate.text,
            start_char=candidate.start_char,
            end_char=candidate.end_char,
            source_group_id=candidate.source_group_id,
            created_at=created_at,
        )
        _insert_finding(
            connection,
            run_id=run_id,
            finding=finding,
            candidate=candidate,
            eligible=True,
            created_at=timestamp,
        )
        return finding

    def list_findings(
        self,
        record_id: str,
        *,
        eligible_only: bool = False,
        connection: sqlite3.Connection | None = None,
    ) -> list[Finding]:
        if connection is None:
            with self.store.connection() as owned_connection:
                return self.list_findings(
                    record_id,
                    eligible_only=eligible_only,
                    connection=owned_connection,
                )
        run_id = self.store.run_id(connection)
        eligibility_filter = "AND f.is_eligible = 1" if eligible_only else ""
        rows = connection.execute(
            f"""
            SELECT f.* FROM findings f
            WHERE f.run_id = ? AND f.record_id = ?
            {eligibility_filter}
            ORDER BY f.start_char, f.end_char, f.finding_id
            """,
            (run_id, record_id),
        ).fetchall()
        return [_finding_from_row(row) for row in rows]

    def set_eligibility(
        self,
        *,
        record_id: str,
        finding_ids: set[str],
        is_eligible: bool,
        reason: str,
        updated_at: datetime,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        """Persist reviewer eligibility changes without mutating finding provenance."""

        if not finding_ids:
            return
        if connection is None:
            with self.store.connection() as owned_connection:
                self.set_eligibility(
                    record_id=record_id,
                    finding_ids=finding_ids,
                    is_eligible=is_eligible,
                    reason=reason,
                    updated_at=updated_at,
                    connection=owned_connection,
                )
            return
        run_id = self.store.run_id(connection)
        del updated_at
        placeholders = ",".join("?" for _ in finding_ids)
        ordered_ids = sorted(finding_ids)
        found = {
            str(row[0])
            for row in connection.execute(
                f"""
                SELECT finding_id FROM findings
                WHERE run_id = ? AND record_id = ? AND finding_id IN ({placeholders})
                """,
                (run_id, record_id, *ordered_ids),
            )
        }
        missing = finding_ids.difference(found)
        if missing:
            raise ValueError("Unknown finding IDs: " + ", ".join(sorted(missing)))
        connection.executemany(
            """
            UPDATE findings
            SET is_eligible = ?, eligibility_reason = ?
            WHERE run_id = ? AND finding_id = ?
            """,
            ((int(is_eligible), reason, run_id, finding_id) for finding_id in ordered_ids),
        )


def _insert_finding(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    finding: Finding,
    candidate: DetectionCandidate,
    eligible: bool,
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO findings(
            finding_id, run_id, record_id, source_kind, source_name, source_version,
            native_category, canonical_category, detector_subtype, backend_span_id,
            source_group_id, exact_text, start_char, end_char, confidence,
            native_payload_json, backend_attempt_id, is_eligible, eligibility_reason, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_id) DO NOTHING
        """,
        (
            finding.finding_id,
            run_id,
            finding.record_id,
            finding.source_kind,
            finding.source_name,
            finding.source_version,
            candidate.native_category,
            finding.category.value,
            finding.detector_subtype,
            candidate.backend_span_id,
            finding.source_group_id,
            finding.exact_text,
            finding.start_char,
            finding.end_char,
            finding.confidence,
            _serialize_json(candidate.native_payload),
            finding.backend_attempt_id,
            int(eligible),
            "confidence threshold passed" if eligible else "below confidence threshold",
            created_at,
        ),
    )


def _finding_from_row(row: sqlite3.Row) -> Finding:
    return Finding(
        finding_id=str(row["finding_id"]),
        record_id=str(row["record_id"]),
        source_kind=str(row["source_kind"]),  # type: ignore[arg-type]
        source_name=str(row["source_name"]),
        source_version=row["source_version"],
        backend_type=row["native_category"],
        category=PhiCategory(str(row["canonical_category"])),
        detector_subtype=row["detector_subtype"],
        exact_text=str(row["exact_text"]),
        start_char=int(row["start_char"]),
        end_char=int(row["end_char"]),
        confidence=row["confidence"],
        backend_attempt_id=row["backend_attempt_id"],
        source_group_id=row["source_group_id"],
        created_at=datetime.fromisoformat(str(row["created_at"])),
    )


def _require_running_attempt(connection: sqlite3.Connection, attempt_id: str) -> None:
    row = connection.execute(
        "SELECT status FROM backend_attempts WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is None or str(row[0]) != "running":
        raise ValueError(f"Attempt {attempt_id!r} is not running.")


def _json_and_hash(value: Any) -> tuple[str, str]:
    payload = _serialize_json(value)
    return payload, hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _serialize_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _usage_from_error(error: BackendExecutionError) -> str | None:
    if not isinstance(error.raw_response, dict):
        return None
    usage = error.raw_response.get("usage")
    if not isinstance(usage, dict):
        return None
    input_tokens = int(usage.get("inputTokens") or usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("outputTokens") or usage.get("output_tokens") or 0)
    return _serialize_json(
        {
            "request_count": 1,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": int(
                usage.get("totalTokens")
                or usage.get("total_tokens")
                or input_tokens + output_tokens
            ),
        }
    )


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Timestamps must include timezone information.")
    return value.astimezone(UTC).isoformat()
