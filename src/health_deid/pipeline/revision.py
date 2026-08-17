"""Create revised runs while reusing compatible paid detector results."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from health_deid.backends.rules import snapshot_configured_rules
from health_deid.core.secret_refs import SecretResolver
from health_deid.models.config import PipelineConfig
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.precheck import precheck_config
from health_deid.storage.database import SqliteRunStore


@dataclass(frozen=True, slots=True)
class RevisionPlan:
    detection: str
    reason: str

    @property
    def requires_paid_detection(self) -> bool:
        return self.detection == "rerun"


def create_revised_run_context(
    parent_run_path: str | Path,
    config: PipelineConfig | None = None,
    *,
    timestamp: datetime | None = None,
    secret_resolver: SecretResolver | None = None,
    reason: str = "revised settings",
    rerun_detection: bool = False,
) -> RunContext:
    reason = reason.strip()
    if not reason:
        raise ValueError("Revised-run reason cannot be blank.")
    parent = RunContext.from_run_path(parent_run_path)
    parent_store = SqliteRunStore.open(parent.database_path)
    revised_config = _revised_config(parent.config, config, parent_run_id=parent.run_id)
    plan = plan_revised_run(parent_store, revised_config)
    if plan.requires_paid_detection and not rerun_detection:
        raise ValueError(
            "Detector results cannot be reused: "
            f"{plan.reason} Rerunning may incur AWS charges; approve it explicitly."
        )
    _precheck(
        revised_config,
        secret_resolver=secret_resolver,
        skip_detection=plan.detection == "reuse",
    )
    revised_config = snapshot_configured_rules(revised_config)
    context = RunContext.from_config(revised_config, timestamp=timestamp)
    context.run_dir.mkdir(parents=True, exist_ok=False)
    try:
        context.exports_dir.mkdir()
        child_store = SqliteRunStore.create(
            context.database_path,
            run_id=context.run_id,
            config=revised_config,
            created_at=context.created_at,
        )
        summary = parent_store.read_input_import().model_copy(
            update={"imported_at": context.created_at}
        )
        child_store.import_records(parent_store.read_input_records(), summary)
        if plan.detection == "reuse":
            reused = _reuse_detector_results(parent_store, child_store, parent.run_id)
        else:
            reused = {"backends": 0, "attempts": 0, "findings": 0}
        _record_reuse(
            child_store,
            parent_run_id=parent.run_id,
            reason=reason,
            detection=plan.detection,
            reused=reused,
            created_at=context.created_at,
        )
    except BaseException:
        shutil.rmtree(context.run_dir, ignore_errors=True)
        raise
    return context


def plan_revised_run(
    parent_run_path: str | Path | SqliteRunStore,
    config: PipelineConfig | None = None,
) -> RevisionPlan:
    if isinstance(parent_run_path, SqliteRunStore):
        store = parent_run_path
        parent_config = store.read_config()
        revised_config = config or parent_config
    else:
        parent = RunContext.from_run_path(parent_run_path)
        store = SqliteRunStore.open(parent.database_path)
        parent_config = parent.config
        revised_config = _revised_config(
            parent_config,
            config,
            parent_run_id=parent.run_id,
        )
    reusable, reason = _detectors_are_reusable(store, parent_config, revised_config)
    if not revised_config.detection.enabled:
        return RevisionPlan("skip", "Paid detection is disabled in the revised run.")
    return RevisionPlan("reuse" if reusable else "rerun", reason)


def _revised_config(
    parent: PipelineConfig,
    supplied: PipelineConfig | None,
    *,
    parent_run_id: str,
) -> PipelineConfig:
    candidate = supplied or parent
    configured_parent = candidate.run.parent_run_id
    if supplied is not None and configured_parent not in {None, parent_run_id}:
        raise ValueError("The revised config references a different parent run.")
    name = candidate.run.name if supplied is not None else f"{candidate.run.name or 'run'}-revised"
    run = candidate.run.model_copy(update={"name": name, "parent_run_id": parent_run_id})
    return candidate.model_copy(update={"run": run})


def _precheck(
    config: PipelineConfig,
    *,
    secret_resolver: SecretResolver | None,
    skip_detection: bool,
) -> None:
    checked = (
        config.model_copy(
            update={"detection": config.detection.model_copy(update={"enabled": False})}
        )
        if skip_detection
        else config
    )
    result = precheck_config(checked, secret_resolver=secret_resolver, check_input=False)
    if not result.ok:
        raise ValueError(
            "Revised run precheck failed: " + "; ".join(issue.message for issue in result.errors)
        )


def _detectors_are_reusable(
    parent: SqliteRunStore,
    parent_config: PipelineConfig,
    revised_config: PipelineConfig,
) -> tuple[bool, str]:
    if _input_contract(parent_config) != _input_contract(revised_config):
        raise ValueError(
            "Revised runs must keep record IDs, entity IDs, source text, metadata, and "
            "normalization unchanged. Input path and structured-PHI mappings may change."
        )
    if not revised_config.detection.enabled:
        return False, "Detection is disabled."
    if not parent_config.detection.enabled:
        return False, "The parent did not use paid detectors."
    if _detector_contract(parent_config) != _detector_contract(revised_config):
        return False, "Detector settings differ from the parent."

    run_id = parent.run_id()
    expected_backends = {detector.name for detector in parent_config.detection.detectors}
    with parent.read_snapshot() as connection:
        actual_backends = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT backend_id FROM backend_definitions
                WHERE run_id = ? AND backend_kind = 'detector'
                """,
                (run_id,),
            )
        }
        active_records = {
            str(row[0])
            for row in connection.execute(
                "SELECT record_id FROM records WHERE run_id = ? AND status != 'excluded'",
                (run_id,),
            )
        }
        pairs = {
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                """
                SELECT record_id, backend_id FROM backend_work_items
                WHERE run_id = ? AND stage_name = 'detection'
                GROUP BY record_id, backend_id
                HAVING sum(status != 'succeeded') = 0
                """,
                (run_id,),
            )
        }
    expected_pairs = {
        (record_id, backend_id) for record_id in active_records for backend_id in expected_backends
    }
    if actual_backends != expected_backends or pairs != expected_pairs:
        return False, "The parent does not contain a complete successful detector ledger."
    return True, "All parent detector results match the revised run."


def _reuse_detector_results(
    parent: SqliteRunStore,
    child: SqliteRunStore,
    parent_run_id: str,
) -> dict[str, int]:
    child_run_id = child.run_id()
    with child.connection() as connection:
        connection.execute("ATTACH DATABASE ? AS parent_db", (str(parent.path.resolve()),))
        connection.execute(
            """
            INSERT INTO backend_definitions
            SELECT ?, backend_id, backend_kind, backend_name, backend_version, model_id,
                   settings_json, settings_sha256, taxonomy_version, prompt_text,
                   prompt_sha256, schema_json, schema_sha256, created_at
            FROM parent_db.backend_definitions
            WHERE run_id = ? AND backend_kind = 'detector'
            """,
            (child_run_id, parent_run_id),
        )
        connection.execute(
            """
            INSERT INTO backend_work_items
            SELECT work_item_id, ?, record_id, backend_id, stage_name, chunk_index,
                   start_char, end_char, input_sha256, status, created_at, updated_at
            FROM parent_db.backend_work_items
            WHERE run_id = ? AND stage_name = 'detection'
            """,
            (child_run_id, parent_run_id),
        )
        connection.execute(
            """
            INSERT INTO backend_attempts
            SELECT attempt_id, ?, record_id, backend_id, work_item_id, stage_name,
                   attempt_number, status, stop_reason, started_at, finished_at,
                   request_metadata_json, raw_response, usage_json, error_class,
                   error_code, error_message, retryable
            FROM parent_db.backend_attempts
            WHERE run_id = ? AND stage_name = 'detection'
            """,
            (child_run_id, parent_run_id),
        )
        connection.execute(
            """
            INSERT INTO findings
            SELECT finding_id, ?, record_id, source_kind, source_name, source_version,
                   native_category, canonical_category, detector_subtype, backend_span_id,
                   source_group_id, exact_text, start_char, end_char, confidence,
                   native_payload_json, backend_attempt_id, is_eligible,
                   eligibility_reason, created_at
            FROM parent_db.findings
            WHERE run_id = ? AND source_kind IN ('aws', 'llm')
            """,
            (child_run_id, parent_run_id),
        )
        row = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM backend_definitions
                 WHERE run_id = ? AND backend_kind = 'detector'),
                (SELECT count(*) FROM backend_attempts
                 WHERE run_id = ? AND stage_name = 'detection'),
                (SELECT count(*) FROM findings
                 WHERE run_id = ? AND source_kind IN ('aws', 'llm'))
            """,
            (child_run_id, child_run_id, child_run_id),
        ).fetchone()
    assert row is not None
    return {"backends": int(row[0]), "attempts": int(row[1]), "findings": int(row[2])}


def _record_reuse(
    child: SqliteRunStore,
    *,
    parent_run_id: str,
    reason: str,
    detection: str,
    reused: dict[str, int],
    created_at: datetime,
) -> None:
    payload = {
        "parent_run_id": parent_run_id,
        "reason": reason,
        "input": "reused",
        "detection": detection,
        "reused_backends": reused["backends"],
        "reused_attempts": reused["attempts"],
        "reused_findings": reused["findings"],
        "created_at": _utc_text(created_at),
    }
    with child.connection() as connection:
        connection.execute(
            "UPDATE runs SET reuse_json = ? WHERE run_id = ?",
            (json.dumps(payload, sort_keys=True), child.run_id(connection)),
        )


def _input_contract(config: PipelineConfig) -> dict[str, object]:
    payload = config.input.model_dump(mode="json")
    payload.pop("path", None)
    payload.pop("structured_phi_columns", None)
    return payload


def _detector_contract(config: PipelineConfig) -> list[dict[str, object]]:
    contracts: list[dict[str, object]] = []
    for detector in config.detection.detectors:
        payload = detector.model_dump(mode="json")
        payload.pop("cost_per_100_characters_usd", None)
        payload.pop("input_cost_per_million_tokens", None)
        payload.pop("output_cost_per_million_tokens", None)
        contracts.append(payload)
    return contracts


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Revision timestamp must be timezone-aware.")
    return value.astimezone(UTC).isoformat()


__all__ = ["RevisionPlan", "create_revised_run_context", "plan_revised_run"]
