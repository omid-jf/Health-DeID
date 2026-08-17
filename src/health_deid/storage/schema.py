from __future__ import annotations

SQLITE_APPLICATION_ID = 0x48444549
SQLITE_SCHEMA_VERSION = 2


SQLITE_SCHEMA = """
CREATE TABLE schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    name TEXT,
    status TEXT NOT NULL CHECK (status IN (
        'initialized', 'running', 'awaiting_review', 'completed',
        'completed_with_errors', 'blocked', 'failed'
    )),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    parent_run_id TEXT,
    config_version INTEGER NOT NULL CHECK (config_version >= 1),
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    config_sha256 TEXT NOT NULL CHECK (
        length(config_sha256) = 64 AND config_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    input_source_name TEXT,
    input_source_path TEXT,
    input_format TEXT CHECK (input_format IS NULL OR input_format IN ('parquet', 'jsonl')),
    input_size_bytes INTEGER CHECK (input_size_bytes IS NULL OR input_size_bytes >= 0),
    input_sha256 TEXT CHECK (
        input_sha256 IS NULL OR
        (length(input_sha256) = 64 AND input_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    record_count INTEGER CHECK (record_count IS NULL OR record_count >= 1),
    active_count INTEGER CHECK (active_count IS NULL OR active_count >= 0),
    excluded_count INTEGER CHECK (excluded_count IS NULL OR excluded_count >= 0),
    normalized_count INTEGER CHECK (normalized_count IS NULL OR normalized_count >= 0),
    imported_at TEXT,
    reuse_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(reuse_json)),
    CHECK (
        record_count IS NULL OR
        (active_count + excluded_count = record_count AND normalized_count <= record_count)
    )
) STRICT;

CREATE TABLE run_stages (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    stage_name TEXT NOT NULL CHECK (stage_name IN (
        'input', 'detection', 'transformation', 'validation',
        'review', 'finalization', 'export'
    )),
    status TEXT NOT NULL CHECK (status IN (
        'pending', 'running', 'completed', 'completed_with_errors',
        'blocked', 'failed', 'skipped'
    )),
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY (run_id, stage_name)
) STRICT;

CREATE TABLE records (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    record_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    source_index INTEGER NOT NULL CHECK (source_index >= 0),
    raw_source_text TEXT,
    normalized_text TEXT,
    normalization_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(normalization_json)),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    draft_metadata_json TEXT CHECK (
        draft_metadata_json IS NULL OR json_valid(draft_metadata_json)
    ),
    final_metadata_json TEXT CHECK (final_metadata_json IS NULL OR json_valid(final_metadata_json)),
    status TEXT NOT NULL CHECK (status IN (
        'processing', 'awaiting_review', 'reviewed', 'excluded', 'ready', 'failed'
    )),
    final_rendering_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, record_id),
    UNIQUE (run_id, source_index)
) STRICT;

CREATE INDEX records_by_entity ON records(run_id, entity_id);
CREATE INDEX records_by_status ON records(run_id, status, source_index);

CREATE TABLE record_stage_states (
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    stage_name TEXT NOT NULL CHECK (stage_name IN (
        'input', 'detection', 'transformation', 'validation',
        'review', 'finalization', 'export'
    )),
    status TEXT NOT NULL CHECK (status IN (
        'pending', 'running', 'succeeded', 'retry_pending', 'retry_exhausted',
        'permanent_error', 'blocked', 'review_pending', 'excluded', 'skipped'
    )),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, record_id, stage_name),
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX record_stage_states_by_status
ON record_stage_states(run_id, stage_name, status);

CREATE TABLE backend_definitions (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    backend_id TEXT NOT NULL,
    backend_kind TEXT NOT NULL CHECK (backend_kind IN ('detector', 'validator')),
    backend_name TEXT NOT NULL,
    backend_version TEXT,
    model_id TEXT,
    settings_json TEXT NOT NULL CHECK (json_valid(settings_json)),
    settings_sha256 TEXT NOT NULL CHECK (
        length(settings_sha256) = 64 AND settings_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    taxonomy_version TEXT,
    prompt_text TEXT,
    prompt_sha256 TEXT,
    schema_json TEXT CHECK (schema_json IS NULL OR json_valid(schema_json)),
    schema_sha256 TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, backend_id)
) STRICT;

CREATE TABLE backend_work_items (
    work_item_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    stage_name TEXT NOT NULL CHECK (stage_name IN ('detection', 'validation')),
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    start_char INTEGER NOT NULL CHECK (start_char >= 0),
    end_char INTEGER NOT NULL CHECK (end_char >= start_char),
    input_sha256 TEXT NOT NULL CHECK (
        length(input_sha256) = 64 AND input_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN (
        'pending', 'running', 'succeeded', 'retry_pending', 'retry_exhausted',
        'permanent_error', 'truncated', 'cancelled'
    )),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (run_id, record_id, backend_id, chunk_index),
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, backend_id) REFERENCES backend_definitions(run_id, backend_id)
        ON DELETE CASCADE
) STRICT;

CREATE TABLE backend_attempts (
    attempt_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    record_id TEXT,
    backend_id TEXT NOT NULL,
    work_item_id TEXT,
    stage_name TEXT NOT NULL CHECK (stage_name IN ('detection', 'validation')),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    status TEXT NOT NULL CHECK (status IN (
        'running', 'succeeded', 'retryable_error', 'permanent_error',
        'truncated', 'cancelled'
    )),
    stop_reason TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    request_metadata_json TEXT CHECK (
        request_metadata_json IS NULL OR json_valid(request_metadata_json)
    ),
    raw_response TEXT,
    usage_json TEXT CHECK (usage_json IS NULL OR json_valid(usage_json)),
    error_class TEXT,
    error_code TEXT,
    error_message TEXT,
    retryable INTEGER CHECK (retryable IS NULL OR retryable IN (0, 1)),
    UNIQUE (run_id, work_item_id, attempt_number),
    FOREIGN KEY (run_id, backend_id) REFERENCES backend_definitions(run_id, backend_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (work_item_id) REFERENCES backend_work_items(work_item_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX backend_attempts_by_record
ON backend_attempts(run_id, record_id, stage_name, backend_id, attempt_number);

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('aws', 'llm', 'rule', 'review')),
    source_name TEXT NOT NULL,
    source_version TEXT,
    native_category TEXT NOT NULL,
    canonical_category TEXT NOT NULL,
    detector_subtype TEXT,
    backend_span_id TEXT,
    source_group_id TEXT,
    exact_text TEXT NOT NULL,
    start_char INTEGER NOT NULL CHECK (start_char >= 0),
    end_char INTEGER NOT NULL CHECK (end_char > start_char),
    confidence REAL CHECK (confidence IS NULL OR confidence BETWEEN 0.0 AND 1.0),
    native_payload_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(native_payload_json)),
    backend_attempt_id TEXT,
    is_eligible INTEGER NOT NULL DEFAULT 1 CHECK (is_eligible IN (0, 1)),
    eligibility_reason TEXT NOT NULL DEFAULT 'detected',
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE,
    FOREIGN KEY (backend_attempt_id) REFERENCES backend_attempts(attempt_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX findings_idempotency
ON findings(run_id, record_id, source_name, start_char, end_char, canonical_category,
            ifnull(backend_span_id, ''), exact_text);
CREATE INDEX findings_by_record
ON findings(run_id, record_id, start_char, end_char, canonical_category);

CREATE TABLE resolution_revisions (
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    resolver_version TEXT NOT NULL,
    findings_sha256 TEXT NOT NULL CHECK (
        length(findings_sha256) = 64 AND findings_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    is_active INTEGER NOT NULL CHECK (is_active IN (0, 1)),
    reason TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, record_id, revision),
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX one_active_resolution_per_record
ON resolution_revisions(run_id, record_id) WHERE is_active = 1;

CREATE TABLE span_groups (
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    resolution_revision INTEGER NOT NULL,
    group_id TEXT NOT NULL,
    canonical_category TEXT NOT NULL,
    start_char INTEGER NOT NULL CHECK (start_char >= 0),
    end_char INTEGER NOT NULL CHECK (end_char > start_char),
    finding_ids_json TEXT NOT NULL CHECK (json_valid(finding_ids_json)),
    resolution_status TEXT NOT NULL CHECK (
        resolution_status IN ('resolved', 'ambiguous', 'rejected', 'superseded')
    ),
    resolution_reason TEXT NOT NULL,
    PRIMARY KEY (run_id, record_id, resolution_revision, group_id),
    FOREIGN KEY (run_id, record_id, resolution_revision)
        REFERENCES resolution_revisions(run_id, record_id, revision) ON DELETE CASCADE
) STRICT;

CREATE TABLE transformation_plans (
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK (plan_revision >= 1),
    resolution_revision INTEGER NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision = 1),
    purpose TEXT NOT NULL CHECK (purpose IN ('draft', 'final')),
    status TEXT NOT NULL CHECK (status IN ('active', 'stale')),
    created_at TEXT NOT NULL,
    stale_at TEXT,
    stale_reason TEXT,
    PRIMARY KEY (run_id, record_id, plan_revision),
    FOREIGN KEY (run_id, record_id, resolution_revision)
        REFERENCES resolution_revisions(run_id, record_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_active_plan_per_record_purpose
ON transformation_plans(run_id, record_id, purpose) WHERE status = 'active';

CREATE TABLE transform_events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    group_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('retain', 'redact', 'generalize', 'surrogate')),
    strategy TEXT,
    canonical_category TEXT NOT NULL,
    original_text TEXT NOT NULL,
    replacement_text TEXT,
    input_start_char INTEGER NOT NULL CHECK (input_start_char >= 0),
    input_end_char INTEGER NOT NULL CHECK (input_end_char > input_start_char),
    surrogate_assignment_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('planned', 'rendered', 'stale', 'rejected')),
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, record_id, plan_revision)
        REFERENCES transformation_plans(run_id, record_id, plan_revision) ON DELETE CASCADE
) STRICT;

CREATE INDEX transform_events_by_record
ON transform_events(run_id, record_id, plan_revision, input_start_char);

CREATE TABLE renderings (
    rendering_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('preview', 'draft', 'final')),
    rendered_text TEXT NOT NULL,
    text_sha256 TEXT NOT NULL CHECK (
        length(text_sha256) = 64 AND text_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    events_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(events_json)),
    is_stale INTEGER NOT NULL DEFAULT 0 CHECK (is_stale IN (0, 1)),
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, record_id, plan_revision)
        REFERENCES transformation_plans(run_id, record_id, plan_revision) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX one_current_rendering_per_kind
ON renderings(run_id, record_id, kind) WHERE is_stale = 0;

CREATE TABLE surrogate_assignments (
    assignment_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    assignment_kind TEXT NOT NULL CHECK (assignment_kind IN ('synthetic', 'date_shift')),
    method TEXT NOT NULL CHECK (method IN ('faker', 'custom_list', 'date_shift')),
    pool_sha256 TEXT,
    canonical_category TEXT NOT NULL,
    consistency_scope TEXT NOT NULL CHECK (consistency_scope IN (
        'occurrence', 'record', 'entity'
    )),
    container_key_hmac TEXT,
    scope_key_hmac TEXT NOT NULL CHECK (
        length(scope_key_hmac) = 64 AND scope_key_hmac NOT GLOB '*[^0-9a-f]*'
    ),
    surrogate_value TEXT NOT NULL,
    entity_id TEXT,
    policy_revision INTEGER,
    secret_reference TEXT,
    algorithm_version TEXT,
    shift_weeks INTEGER,
    created_at TEXT NOT NULL,
    CHECK (
        (assignment_kind = 'synthetic' AND method IN ('faker', 'custom_list')
            AND container_key_hmac IS NOT NULL
            AND entity_id IS NULL AND policy_revision IS NULL AND shift_weeks IS NULL)
        OR
        (assignment_kind = 'date_shift' AND method = 'date_shift'
            AND container_key_hmac IS NULL
            AND entity_id IS NOT NULL AND policy_revision = 1
            AND secret_reference IS NOT NULL AND algorithm_version IS NOT NULL
            AND shift_weeks IS NOT NULL AND shift_weeks != 0)
    )
) STRICT;

CREATE UNIQUE INDEX one_synthetic_assignment_per_scope
ON surrogate_assignments(run_id, method, canonical_category, scope_key_hmac)
WHERE assignment_kind = 'synthetic';

CREATE UNIQUE INDEX unique_synthetic_value_within_container
ON surrogate_assignments(
    run_id, method, canonical_category, container_key_hmac, surrogate_value
)
WHERE assignment_kind = 'synthetic';

CREATE UNIQUE INDEX one_date_shift_per_entity
ON surrogate_assignments(run_id, entity_id, policy_revision)
WHERE assignment_kind = 'date_shift';

CREATE TABLE structured_transform_events (
    structured_event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision = 1),
    purpose TEXT NOT NULL CHECK (purpose IN ('draft', 'final')),
    column_name TEXT NOT NULL,
    canonical_category TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('retain', 'redact', 'generalize', 'surrogate')),
    original_value_json TEXT NOT NULL CHECK (json_valid(original_value_json)),
    replacement_value_json TEXT NOT NULL CHECK (json_valid(replacement_value_json)),
    surrogate_assignment_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, record_id, plan_revision)
        REFERENCES transformation_plans(run_id, record_id, plan_revision) ON DELETE CASCADE,
    FOREIGN KEY (surrogate_assignment_id)
        REFERENCES surrogate_assignments(assignment_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE validation_results (
    validation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    rendering_id TEXT NOT NULL REFERENCES renderings(rendering_id) ON DELETE CASCADE,
    backend_attempt_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'technical_error', 'truncated')),
    raw_violation INTEGER CHECK (raw_violation IS NULL OR raw_violation IN (0, 1)),
    effective_violation INTEGER CHECK (
        effective_violation IS NULL OR effective_violation IN (0, 1)
    ),
    rationale TEXT,
    is_stale INTEGER NOT NULL DEFAULT 0 CHECK (is_stale IN (0, 1)),
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE,
    FOREIGN KEY (backend_attempt_id) REFERENCES backend_attempts(attempt_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_current_validation_per_record
ON validation_results(run_id, record_id) WHERE is_stale = 0;

CREATE TABLE validation_findings (
    validation_finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    validation_id TEXT NOT NULL REFERENCES validation_results(validation_id) ON DELETE CASCADE,
    canonical_category TEXT NOT NULL,
    evidence TEXT,
    rule_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(rule_ids_json)),
    confidence TEXT CHECK (confidence IS NULL OR confidence IN ('low', 'medium', 'high')),
    rationale TEXT NOT NULL,
    ignored_by_policy INTEGER NOT NULL CHECK (ignored_by_policy IN (0, 1)),
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE review_decisions (
    decision_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    basis_plan_revision INTEGER NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition IN (
        'approved_unchanged', 'corrected', 'excluded'
    )),
    reviewer_id TEXT,
    review_seconds INTEGER NOT NULL DEFAULT 0 CHECK (review_seconds >= 0),
    span_events_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(span_events_json)),
    structured_events_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(structured_events_json)),
    validation_reviews_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(validation_reviews_json)),
    record_comment TEXT,
    is_current INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0, 1)),
    is_stale INTEGER NOT NULL DEFAULT 0 CHECK (is_stale IN (0, 1)),
    stale_reason TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, record_id, basis_plan_revision)
        REFERENCES transformation_plans(run_id, record_id, plan_revision) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_current_review_decision
ON review_decisions(run_id, record_id) WHERE is_current = 1;

CREATE TABLE review_workspaces (
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    reviewer_id TEXT NOT NULL,
    basis_plan_revision INTEGER NOT NULL CHECK (basis_plan_revision >= 1),
    span_events_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(span_events_json)),
    structured_events_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(structured_events_json)),
    validation_reviews_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(validation_reviews_json)),
    record_comment TEXT,
    review_seconds INTEGER NOT NULL DEFAULT 0 CHECK (review_seconds >= 0),
    timer_started_at TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, record_id),
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, record_id, basis_plan_revision)
        REFERENCES transformation_plans(run_id, record_id, plan_revision) ON DELETE CASCADE
) STRICT;

CREATE INDEX active_review_timers
ON review_workspaces(run_id, reviewer_id, timer_started_at);

CREATE TABLE processing_errors (
    error_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    record_id TEXT,
    stage_name TEXT NOT NULL CHECK (stage_name IN (
        'run', 'input', 'detection', 'transformation', 'validation',
        'review', 'finalization', 'export'
    )),
    backend_attempt_id TEXT REFERENCES backend_attempts(attempt_id) ON DELETE SET NULL,
    error_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    message TEXT NOT NULL,
    retryable INTEGER NOT NULL CHECK (retryable IN (0, 1)),
    resolved INTEGER NOT NULL DEFAULT 0 CHECK (resolved IN (0, 1)),
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    FOREIGN KEY (run_id, record_id) REFERENCES records(run_id, record_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX processing_errors_by_status
ON processing_errors(run_id, stage_name, resolved, retryable);

CREATE TABLE exports (
    export_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    format TEXT NOT NULL CHECK (format IN ('parquet', 'jsonl')),
    mode TEXT NOT NULL CHECK (mode IN ('ready_only', 'all_records')),
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    output_path TEXT NOT NULL,
    output_sha256 TEXT CHECK (
        output_sha256 IS NULL OR
        (length(output_sha256) = 64 AND output_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    selected_columns_json TEXT NOT NULL CHECK (json_valid(selected_columns_json)),
    record_count INTEGER NOT NULL DEFAULT 0 CHECK (record_count >= 0),
    error_message TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
) STRICT;
"""


REQUIRED_SQLITE_TABLES = frozenset(
    {
        "backend_attempts",
        "backend_definitions",
        "backend_work_items",
        "exports",
        "findings",
        "processing_errors",
        "record_stage_states",
        "records",
        "renderings",
        "resolution_revisions",
        "review_decisions",
        "review_workspaces",
        "run_stages",
        "runs",
        "schema_metadata",
        "span_groups",
        "structured_transform_events",
        "surrogate_assignments",
        "transform_events",
        "transformation_plans",
        "validation_findings",
        "validation_results",
    }
)
