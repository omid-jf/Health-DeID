from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from math import ceil
from pathlib import Path
from typing import Any, Literal

import boto3
from polars.exceptions import PolarsError

from health_deid.backends.bedrock import detection_input_characters, safeguard_input_characters
from health_deid.backends.runtime import chunk_utf8_text
from health_deid.core.secret_refs import EnvironmentSecretResolver, SecretResolver
from health_deid.models.config import (
    AwsComprehendDetectorConfig,
    PipelineConfig,
)
from health_deid.models.input import EntityIdSource, NormalizedInputRecord
from health_deid.models.policy import CustomListSurrogate, TransformationAction
from health_deid.pipeline.input import normalize_input_records, read_input_file

PrecheckSeverity = Literal["error", "warning", "info"]


@dataclass(frozen=True, slots=True)
class PrecheckIssue:
    """One actionable configuration issue found before processing starts."""

    severity: PrecheckSeverity
    code: str
    message: str
    field: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "field": self.field,
        }


@dataclass(frozen=True, slots=True)
class BackendCostEstimate:
    """Estimated one-pass usage and cost for one configured AWS backend."""

    backend_id: str
    backend: str
    request_count: int
    input_characters: int
    estimated_input_tokens: int | None = None
    estimated_output_tokens: int | None = None
    estimated_total_tokens: int | None = None
    maximum_output_tokens_per_request: int | None = None
    billable_100_character_units: int | None = None
    estimated_input_cost_usd: float | None = None
    estimated_output_cost_usd: float | None = None
    estimated_total_cost_usd: float | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "backend_id": self.backend_id,
            "backend": self.backend,
            "request_count": self.request_count,
            "input_characters": self.input_characters,
            "estimated_input_tokens": self.estimated_input_tokens,
            "estimated_output_tokens": self.estimated_output_tokens,
            "estimated_total_tokens": self.estimated_total_tokens,
            "maximum_output_tokens_per_request": self.maximum_output_tokens_per_request,
            "billable_100_character_units": self.billable_100_character_units,
            "estimated_input_cost_usd": self.estimated_input_cost_usd,
            "estimated_output_cost_usd": self.estimated_output_cost_usd,
            "estimated_total_cost_usd": self.estimated_total_cost_usd,
        }


@dataclass(frozen=True, slots=True)
class CostEstimate:
    """Shared one-pass estimate reported by the API, CLI, and UI."""

    active_record_count: int
    backends: tuple[BackendCostEstimate, ...]
    estimated_input_cost_usd: float | None
    estimated_output_cost_usd: float | None
    estimated_total_cost_usd: float | None

    @property
    def pricing_complete(self) -> bool:
        return self.estimated_total_cost_usd is not None

    def as_dict(self) -> dict[str, object]:
        return {
            "basis": "one_pass",
            "active_record_count": self.active_record_count,
            "pricing_complete": self.pricing_complete,
            "estimated_input_cost_usd": self.estimated_input_cost_usd,
            "estimated_output_cost_usd": self.estimated_output_cost_usd,
            "estimated_total_cost_usd": self.estimated_total_cost_usd,
            "backends": [backend.as_dict() for backend in self.backends],
            "notes": [
                "Bedrock tokens are estimated as the ceiling of request characters divided by 4.",
                "Bedrock output assumes every first request uses its configured output-token limit.",
                "Validation starts at the first output-token tier; truncation-triggered tier "
                "escalation is excluded.",
                "Validation uses original content as a length proxy for de-identified content.",
                "Automatic and manual retries, failed requests, credits, discounts, and taxes "
                "are excluded.",
            ],
        }


@dataclass(frozen=True, slots=True)
class PrecheckResult:
    """Complete non-mutating precheck result."""

    issues: tuple[PrecheckIssue, ...]
    record_count: int | None = None
    cost_estimate: CostEstimate | None = None

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    @property
    def errors(self) -> tuple[PrecheckIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> tuple[PrecheckIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "warning")

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "record_count": self.record_count,
            "issues": [issue.as_dict() for issue in self.issues],
            "cost_estimate": (
                self.cost_estimate.as_dict() if self.cost_estimate is not None else None
            ),
        }


def precheck_config(
    config: PipelineConfig,
    *,
    secret_resolver: SecretResolver | None = None,
    check_input: bool = True,
    aws_session: Any | None = None,
) -> PrecheckResult:
    """Validate a run without making detector, validator, or other paid calls."""

    issues: list[PrecheckIssue] = []
    resolver = secret_resolver or EnvironmentSecretResolver()

    record_count, records = _check_input(config, issues) if check_input else (None, None)
    _check_entity_scope(config, issues)
    _check_detection(config, issues, aws_session=aws_session)
    _check_rules(config, issues)
    _check_validation_and_review(config, issues, aws_session=aws_session)
    _check_replacements(config, resolver, issues)

    if not issues:
        issues.append(
            PrecheckIssue(
                "info",
                "ready",
                "Configuration is ready. No backend request was made during precheck.",
            )
        )

    cost_estimate = estimate_cost(config, records) if records is not None else None
    return PrecheckResult(
        tuple(issues),
        record_count=record_count,
        cost_estimate=cost_estimate,
    )


def estimate_cost(
    config: PipelineConfig,
    records: list[NormalizedInputRecord],
) -> CostEstimate:
    """Estimate configured one-pass AWS usage without making backend calls."""

    active = [record for record in records if record.status == "active"]
    backends: list[BackendCostEstimate] = []

    if config.detection.enabled:
        for detector in config.detection.detectors:
            if isinstance(detector, AwsComprehendDetectorConfig):
                chunks = [
                    chunk
                    for record in active
                    for chunk in chunk_utf8_text(
                        record.source_text or "",
                        maximum_bytes=detector.maximum_bytes,
                        overlap_characters=detector.overlap_characters,
                    )
                ]
                units = sum(max(1, ceil(len(chunk.text) / 100)) for chunk in chunks)
                input_cost = (
                    units * detector.cost_per_100_characters_usd
                    if detector.cost_per_100_characters_usd is not None
                    else None
                )
                backends.append(
                    BackendCostEstimate(
                        backend_id=detector.name,
                        backend=detector.backend,
                        request_count=len(chunks),
                        input_characters=sum(len(chunk.text) for chunk in chunks),
                        billable_100_character_units=units,
                        estimated_input_cost_usd=input_cost,
                        estimated_output_cost_usd=0.0,
                        estimated_total_cost_usd=input_cost,
                    )
                )
                continue

            character_counts = [
                detection_input_characters(record.source_text or "") for record in active
            ]
            input_tokens = sum(ceil(characters / 4) for characters in character_counts)
            output_tokens = len(active) * detector.max_output_tokens
            input_cost = _token_cost(
                input_tokens,
                detector.input_cost_per_million_tokens,
            )
            output_cost = _token_cost(
                output_tokens,
                detector.output_cost_per_million_tokens,
            )
            backends.append(
                BackendCostEstimate(
                    backend_id=detector.name,
                    backend=detector.backend,
                    request_count=len(active),
                    input_characters=sum(character_counts),
                    estimated_input_tokens=input_tokens,
                    estimated_output_tokens=output_tokens,
                    estimated_total_tokens=input_tokens + output_tokens,
                    maximum_output_tokens_per_request=detector.max_output_tokens,
                    estimated_input_cost_usd=input_cost,
                    estimated_output_cost_usd=output_cost,
                    estimated_total_cost_usd=_combined_cost(input_cost, output_cost),
                )
            )

    if config.validation.enabled:
        validation_character_counts: list[int] = []

        for record in active:
            text = record.source_text or ""
            validation_character_counts.append(
                safeguard_input_characters(
                    original_text=text,
                    deidentified_text=text,
                )
            )

        input_tokens = sum(ceil(characters / 4) for characters in validation_character_counts)
        first_output_tier = config.validation.output_token_tiers[0]
        output_tokens = len(active) * first_output_tier
        input_cost = _token_cost(
            input_tokens,
            config.validation.input_cost_per_million_tokens,
        )
        output_cost = _token_cost(
            output_tokens,
            config.validation.output_cost_per_million_tokens,
        )
        backends.append(
            BackendCostEstimate(
                backend_id="validator",
                backend=config.validation.backend,
                request_count=len(active),
                input_characters=sum(validation_character_counts),
                estimated_input_tokens=input_tokens,
                estimated_output_tokens=output_tokens,
                estimated_total_tokens=input_tokens + output_tokens,
                maximum_output_tokens_per_request=first_output_tier,
                estimated_input_cost_usd=input_cost,
                estimated_output_cost_usd=output_cost,
                estimated_total_cost_usd=_combined_cost(input_cost, output_cost),
            )
        )

    input_cost = _complete_sum([backend.estimated_input_cost_usd for backend in backends])
    output_cost = _complete_sum(
        [
            backend.estimated_output_cost_usd
            for backend in backends
            if backend.estimated_output_tokens is not None
        ]
    )

    return CostEstimate(
        active_record_count=len(active),
        backends=tuple(backends),
        estimated_input_cost_usd=input_cost,
        estimated_output_cost_usd=output_cost,
        estimated_total_cost_usd=_combined_cost(input_cost, output_cost),
    )


def _check_input(
    config: PipelineConfig,
    issues: list[PrecheckIssue],
) -> tuple[int | None, list[NormalizedInputRecord] | None]:
    try:
        raw_records = read_input_file(config.input)
    except (OSError, PolarsError, ValueError) as exc:
        issues.append(PrecheckIssue("error", "input_unreadable", str(exc), "input.path"))
        return None, None

    available_columns = set(raw_records.columns)
    entity_column = config.input.entity_id.source_column(
        record_id_column=config.input.record_id_column
    )
    required_columns = {
        config.input.record_id_column,
        entity_column,
        config.input.text_column,
        *config.input.metadata_columns,
    }
    missing_columns = sorted(required_columns.difference(available_columns))

    if missing_columns:
        issues.append(
            PrecheckIssue(
                "error",
                "input_columns_missing",
                "Input is missing configured columns: " + ", ".join(missing_columns),
                "input",
            )
        )

    record_count = raw_records.height
    if record_count == 0:
        issues.append(
            PrecheckIssue("error", "input_empty", "Input contains no records.", "input.path")
        )

    if missing_columns or record_count == 0:
        return record_count, None

    try:
        records = normalize_input_records(raw_records, config.input)
    except (OSError, PolarsError, ValueError) as exc:
        issues.append(
            PrecheckIssue(
                "error",
                "input_invalid",
                str(exc),
                "input",
            )
        )
        return record_count, None
    return record_count, records


def _check_entity_scope(config: PipelineConfig, issues: list[PrecheckIssue]) -> None:
    if config.input.entity_id.source is not EntityIdSource.RECORD_ID:
        return

    issues.append(
        PrecheckIssue(
            "info",
            "record_id_used_as_entity_id",
            "Entity-consistent transformations will be scoped to one record.",
            "input.entity_id",
        )
    )


def _check_detection(
    config: PipelineConfig,
    issues: list[PrecheckIssue],
    *,
    aws_session: Any | None,
) -> None:
    if not config.detection.enabled:
        return

    for index, detector in enumerate(config.detection.detectors):
        _check_aws_settings(
            detector.region_name,
            issues,
            f"detection.detectors.{index}",
            session=aws_session,
        )


def _check_rules(config: PipelineConfig, issues: list[PrecheckIssue]) -> None:
    if not config.rules.enabled or config.rules.embedded is not None:
        return

    rules_path = config.rules.rules_path
    if rules_path is not None and Path(rules_path).is_file():
        return

    issues.append(
        PrecheckIssue(
            "error",
            "rules_file_unreadable",
            f"Rules file does not exist: {rules_path}",
            "rules.rules_path",
        )
    )


def _check_validation_and_review(
    config: PipelineConfig,
    issues: list[PrecheckIssue],
    *,
    aws_session: Any | None,
) -> None:
    if config.validation.enabled:
        _check_aws_settings(
            config.validation.region_name,
            issues,
            "validation",
            session=aws_session,
        )

        if not config.review.enabled:
            issues.append(
                PrecheckIssue(
                    "error",
                    "validator_requires_review",
                    "Automated validation requires human review of validator concerns.",
                    "review.enabled",
                )
            )

    review_requires_validation = (
        config.review.enabled
        and not config.validation.enabled
        and config.review.review_scope != "all"
    )
    if review_requires_validation:
        issues.append(
            PrecheckIssue(
                "error",
                "review_scope_requires_validation",
                "Review without automated validation must review all records.",
                "review.review_scope",
            )
        )


def _check_replacements(
    config: PipelineConfig,
    resolver: SecretResolver,
    issues: list[PrecheckIssue],
) -> None:
    secret_references: set[tuple[str, str]] = set()

    for category, category_policy in config.policy.categories.items():
        if category_policy.action is not TransformationAction.SURROGATE:
            continue
        replacement = category_policy.surrogate
        assert replacement is not None
        field = f"policy.categories.{category.value}.surrogate"
        secret_references.add((replacement.secret_reference, f"{field}.secret_reference"))
        if isinstance(replacement, CustomListSurrogate):
            issues.append(
                PrecheckIssue(
                    "warning",
                    "custom_list_capacity_runtime_check",
                    f"The {category.value} list has {len(replacement.values)} values. Capacity "
                    "is checked after findings are resolved, and the run will fail clearly if "
                    "the list is too small.",
                    field,
                )
            )
    for reference, field in sorted(secret_references):
        try:
            resolver.resolve(reference)
        except (KeyError, ValueError) as exc:
            issues.append(PrecheckIssue("error", "secret_unavailable", str(exc), field))


def _check_aws_settings(
    configured_region: str | None,
    issues: list[PrecheckIssue],
    field: str,
    *,
    session: Any | None,
) -> None:
    try:
        resolved_session = session or boto3.Session()
        session_region = resolved_session.region_name
    except Exception as exc:
        issues.append(
            PrecheckIssue(
                "error",
                "aws_credentials_expired_or_unavailable",
                f"AWS configuration could not be loaded: {exc}",
                field,
            )
        )
        return

    region = (
        configured_region
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or session_region
    )
    if not region:
        issues.append(
            PrecheckIssue(
                "warning",
                "aws_region_not_verified",
                "No AWS region is configured explicitly; the AWS SDK default will be used.",
                field,
            )
        )

    explicit_credentials = bool(
        (os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"))
        or os.environ.get("AWS_PROFILE")
    )
    try:
        credentials = resolved_session.get_credentials()
        if credentials is not None:
            credentials.get_frozen_credentials()
            expiry = getattr(credentials, "_expiry_time", None)
            if isinstance(expiry, datetime) and expiry.astimezone(UTC) <= datetime.now(UTC):
                raise ValueError("The configured AWS session has expired.")
    except Exception as exc:
        issues.append(
            PrecheckIssue(
                "error",
                "aws_credentials_expired_or_unavailable",
                f"AWS credentials could not be loaded: {exc}",
                field,
            )
        )
        return

    if credentials is None:
        issues.append(
            PrecheckIssue(
                "error" if explicit_credentials else "warning",
                "aws_credentials_not_found",
                "AWS credentials were not found in the normal SDK credential chain.",
                field,
            )
        )


def _token_cost(tokens: int, rate: float | None) -> float | None:
    return None if rate is None else tokens * rate / 1_000_000


def _complete_sum(values: list[float | None]) -> float | None:
    if any(value is None for value in values):
        return None
    return sum(value for value in values if value is not None)


def _combined_cost(input_cost: float | None, output_cost: float | None) -> float | None:
    if input_cost is None or output_cost is None:
        return None
    return input_cost + output_cost


__all__ = [
    "BackendCostEstimate",
    "CostEstimate",
    "PrecheckIssue",
    "PrecheckResult",
    "estimate_cost",
    "precheck_config",
]
