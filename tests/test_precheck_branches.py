from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl
import pytest

from health_deid.core.secret_refs import MappingSecretResolver
from health_deid.models.config import (
    PipelineConfig,
    ReviewConfig,
    ValidationConfig,
)
from health_deid.pipeline.precheck import PrecheckIssue, precheck_config


class _Credentials:
    def get_frozen_credentials(self) -> object:
        return object()


class _AwsSession:
    def __init__(self, *, region_name: str | None, credentials: object | None) -> None:
        self.region_name = region_name
        self._credentials = credentials

    def get_credentials(self) -> object | None:
        return self._credentials


class _BrokenCredentials:
    def get_frozen_credentials(self) -> object:
        raise RuntimeError("credential refresh failed")


class _ExpiringCredentials(_Credentials):
    def __init__(self, expiry: datetime) -> None:
        self._expiry_time = expiry


def _source(tmp_path: Path, *, include_entity: bool = True) -> Path:
    path = tmp_path / "records.jsonl"
    entity = ',"patient_id":"P1"' if include_entity else ""
    path.write_text(
        f'{{"record_id":"R1","text":"Example"{entity}}}\n',
        encoding="utf-8",
    )
    return path


def _config(path: Path, *, entity_column: bool = False, **updates: object) -> PipelineConfig:
    payload: dict[str, object] = {
        "run": {"output_dir": path.parent / "runs"},
        "input": {
            "path": path,
            "format": "jsonl",
            "record_id_column": "record_id",
            "entity_id": (
                {"source": "column", "column": "patient_id"}
                if entity_column
                else {"source": "record_id"}
            ),
            "text_column": "text",
        },
        "detection": {"enabled": False},
    }
    payload.update(updates)
    return PipelineConfig.model_validate(payload)


def test_precheck_ready_path_and_issue_helpers(tmp_path: Path) -> None:
    result = precheck_config(_config(_source(tmp_path), entity_column=True))

    assert result.ok
    assert result.errors == ()
    assert result.warnings == ()
    assert result.issues == (
        PrecheckIssue(
            "info",
            "ready",
            "Configuration is ready. No backend request was made during precheck.",
        ),
    )
    assert result.issues[0].as_dict()["field"] is None


def test_precheck_reports_missing_columns_and_empty_input(tmp_path: Path) -> None:
    missing = _config(_source(tmp_path, include_entity=False), entity_column=True)
    missing_result = precheck_config(missing)
    assert [issue.code for issue in missing_result.errors] == ["input_columns_missing"]
    assert "patient_id" in missing_result.errors[0].message

    empty_path = tmp_path / "empty.parquet"
    pl.DataFrame(schema={"record_id": pl.String, "text": pl.String}).write_parquet(empty_path)
    empty = PipelineConfig.model_validate(
        {
            "input": {
                "path": empty_path,
                "format": "parquet",
                "record_id_column": "record_id",
                "entity_id": {"source": "record_id"},
                "text_column": "text",
            },
            "detection": {"enabled": False},
        }
    )
    empty_result = precheck_config(empty)
    assert "input_empty" in {issue.code for issue in empty_result.errors}


def test_precheck_aws_warnings_and_configured_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    for name in (
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_PROFILE",
    ):
        monkeypatch.delenv(name, raising=False)
    config = _config(
        source,
        entity_column=True,
        detection={
            "enabled": True,
            "detectors": [{"backend": "aws_comprehend_medical"}],
        },
        validation={"enabled": True},
        review={"enabled": True},
    )

    warned = precheck_config(
        config,
        aws_session=_AwsSession(region_name=None, credentials=None),
    )

    assert {issue.code for issue in warned.warnings} == {
        "aws_region_not_verified",
        "aws_credentials_not_found",
    }
    assert len(warned.warnings) == 4

    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    configured = precheck_config(
        config,
        aws_session=_AwsSession(region_name="us-east-1", credentials=_Credentials()),
    )
    assert configured.warnings == ()
    assert configured.issues[0].code == "ready"


def test_precheck_reports_session_load_refresh_and_expiry_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(
        _source(tmp_path),
        detection={
            "enabled": True,
            "detectors": [{"backend": "aws_comprehend_medical"}],
        },
    )

    def fail_session() -> object:
        raise RuntimeError("profile configuration is invalid")

    monkeypatch.setattr("health_deid.pipeline.precheck.boto3.Session", fail_session)
    unavailable = precheck_config(config)
    assert {issue.code for issue in unavailable.errors} == {
        "aws_credentials_expired_or_unavailable"
    }
    assert "profile configuration is invalid" in unavailable.errors[0].message

    refresh_failure = precheck_config(
        config,
        aws_session=_AwsSession(region_name="us-east-1", credentials=_BrokenCredentials()),
    )
    assert refresh_failure.errors[0].code == "aws_credentials_expired_or_unavailable"
    assert "credential refresh failed" in refresh_failure.errors[0].message

    expired = precheck_config(
        config,
        aws_session=_AwsSession(
            region_name="us-east-1",
            credentials=_ExpiringCredentials(datetime.now(UTC) - timedelta(minutes=1)),
        ),
    )
    assert expired.errors[0].code == "aws_credentials_expired_or_unavailable"
    assert "session has expired" in expired.errors[0].message


def test_precheck_bedrock_and_profile_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_PROFILE", "research")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    config = _config(
        _source(tmp_path),
        entity_column=True,
        detection={
            "enabled": True,
            "detectors": [
                {
                    "backend": "aws_bedrock",
                    "model_id": "us.anthropic.claude-sonnet-4-6",
                    "region_name": "us-west-2",
                },
            ],
        },
    )

    result = precheck_config(
        config,
        aws_session=_AwsSession(region_name="us-west-2", credentials=_Credentials()),
    )

    assert result.ok
    assert result.warnings == ()


def test_precheck_rules_paths(tmp_path: Path) -> None:
    source = _source(tmp_path)
    missing = _config(
        source,
        entity_column=True,
        rules={"enabled": True, "rules_path": tmp_path / "missing.yaml"},
    )
    assert [issue.code for issue in precheck_config(missing).errors] == ["rules_file_unreadable"]

    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text("rules: []\n", encoding="utf-8")
    valid = _config(
        source,
        entity_column=True,
        rules={"enabled": True, "rules_path": rules_path},
    )
    assert precheck_config(valid).ok


def test_precheck_secret_and_generator_checks(tmp_path: Path) -> None:
    source = _source(tmp_path)
    raw = _config(source, entity_column=True).model_dump(mode="json")
    raw["policy"]["categories"]["DATE"] = {
        "action": "surrogate",
        "surrogate": {
            "method": "date_shift",
            "consistency": "entity",
            "secret_reference": "DATE_SHIFT_SECRET",
        },
    }
    raw["policy"]["categories"]["NAME"] = {
        "action": "surrogate",
        "surrogate": {
            "method": "custom_list",
            "values": ["Alex Example"],
            "secret_reference": "NAME_SECRET",
        },
    }
    config = PipelineConfig.model_validate(raw)

    missing_secret = precheck_config(
        config,
        secret_resolver=MappingSecretResolver({"DATE_SHIFT_SECRET": "shift-key"}),
    )
    assert {issue.code for issue in missing_secret.issues} == {
        "custom_list_capacity_runtime_check",
        "secret_unavailable",
    }

    ready = precheck_config(
        config,
        secret_resolver=MappingSecretResolver(
            {"DATE_SHIFT_SECRET": "shift-key", "NAME_SECRET": "name-key"}
        ),
    )
    assert ready.ok
    assert [issue.code for issue in ready.warnings] == ["custom_list_capacity_runtime_check"]


def test_precheck_defensively_rejects_review_without_validation(tmp_path: Path) -> None:
    config = _config(_source(tmp_path), entity_column=True)
    broken = config.model_copy(
        update={"review": ReviewConfig(enabled=True), "validation": ValidationConfig(enabled=False)}
    )

    result = precheck_config(broken)

    assert [issue.code for issue in result.errors] == ["review_scope_requires_validation"]

    missing_review = config.model_copy(
        update={"validation": ValidationConfig(enabled=True), "review": ReviewConfig(enabled=False)}
    )
    missing_review_result = precheck_config(
        missing_review,
        aws_session=_AwsSession(region_name="us-east-1", credentials=_Credentials()),
    )
    assert [issue.code for issue in missing_review_result.errors] == ["validator_requires_review"]

    valid = config.model_copy(
        update={
            "review": ReviewConfig(enabled=True, review_scope="all"),
            "validation": ValidationConfig(enabled=False),
        }
    )
    assert precheck_config(valid).ok
