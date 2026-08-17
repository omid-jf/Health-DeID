from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

import health_deid.backends.bedrock as safeguard_module
from health_deid.backends.bedrock import (
    DEFAULT_MODEL_ID,
    DEIDENTIFICATION_POLICY,
    SAFEGUARD_POLICY_SHA256,
    SAFEGUARD_SCHEMA,
    SAFEGUARD_SCHEMA_JSON,
    SAFEGUARD_SCHEMA_SHA256,
    AwsBedrockSafeguardValidator,
    _estimate_cost,
    _extract_response_text,
    _nonnegative_float,
    _nonnegative_int,
    _optional_text,
    _parse_json_object,
)
from health_deid.backends.runtime import BackendExecutionError
from health_deid.core.taxonomy import LLM_PHI_CATEGORIES, PhiCategory


class FakeBedrockClient:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.response


def _finding(
    category: object,
    *,
    evidence: object = "Jane",
    rationale: object = "Residual identifier",
    rule_ids: object = ("SH-NAME",),
    confidence: object = "high",
) -> dict[str, object]:
    return {
        "category": category,
        "evidence": evidence,
        "rationale": rationale,
        "rule_ids": list(rule_ids) if isinstance(rule_ids, tuple) else rule_ids,
        "confidence": confidence,
    }


def _response(
    payload: object,
    *,
    stop_reason: object = "end_turn",
    usage: object | None = None,
    metrics: object | None = None,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "output": {"message": {"content": [{"text": json.dumps(payload)}]}},
        "stopReason": stop_reason,
    }
    if usage is not None:
        response["usage"] = usage
    if metrics is not None:
        response["metrics"] = metrics
    return response


def test_safeguard_uses_strict_request_and_returns_exhaustive_findings_with_cost() -> None:
    original = "Jane was seen on 03/14/2024."
    validation = "Jane was seen on [R_DATE]."
    payload = {
        "rationale": "Two residual categories checked.",
        "findings": [
            _finding("NAME", evidence="Jane"),
            _finding(
                "ID",
                evidence="MRN 123",
                rationale="Residual record number",
                rule_ids=("SH-ID",),
                confidence="medium",
            ),
        ],
    }
    response = _response(
        payload,
        usage={"inputTokens": 100, "outputTokens": 50, "totalTokens": 150},
        metrics={"latencyMs": 12.5},
    )
    client = FakeBedrockClient(response)
    validator = AwsBedrockSafeguardValidator(
        max_output_tokens=777,
        input_cost_per_million_tokens=2.0,
        output_cost_per_million_tokens=4.0,
        client=client,
    )

    result = validator.validate(
        original_text=original,
        deidentified_text=validation,
    )

    assert [item.category for item in result.findings] == [PhiCategory.NAME, PhiCategory.ID]
    assert all(item.source == DEFAULT_MODEL_ID for item in result.findings)
    assert result.rationale == "Two residual categories checked."
    assert result.raw_violation is True
    assert result.effective_violation is True
    assert result.stop_reason == "end_turn"
    assert result.raw_output == response
    payload_text = json.dumps(
        {
            "ORIGINAL_TEXT": original,
            "DEIDENTIFIED_TEXT": validation,
        },
        ensure_ascii=False,
    )
    assert result.usage.input_chars == len(payload_text)
    assert result.usage.input_bytes == len(payload_text.encode())
    assert (result.usage.input_tokens, result.usage.output_tokens, result.usage.total_tokens) == (
        100,
        50,
        150,
    )
    assert result.usage.latency_ms == 12.5
    assert result.usage.cost_usd == pytest.approx(0.0004)

    assert client.calls == [
        {
            "modelId": DEFAULT_MODEL_ID,
            "system": [{"text": DEIDENTIFICATION_POLICY}],
            "messages": [{"role": "user", "content": [{"text": payload_text}]}],
            "inferenceConfig": {"maxTokens": 777, "temperature": 0.0},
            "outputConfig": {
                "textFormat": {
                    "type": "json_schema",
                    "structure": {
                        "jsonSchema": {
                            "schema": SAFEGUARD_SCHEMA_JSON,
                            "name": "deidentification_audit",
                            "description": "Exhaustive residual PHI findings",
                        }
                    },
                }
            },
        }
    ]


def test_safeguard_policy_schema_and_hashes_are_stable_and_complete() -> None:
    assert (
        SAFEGUARD_POLICY_SHA256
        == hashlib.sha256(DEIDENTIFICATION_POLICY.encode("utf-8")).hexdigest()
    )
    assert SAFEGUARD_SCHEMA_JSON == json.dumps(
        SAFEGUARD_SCHEMA,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert (
        SAFEGUARD_SCHEMA_SHA256 == hashlib.sha256(SAFEGUARD_SCHEMA_JSON.encode("utf-8")).hexdigest()
    )
    category_schema = SAFEGUARD_SCHEMA["properties"]["findings"]["items"]["properties"]["category"]
    assert category_schema["enum"] == [category.value for category in LLM_PHI_CATEGORIES]
    assert SAFEGUARD_SCHEMA["required"] == ["rationale", "findings"]
    assert SAFEGUARD_SCHEMA["additionalProperties"] is False


def test_safeguard_default_client_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    client = FakeBedrockClient(_response({"rationale": "No PHI.", "findings": []}))

    def fake_client(service: str, **kwargs: Any) -> FakeBedrockClient:
        captured["service"] = service
        captured.update(kwargs)
        return client

    monkeypatch.setattr(safeguard_module.boto3, "client", fake_client)
    validator = AwsBedrockSafeguardValidator(region_name="us-west-2")

    assert validator.model_id == DEFAULT_MODEL_ID
    assert validator.max_output_tokens == 4_096
    assert validator.input_cost_per_million_tokens is None
    assert validator.output_cost_per_million_tokens is None
    assert captured["service"] == "bedrock-runtime"
    assert captured["region_name"] == "us-west-2"
    config = captured["config"]
    assert config.connect_timeout == 10.0
    assert config.read_timeout == 300.0
    assert config.retries["max_attempts"] == 3
    assert config.retries["mode"] == "standard"


@pytest.mark.parametrize("stop_reason", ["max_tokens", "maxTokens", "length"])
def test_safeguard_marks_length_stops_as_truncated(stop_reason: str) -> None:
    response = _response(
        {"rationale": "partial", "findings": []},
        stop_reason=stop_reason,
    )
    validator = AwsBedrockSafeguardValidator(client=FakeBedrockClient(response))

    with pytest.raises(BackendExecutionError) as raised:
        validator.validate(original_text="original", deidentified_text="redacted")

    assert raised.value.code == "truncated_output"
    assert raised.value.retryable is True
    assert raised.value.truncated is True
    assert raised.value.raw_response == response


def test_safeguard_empty_findings_and_invalid_usage_defaults() -> None:
    response = _response(
        {"rationale": "No residual PHI.", "findings": []},
        stop_reason=1,
        usage={"inputTokens": True, "outputTokens": -1, "totalTokens": "bad"},
        metrics={"latencyMs": -1},
    )
    client = FakeBedrockClient(response)
    result = AwsBedrockSafeguardValidator(client=client).validate(
        original_text="é",
        deidentified_text="x",
    )

    assert result.findings == []
    assert result.raw_violation is False
    assert result.effective_violation is False
    assert result.stop_reason is None
    request_text = client.calls[0]["messages"][0]["content"][0]["text"]
    assert result.usage.input_bytes == len(request_text.encode("utf-8"))
    assert result.usage.input_tokens == 0
    assert result.usage.output_tokens == 0
    assert result.usage.total_tokens == 0
    assert result.usage.latency_ms >= 0
    assert result.usage.cost_usd is None


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, "must contain rationale and findings"),
        ({"rationale": 1, "findings": []}, "must contain rationale and findings"),
        ({"rationale": "ok", "findings": {}}, "must contain rationale and findings"),
        (
            {"rationale": "ok", "findings": ["bad"]},
            "must be an object",
        ),
        (
            {"rationale": "ok", "findings": [_finding(1)]},
            "category must be a string",
        ),
        (
            {"rationale": "ok", "findings": [_finding("FUTURE")]},
            "FUTURE",
        ),
        (
            {"rationale": "ok", "findings": [_finding("NAME", confidence="certain")]},
            "confidence",
        ),
        (
            {"rationale": "ok", "findings": [_finding("NAME", rationale=" ")]},
            "cannot be empty",
        ),
    ],
)
def test_safeguard_rejects_incomplete_or_malformed_findings(
    payload: dict[str, object],
    message: str,
) -> None:
    response = _response(payload)
    validator = AwsBedrockSafeguardValidator(client=FakeBedrockClient(response))

    with pytest.raises(BackendExecutionError, match=message) as caught:
        validator.validate(original_text="original", deidentified_text="redacted")
    assert caught.value.code == "invalid_structured_output"
    assert caught.value.raw_response == response


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({}, "does not contain message content"),
        ({"output": None}, "does not contain message content"),
        ({"output": {"message": {"content": []}}}, "contains no text"),
        (
            {"output": {"message": {"content": [{"not_text": "ignored"}]}}},
            "contains no text",
        ),
    ],
)
def test_extract_safeguard_response_text_rejects_missing_content(
    response: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _extract_response_text(response)


def test_extract_safeguard_response_text_joins_text_parts() -> None:
    response = {
        "output": {
            "message": {
                "content": [
                    {"text": " first "},
                    {"ignored": "value"},
                    {"text": " second "},
                ]
            }
        }
    }

    assert _extract_response_text(response) == "first \n second"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("not json", "not valid JSON"),
        ("[]", "must be a JSON object"),
    ],
)
def test_parse_safeguard_response_requires_a_json_object(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _parse_json_object(text)


def test_safeguard_numeric_helpers_and_cost_defaults() -> None:
    assert _nonnegative_int(2) == 2
    assert _nonnegative_int(True, default=7) == 7
    assert _nonnegative_int(-1, default=7) == 7
    assert _nonnegative_float(2, default=7.0) == 2.0
    assert _nonnegative_float(2.5, default=7.0) == 2.5
    assert _nonnegative_float(True, default=7.0) == 7.0
    assert _nonnegative_float(-1, default=7.0) == 7.0
    assert _optional_text("stop") == "stop"
    assert _optional_text("") is None
    assert _optional_text(1) is None
    assert _estimate_cost(10, 5, None, 2.0) is None
    assert _estimate_cost(10, 5, 2.0, None) is None
    assert _estimate_cost(10, 5, 2.0, 4.0) == pytest.approx(0.00004)
