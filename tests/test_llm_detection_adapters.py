from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

import health_deid.backends.bedrock as llm_module
from health_deid.backends.bedrock import (
    LLM_DETECTION_PROMPT_SHA256,
    LLM_DETECTION_SCHEMA,
    LLM_DETECTION_SCHEMA_JSON,
    LLM_DETECTION_SCHEMA_SHA256,
    LLM_DETECTION_SYSTEM_PROMPT,
    AwsBedrockLlmPhiDetector,
    _align_llm_finding,
    _extract_response_text,
    _nonnegative_int,
    _optional_text,
    _parse_response_text,
    parse_llm_findings,
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
    category: str,
    text: str,
    start: int,
    end: int,
    *,
    subtype: str | None = None,
    confidence: float | None = None,
    source_group_id: str | None = None,
) -> dict[str, Any]:
    return {
        "category": category,
        "subtype": subtype,
        "text": text,
        "start_char": start,
        "end_char": end,
        "confidence": confidence,
        "source_group_id": source_group_id,
    }


def _response(
    payload: object,
    *,
    stop_reason: object = "end_turn",
    usage: object | None = None,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "output": {"message": {"content": [{"text": json.dumps(payload)}]}},
        "stopReason": stop_reason,
    }
    if usage is not None:
        response["usage"] = usage
    return response


def test_bedrock_detector_uses_fixed_strict_request_and_returns_all_findings() -> None:
    source = "Dr. Jane on 03/14/2024"
    payload = {
        "findings": [
            _finding("NAME", "Dr. Jane", 0, 8, confidence=0.97, source_group_id="p1"),
            _finding("DATE", "03/14/2024", 12, 22, confidence=0.91),
        ]
    }
    response = _response(
        payload,
        usage={"inputTokens": 17, "outputTokens": 11, "totalTokens": 28},
    )
    client = FakeBedrockClient(response)
    detector = AwsBedrockLlmPhiDetector(
        model_id="model-1",
        max_output_tokens=321,
        client=client,
    )

    result = detector.detect(source)

    assert [(item.category, item.text) for item in result.candidates] == [
        (PhiCategory.NAME, "Dr. Jane"),
        (PhiCategory.DATE, "03/14/2024"),
    ]
    assert result.candidates[0].backend_span_id == "0"
    assert result.candidates[0].native_payload == payload["findings"][0]
    assert result.raw_output == response
    assert result.model_version == "model-1"
    assert result.stop_reason == "end_turn"
    assert result.usage.input_chars == len(source)
    assert result.usage.input_bytes == len(source.encode("utf-8"))
    assert (result.usage.input_tokens, result.usage.output_tokens, result.usage.total_tokens) == (
        17,
        11,
        28,
    )
    assert result.usage.latency_ms >= 0

    assert len(client.calls) == 1
    request = client.calls[0]
    assert request == {
        "modelId": "model-1",
        "system": [{"text": LLM_DETECTION_SYSTEM_PROMPT}],
        "messages": [
            {
                "role": "user",
                "content": [{"text": json.dumps({"clinical_text": source}, ensure_ascii=False)}],
            }
        ],
        "inferenceConfig": {"maxTokens": 321, "temperature": 0.0},
        "outputConfig": {
            "textFormat": {
                "type": "json_schema",
                "structure": {
                    "jsonSchema": {
                        "schema": LLM_DETECTION_SCHEMA_JSON,
                        "name": "phi_findings",
                        "description": "Exact PHI spans in clinical text",
                    }
                },
            }
        },
    }


def test_detector_prompt_and_schema_hashes_are_stable_and_complete() -> None:
    assert (
        LLM_DETECTION_PROMPT_SHA256
        == hashlib.sha256(LLM_DETECTION_SYSTEM_PROMPT.encode("utf-8")).hexdigest()
    )
    assert LLM_DETECTION_SCHEMA_JSON == json.dumps(
        LLM_DETECTION_SCHEMA,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert (
        LLM_DETECTION_SCHEMA_SHA256
        == hashlib.sha256(LLM_DETECTION_SCHEMA_JSON.encode("utf-8")).hexdigest()
    )
    category_schema = LLM_DETECTION_SCHEMA["properties"]["findings"]["items"]["properties"][
        "category"
    ]
    assert category_schema["enum"] == [category.value for category in LLM_PHI_CATEGORIES]
    assert PhiCategory.UNMAPPED.value not in category_schema["enum"]
    assert LLM_DETECTION_SCHEMA["additionalProperties"] is False
    assert LLM_DETECTION_SCHEMA["properties"]["findings"]["items"]["additionalProperties"] is False


def test_bedrock_detector_default_client_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    client = FakeBedrockClient(_response({"findings": []}))

    def fake_client(service: str, **kwargs: Any) -> FakeBedrockClient:
        captured["service"] = service
        captured.update(kwargs)
        return client

    monkeypatch.setattr(llm_module.boto3, "client", fake_client)
    detector = AwsBedrockLlmPhiDetector(model_id="model-defaults", region_name="us-east-2")

    assert detector.max_output_tokens == 8_192
    assert captured["service"] == "bedrock-runtime"
    assert captured["region_name"] == "us-east-2"
    config = captured["config"]
    assert config.connect_timeout == 10.0
    assert config.read_timeout == 300.0
    assert config.retries["max_attempts"] == 3
    assert config.retries["mode"] == "standard"

    with pytest.raises(ValueError, match="cannot be blank"):
        AwsBedrockLlmPhiDetector(model_id=" ", client=client)


@pytest.mark.parametrize("stop_reason", ["max_tokens", "maxTokens", "length"])
def test_bedrock_detector_marks_only_length_stops_as_truncated(stop_reason: str) -> None:
    response = _response({"findings": []}, stop_reason=stop_reason)

    with pytest.raises(BackendExecutionError) as raised:
        AwsBedrockLlmPhiDetector(model_id="model", client=FakeBedrockClient(response)).detect(
            "text"
        )

    assert raised.value.code == "truncated_output"
    assert raised.value.retryable is True
    assert raised.value.truncated is True
    assert raised.value.raw_response == response


def test_bedrock_detector_sanitizes_invalid_usage_values_and_stop_reason() -> None:
    response = _response(
        {"findings": []},
        stop_reason=123,
        usage={"inputTokens": True, "outputTokens": -1, "totalTokens": "bad"},
    )

    result = AwsBedrockLlmPhiDetector(
        model_id="model",
        client=FakeBedrockClient(response),
    ).detect("é")

    assert result.stop_reason is None
    assert result.usage.input_bytes == 2
    assert result.usage.input_tokens == 0
    assert result.usage.output_tokens == 0
    assert result.usage.total_tokens == 0


@pytest.mark.parametrize("effort", ["low", "medium", "high"])
def test_bedrock_detector_uses_sonnet_adaptive_reasoning(effort: str) -> None:
    client = FakeBedrockClient(_response({"findings": []}))
    detector = AwsBedrockLlmPhiDetector(
        model_id="model",
        reasoning_effort=effort,  # type: ignore[arg-type]
        input_cost_per_million_tokens=3.0,
        output_cost_per_million_tokens=15.0,
        client=client,
    )

    result = detector.detect("text")

    request = client.calls[0]
    assert request["inferenceConfig"] == {"maxTokens": 8192}
    assert request["additionalModelRequestFields"] == {
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": effort},
    }
    assert result.usage.input_cost_usd == 0.0
    assert result.usage.output_cost_usd == 0.0


def test_bedrock_detector_retains_raw_invalid_structured_output() -> None:
    response = _response({"findings": "not-an-array"})

    with pytest.raises(BackendExecutionError, match="must be a list") as caught:
        AwsBedrockLlmPhiDetector(
            model_id="model",
            client=FakeBedrockClient(response),
        ).detect("text")

    assert caught.value.code == "invalid_structured_output"
    assert caught.value.raw_response == response


def test_bedrock_detector_keeps_valid_findings_when_one_item_is_unusable() -> None:
    payload = {
        "findings": [
            _finding("DATE", "", 0, 0),
            _finding("NAME", "Jane", 0, 4),
        ]
    }
    response = _response(payload)

    result = AwsBedrockLlmPhiDetector(
        model_id="model",
        client=FakeBedrockClient(response),
    ).detect("Jane")

    assert [candidate.text for candidate in result.candidates] == ["Jane"]
    assert result.raw_output == response


@pytest.mark.parametrize(
    ("payload", "source", "error_type", "message"),
    [
        ({}, "Jane", ValueError, "findings must be a list"),
        ({"findings": "bad"}, "Jane", ValueError, "findings must be a list"),
        ({"findings": ["bad"]}, "Jane", ValueError, "must be an object"),
        ({"findings": [{"category": 1}]}, "Jane", ValueError, "must be a string"),
        (
            {"findings": [_finding("FUTURE", "Jane", 0, 4)]},
            "Jane",
            ValueError,
            "FUTURE",
        ),
        (
            {"findings": [_finding("NAME", "Joan", 0, 4)]},
            "Jane",
            ValueError,
            "does not occur",
        ),
        (
            {"findings": [_finding("NAME", "", 2, 2)]},
            "Jane",
            ValueError,
            "positive source span",
        ),
    ],
)
def test_parse_llm_findings_rejects_malformed_or_unaligned_spans(
    payload: dict[str, Any],
    source: str,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        parse_llm_findings(payload, source_text=source)


def test_parse_llm_findings_repairs_bedrock_character_counting_errors() -> None:
    source = "Patient Jane Doe was seen at Northstar Medical Center on 01/15/2024."
    payload = {
        "findings": [
            _finding("NAME", "Jane Doe", 8, 15),
            _finding("LOCATION", "Northstar Medical Center", 48, 72),
            _finding("DATE", "01/15/2024", 80, 90),
        ]
    }

    candidates = parse_llm_findings(payload, source_text=source)

    assert [(item.text, item.start_char, item.end_char) for item in candidates] == [
        ("Jane Doe", 8, 16),
        ("Northstar Medical Center", 29, 53),
        ("01/15/2024", 57, 67),
    ]
    assert candidates[1].native_payload == payload["findings"][1]


def test_parse_llm_findings_repairs_empty_text_and_nonpositive_offsets() -> None:
    source = "Jane met Mark"
    payload = {
        "findings": [
            _finding("NAME", "Jane", 0, 0),
            _finding("NAME", "", 9, 13),
        ]
    }

    candidates = parse_llm_findings(payload, source_text=source)

    assert [(item.text, item.start_char, item.end_char) for item in candidates] == [
        ("Jane", 0, 4),
        ("Mark", 9, 13),
    ]
    assert candidates[1].native_payload == payload["findings"][1]


def test_parse_llm_findings_ignores_one_unusable_item_but_keeps_its_raw_index() -> None:
    payload = {
        "findings": [
            _finding("DATE", "", 0, 0),
            _finding("NAME", "Jane", 0, 4),
        ]
    }

    candidates = parse_llm_findings(payload, source_text="Jane")

    assert len(candidates) == 1
    assert candidates[0].text == "Jane"
    assert candidates[0].backend_span_id == "1"


def test_llm_alignment_uses_end_boundary_then_nearest_reported_occurrence() -> None:
    source = "Jane met Jane"

    assert _align_llm_finding(
        source_text=source,
        finding_text="Jane",
        reported_start=8,
        reported_end=13,
    ) == (9, 13)
    assert _align_llm_finding(
        source_text=source,
        finding_text="Jane",
        reported_start=7,
        reported_end=11,
    ) == (9, 13)


@pytest.mark.parametrize(
    ("finding_text", "start", "end", "message"),
    [
        ("", 2, 2, "positive source span"),
        (None, -1, 1, "positive source span"),
        ("Jane", True, 4, "must be an integer"),
        ("Jane", 0, False, "must be an integer"),
        ("Jane", "0", 4, "must be an integer"),
        ("Jane", 0, "4", "must be an integer"),
    ],
)
def test_llm_alignment_rejects_invalid_raw_fields(
    finding_text: object,
    start: object,
    end: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _align_llm_finding(
            source_text="Jane",
            finding_text=finding_text,
            reported_start=start,
            reported_end=end,
        )


def test_llm_alignment_rejects_equidistant_repeated_text() -> None:
    with pytest.raises(ValueError, match="unambiguously"):
        _align_llm_finding(
            source_text="Jane Jane",
            finding_text="Jane",
            reported_start=2,
            reported_end=7,
        )


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
def test_extract_detector_response_text_rejects_missing_content(
    response: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _extract_response_text(response)


def test_extract_detector_response_text_joins_text_parts() -> None:
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
def test_parse_detector_response_text_requires_a_json_object(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _parse_response_text(text)


def test_detector_small_value_helpers_reject_bool_negative_and_empty_text() -> None:
    assert _nonnegative_int(2) == 2
    assert _nonnegative_int(True, default=7) == 7
    assert _nonnegative_int(-1, default=7) == 7
    assert _optional_text("stop") == "stop"
    assert _optional_text("") is None
    assert _optional_text(1) is None
