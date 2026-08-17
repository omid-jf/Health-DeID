from __future__ import annotations

from typing import Any

import pytest

import health_deid.backends.comprehend as aws_module
from health_deid.backends.comprehend import AwsComprehendMedicalPhiDetector
from health_deid.backends.contracts import PhiDetector
from health_deid.backends.runtime import BackendExecutionError
from health_deid.models.backend import DetectionResult


class FakeAwsClient:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.requests: list[str] = []

    def detect_phi(self, *, Text: str) -> dict[str, Any]:
        self.requests.append(Text)
        return self.response


def _entity(
    entity_id: int,
    text: str,
    start: int,
    native_type: str,
    score: object = 0.99,
) -> dict[str, Any]:
    return {
        "Id": entity_id,
        "BeginOffset": start,
        "EndOffset": start + len(text),
        "Score": score,
        "Text": text,
        "Type": native_type,
    }


def test_aws_detector_preserves_all_native_findings_and_usage() -> None:
    text = "John Smith in Houston; 555-123-4567"
    response = {
        "ModelVersion": "cm-phi-1",
        "Entities": [
            _entity(0, "John Smith", 0, "NAME"),
            _entity(1, "Houston", 14, "ADDRESS", 0.50),
            _entity(2, "555-123-4567", 23, "PHONE_OR_FAX", None),
            _entity(3, "John", 0, "NEW_BACKEND_TYPE", 1),
        ],
    }
    client = FakeAwsClient(response)

    result = AwsComprehendMedicalPhiDetector(client=client).detect(text)

    assert client.requests == [text]
    assert [item.category.value for item in result.candidates] == [
        "NAME",
        "LOCATION",
        "PHONE_OR_FAX",
        "UNMAPPED",
    ]
    assert result.candidates[1].confidence == 0.5
    assert result.candidates[2].confidence is None
    assert result.candidates[3].native_category == "NEW_BACKEND_TYPE"
    assert result.candidates[0].native_payload["Id"] == 0
    assert result.model_version == "cm-phi-1"
    assert result.raw_output == response
    assert result.usage.request_count == 1
    assert result.usage.input_chars == len(text)
    assert result.usage.input_bytes == len(text.encode())
    assert result.usage.latency_ms >= 0


def test_aws_detector_rejects_empty_text_and_unfollowable_pagination() -> None:
    detector = AwsComprehendMedicalPhiDetector(client=FakeAwsClient({"Entities": []}))
    with pytest.raises(ValueError, match="non-empty"):
        detector.detect("")

    response = {"Entities": [], "PaginationToken": "next"}
    detector = AwsComprehendMedicalPhiDetector(client=FakeAwsClient(response))
    with pytest.raises(BackendExecutionError, match="continuation") as caught:
        detector.detect("note")
    assert caught.value.truncated
    assert not caught.value.retryable
    assert caught.value.raw_response == response


@pytest.mark.parametrize(
    "entity",
    [
        "bad",
        {"Type": "", "BeginOffset": 0, "EndOffset": 1, "Text": "x"},
        {"Type": "NAME", "BeginOffset": True, "EndOffset": 1, "Text": "x"},
        {"Type": "NAME", "BeginOffset": 0, "EndOffset": 2, "Text": "x"},
        {"Type": "NAME", "BeginOffset": 0, "EndOffset": 1, "Text": "y"},
    ],
)
def test_aws_detector_rejects_malformed_entities(entity: object) -> None:
    response = {"Entities": [entity]}
    detector = AwsComprehendMedicalPhiDetector(client=FakeAwsClient(response))
    with pytest.raises(BackendExecutionError, match="entity|offsets") as caught:
        detector.detect("x")
    assert caught.value.code == "invalid_backend_response"
    assert caught.value.raw_response == response


def test_aws_detector_uses_standard_sdk_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    fake = FakeAwsClient({"Entities": []})

    def client(service: str, **kwargs: object) -> FakeAwsClient:
        captured.update(service=service, **kwargs)
        return fake

    monkeypatch.setattr(aws_module.boto3, "client", client)
    detector = AwsComprehendMedicalPhiDetector(
        region_name="us-east-1",
        connect_timeout_seconds=3,
        read_timeout_seconds=9,
    )
    assert detector.detect("x").candidates == []
    assert captured["service"] == "comprehendmedical"
    assert captured["region_name"] == "us-east-1"
    config = captured["config"]
    assert config.retries["max_attempts"] == 3
    assert config.retries["mode"] == "standard"


def test_phi_detector_contract_is_abstract() -> None:
    class ConcreteDetector(PhiDetector):
        def detect(self, text: str) -> DetectionResult:
            return super().detect(text)

    with pytest.raises(NotImplementedError):
        ConcreteDetector().detect("text")
