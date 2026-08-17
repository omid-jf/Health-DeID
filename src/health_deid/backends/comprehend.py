from __future__ import annotations

import json
from math import ceil
from time import perf_counter
from typing import Any, cast

import boto3
from botocore.config import Config
from pydantic import JsonValue

from health_deid.backends.contracts import PhiDetector
from health_deid.backends.runtime import AWS_MAX_RETRIES, AWS_RETRY_MODE, BackendExecutionError
from health_deid.core.taxonomy import map_aws_phi_type
from health_deid.models.backend import BackendUsage, DetectionCandidate, DetectionResult


class AwsComprehendMedicalPhiDetector(PhiDetector):
    def __init__(
        self,
        *,
        region_name: str | None = None,
        connect_timeout_seconds: float = 10.0,
        read_timeout_seconds: float = 120.0,
        cost_per_100_characters_usd: float | None = None,
        client: Any | None = None,
    ) -> None:
        self.cost_per_100_characters_usd = cost_per_100_characters_usd
        self.client = client or boto3.client(
            "comprehendmedical",
            region_name=region_name,
            config=Config(
                connect_timeout=connect_timeout_seconds,
                read_timeout=read_timeout_seconds,
                retries=cast(
                    Any,
                    {"mode": AWS_RETRY_MODE, "max_attempts": AWS_MAX_RETRIES},
                ),
            ),
        )

    def detect(self, text: str) -> DetectionResult:
        if not text:
            raise ValueError("AWS DetectPHI requires non-empty text.")
        started = perf_counter()
        response: dict[str, Any] = dict(self.client.detect_phi(Text=text))
        latency_ms = (perf_counter() - started) * 1_000
        if response.get("PaginationToken"):
            raise BackendExecutionError(
                code="pagination_token_unsupported",
                message=(
                    "DetectPHI returned PaginationToken, but the current request API has no "
                    "continuation parameter. The chunk cannot be marked complete."
                ),
                retryable=False,
                truncated=True,
                raw_response=response,
            )
        try:
            candidates: list[DetectionCandidate] = []
            for entity in response.get("Entities") or []:
                if not isinstance(entity, dict):
                    raise ValueError("Every AWS DetectPHI entity must be an object.")
                native_category = entity.get("Type")
                if not isinstance(native_category, str) or not native_category:
                    raise ValueError("AWS DetectPHI entity Type must be a non-empty string.")
                start = entity.get("BeginOffset")
                end = entity.get("EndOffset")
                entity_text = entity.get("Text")
                if (
                    isinstance(start, bool)
                    or isinstance(end, bool)
                    or not isinstance(start, int)
                    or not isinstance(end, int)
                    or not 0 <= start < end <= len(text)
                    or not isinstance(entity_text, str)
                    or text[start:end] != entity_text
                ):
                    raise ValueError(
                        "AWS DetectPHI entity offsets/text do not match the request text."
                    )
                score = entity.get("Score")
                confidence = float(score) if isinstance(score, (int, float)) else None
                candidates.append(
                    DetectionCandidate(
                        backend_span_id=str(entity["Id"]) if "Id" in entity else None,
                        category=map_aws_phi_type(native_category),
                        native_category=native_category,
                        subtype=native_category,
                        text=entity_text,
                        start_char=start,
                        end_char=end,
                        confidence=confidence,
                        native_payload=_json_object(entity),
                    )
                )
        except (TypeError, ValueError) as exc:
            raise BackendExecutionError(
                code="invalid_backend_response",
                message=str(exc),
                retryable=False,
                raw_response=response,
            ) from exc

        billable_units = max(1, ceil(len(text) / 100))

        cost_usd = (
            billable_units * self.cost_per_100_characters_usd
            if self.cost_per_100_characters_usd is not None
            else None
        )

        return DetectionResult(
            candidates=candidates,
            raw_output=response,
            model_version=_optional_text(response.get("ModelVersion")),
            usage=BackendUsage(
                request_count=1,
                input_chars=len(text),
                input_bytes=len(text.encode("utf-8")),
                latency_ms=latency_ms,
                cost_usd=cost_usd,
            ),
        )


def _json_object(value: dict[str, Any]) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], json.loads(json.dumps(value, default=str)))


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
