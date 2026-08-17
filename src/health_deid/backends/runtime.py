"""AWS error normalization and UTF-8-safe request chunking."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
    ReadTimeoutError,
)

from health_deid.models.backend import DetectionCandidate

AWS_RETRY_MODE = "standard"
AWS_MAX_RETRIES = 3


@dataclass(slots=True)
class BackendExecutionError(RuntimeError):
    code: str
    message: str
    retryable: bool
    systemic: bool = False
    truncated: bool = False
    raw_response: object | None = None

    def __str__(self) -> str:
        return self.message


_RETRYABLE_AWS_CODES = frozenset(
    {
        "InternalServerException",
        "ModelNotReadyException",
        "ServiceUnavailableException",
        "ThrottlingException",
        "TooManyRequestsException",
    }
)
_PERMANENT_AWS_CODES = frozenset(
    {
        "AccessDeniedException",
        "InvalidEncodingException",
        "InvalidRequestException",
        "ResourceNotFoundException",
        "TextSizeLimitExceededException",
        "UnrecognizedClientException",
        "ValidationException",
    }
)


def classify_exception(exc: BaseException) -> BackendExecutionError:
    """Normalize AWS, network, and validation failures for durable retry state."""

    if isinstance(exc, BackendExecutionError):
        return exc
    if isinstance(exc, ClientError):
        response = cast(Mapping[str, object], exc.response)
        raw_error = response.get("Error")
        error = raw_error if isinstance(raw_error, Mapping) else {}
        code = str(error.get("Code") or type(exc).__name__)
        message = str(error.get("Message") or exc)
        if code in _RETRYABLE_AWS_CODES:
            return BackendExecutionError(
                code,
                message,
                True,
                systemic=True,
                raw_response=dict(response),
            )
        if code in _PERMANENT_AWS_CODES:
            return BackendExecutionError(code, message, False, raw_response=dict(response))
        raw_metadata = response.get("ResponseMetadata")
        metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
        status = metadata.get("HTTPStatusCode")
        retryable = isinstance(status, int) and status >= 500
        return BackendExecutionError(
            code,
            message,
            retryable,
            systemic=retryable,
            raw_response=dict(response),
        )
    if isinstance(
        exc,
        (ConnectTimeoutError, ConnectionClosedError, EndpointConnectionError, ReadTimeoutError),
    ):
        return BackendExecutionError(type(exc).__name__, str(exc), True, systemic=True)
    if isinstance(exc, (NoCredentialsError, ParamValidationError)):
        return BackendExecutionError(type(exc).__name__, str(exc), False, systemic=True)
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return BackendExecutionError(type(exc).__name__, str(exc), True, systemic=True)
    if isinstance(exc, (ValueError, TypeError)):
        return BackendExecutionError(type(exc).__name__, str(exc), False)
    if isinstance(exc, BotoCoreError):
        return BackendExecutionError(type(exc).__name__, str(exc), True, systemic=True)
    return BackendExecutionError(type(exc).__name__, str(exc) or type(exc).__name__, False)


@dataclass(frozen=True, slots=True)
class TextChunk:
    index: int
    start_char: int
    end_char: int
    text: str


def chunk_utf8_text(
    text: str,
    *,
    maximum_bytes: int,
    overlap_characters: int,
) -> list[TextChunk]:
    """Split text at Unicode code-point boundaries under a strict byte limit."""

    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive.")
    if overlap_characters < 0:
        raise ValueError("overlap_characters cannot be negative.")
    if not text:
        return []

    chunks: list[TextChunk] = []
    start = 0
    while True:
        end = _largest_fitting_end(text, start=start, maximum_bytes=maximum_bytes)
        if end == start:
            raise ValueError("maximum_bytes is too small for one UTF-8 character.")
        chunks.append(TextChunk(len(chunks), start, end, text[start:end]))
        if end == len(text):
            break
        start = max(start + 1, end - overlap_characters)
    return chunks


def rebase_candidate(candidate: DetectionCandidate, *, chunk_start: int) -> DetectionCandidate:
    return candidate.model_copy(
        update={
            "start_char": candidate.start_char + chunk_start,
            "end_char": candidate.end_char + chunk_start,
        }
    )


def deduplicate_candidates(
    candidates: list[DetectionCandidate],
) -> list[DetectionCandidate]:
    """Deduplicate overlap results while retaining the strongest candidate."""

    selected: dict[tuple[object, ...], DetectionCandidate] = {}
    for candidate in candidates:
        key = (
            candidate.start_char,
            candidate.end_char,
            candidate.category,
            candidate.text,
            candidate.subtype,
        )
        current = selected.get(key)
        score = candidate.confidence if candidate.confidence is not None else -1.0
        current_score = (
            current.confidence if current is not None and current.confidence is not None else -1.0
        )
        if current is None or score > current_score:
            selected[key] = candidate
    return sorted(
        selected.values(),
        key=lambda item: (item.start_char, item.end_char, item.category.value, item.text),
    )


def _largest_fitting_end(text: str, *, start: int, maximum_bytes: int) -> int:
    low = start + 1
    high = len(text)
    best = start
    while low <= high:
        middle = (low + high) // 2
        if len(text[start:middle].encode("utf-8")) <= maximum_bytes:
            best = middle
            low = middle + 1
        else:
            high = middle - 1
    return best


__all__ = [
    "BackendExecutionError",
    "TextChunk",
    "chunk_utf8_text",
    "classify_exception",
    "deduplicate_candidates",
    "rebase_candidate",
]
