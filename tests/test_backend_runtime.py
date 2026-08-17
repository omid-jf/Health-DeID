from __future__ import annotations

import pytest
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
)

from health_deid.backends.runtime import (
    BackendExecutionError,
    chunk_utf8_text,
    classify_exception,
    deduplicate_candidates,
    rebase_candidate,
)
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import DetectionCandidate


def _candidate(
    text: str,
    start: int,
    *,
    confidence: float | None = None,
    subtype: str | None = None,
) -> DetectionCandidate:
    return DetectionCandidate(
        category=PhiCategory.NAME,
        native_category="NAME",
        subtype=subtype,
        text=text,
        start_char=start,
        end_char=start + len(text),
        confidence=confidence,
    )


def test_utf8_chunking_respects_bytes_overlap_and_character_offsets() -> None:
    text = "Aé🙂BC"

    chunks = chunk_utf8_text(text, maximum_bytes=7, overlap_characters=1)

    assert [(chunk.start_char, chunk.end_char, chunk.text) for chunk in chunks] == [
        (0, 3, "Aé🙂"),
        (2, 5, "🙂BC"),
    ]
    assert all(len(chunk.text.encode("utf-8")) <= 7 for chunk in chunks)
    assert all(text[chunk.start_char : chunk.end_char] == chunk.text for chunk in chunks)


@pytest.mark.parametrize(
    ("text", "maximum_bytes", "overlap", "message"),
    [
        ("text", 0, 0, "must be positive"),
        ("text", 4, -1, "cannot be negative"),
        ("🙂", 3, 0, "too small"),
    ],
)
def test_utf8_chunking_rejects_invalid_limits(
    text: str,
    maximum_bytes: int,
    overlap: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        chunk_utf8_text(
            text,
            maximum_bytes=maximum_bytes,
            overlap_characters=overlap,
        )


def test_utf8_chunking_handles_empty_text_and_large_overlap() -> None:
    assert chunk_utf8_text("", maximum_bytes=10, overlap_characters=2) == []
    chunks = chunk_utf8_text("abcd", maximum_bytes=2, overlap_characters=5)
    assert [(chunk.start_char, chunk.end_char) for chunk in chunks] == [
        (0, 2),
        (1, 3),
        (2, 4),
    ]


def test_candidates_are_rebased_and_overlap_duplicates_keep_best_confidence() -> None:
    local = _candidate("🙂", 0, confidence=0.4)
    rebased = rebase_candidate(local, chunk_start=6)
    weaker = _candidate("Jane", 2, confidence=0.2)
    stronger = _candidate("Jane", 2, confidence=0.9)
    distinct_subtype = _candidate("Jane", 2, confidence=0.1, subtype="PATIENT")

    selected = deduplicate_candidates([stronger, distinct_subtype, weaker, rebased])

    assert (rebased.start_char, rebased.end_char, rebased.text) == (6, 7, "🙂")
    assert [(item.start_char, item.subtype) for item in selected] == [
        (2, None),
        (2, "PATIENT"),
        (6, None),
    ]
    assert selected[0].confidence == 0.9


def _client_error(code: str, status: int) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": f"message for {code}"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "Operation",
    )


@pytest.mark.parametrize(
    ("exception", "retryable", "systemic"),
    [
        (_client_error("ThrottlingException", 400), True, True),
        (_client_error("AccessDeniedException", 403), False, False),
        (_client_error("FutureServiceError", 503), True, True),
        (_client_error("FutureClientError", 409), False, False),
        (TimeoutError("late"), True, True),
        (ConnectionError("closed"), True, True),
        (EndpointConnectionError(endpoint_url="https://example.invalid"), True, True),
        (NoCredentialsError(), False, True),
        (ParamValidationError(report="invalid input"), False, True),
        (ValueError("bad input"), False, False),
        (BotoCoreError(), True, True),
        (RuntimeError("unknown"), False, False),
    ],
)
def test_error_classification_distinguishes_retryable_and_systemic_failures(
    exception: BaseException,
    retryable: bool,
    systemic: bool,
) -> None:
    classified = classify_exception(exception)

    assert classified.retryable is retryable
    assert classified.systemic is systemic
    assert classified.code
    assert classified.message
    if isinstance(exception, ClientError):
        assert classified.raw_response == exception.response


def test_error_classification_preserves_an_existing_execution_error() -> None:
    existing = BackendExecutionError(
        code="truncated",
        message="output stopped early",
        retryable=True,
        truncated=True,
    )

    assert classify_exception(existing) is existing
    assert str(existing) == "output stopped early"


def test_error_classification_tolerates_missing_aws_error_metadata() -> None:
    exception = ClientError({}, "Operation")

    classified = classify_exception(exception)

    assert classified.code == "ClientError"
    assert classified.retryable is False
    assert classified.systemic is False
