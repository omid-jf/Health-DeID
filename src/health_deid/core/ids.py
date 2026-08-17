from __future__ import annotations

import hashlib
import json
from typing import Any


def build_deterministic_id(
    prefix: str,
    *,
    record_id: str,
    stage: str,
    index: int,
) -> str:
    """Build a stable identifier without embedding the original record ID."""

    if not prefix.strip():
        raise ValueError("prefix cannot be empty.")

    if not record_id.strip():
        raise ValueError("record_id cannot be empty.")

    if not stage.strip():
        raise ValueError("stage cannot be empty.")

    if index < 1:
        raise ValueError("index must be at least 1.")

    payload = "\x1f".join((record_id, stage, str(index)))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


def build_content_id(prefix: str, *parts: Any) -> str:
    """Build an opaque stable ID from canonical, non-embedded content."""

    if not prefix.strip():
        raise ValueError("prefix cannot be empty.")
    payload = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
    return f"{prefix}_{digest}"
