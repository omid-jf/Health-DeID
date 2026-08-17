from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base model for persisted health-deid schemas."""

    model_config = ConfigDict(extra="forbid")
