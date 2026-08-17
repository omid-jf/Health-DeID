from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from health_deid.models.common import StrictModel

ExportFormat = Literal["parquet", "jsonl"]
ExportMode = Literal["ready_only", "all_records"]


class ExportRequest(StrictModel):
    output_path: Path
    format: ExportFormat = "parquet"
    mode: ExportMode = "ready_only"
    selected_columns: list[str] = Field(
        default_factory=lambda: ["record_id", "entity_id", "final_text", "deid_status"]
    )

    @field_validator("selected_columns")
    @classmethod
    def validate_columns(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value]
        if not cleaned or any(not item for item in cleaned):
            raise ValueError("At least one non-empty export column is required.")
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("Export columns cannot contain duplicates.")
        return cleaned

    @model_validator(mode="after")
    def include_status_for_all_records(self) -> ExportRequest:
        if self.mode == "all_records" and "deid_status" not in self.selected_columns:
            self.selected_columns.append("deid_status")
        return self


class ExportResult(StrictModel):
    export_id: str
    output_path: Path
    format: ExportFormat
    mode: ExportMode
    selected_columns: list[str]
    record_count: int = Field(ge=0)
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: AwareDatetime
    finished_at: AwareDatetime
