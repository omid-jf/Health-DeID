"""Validated local rules plus their small detection engine."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import yaml
from pydantic import Field, field_validator, model_validator

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.backend import DetectionCandidate
from health_deid.models.common import StrictModel

if TYPE_CHECKING:
    from health_deid.models.config import PipelineConfig


class RedactionRule(StrictModel):
    id: str
    name: str
    category: PhiCategory
    type: Literal["regex", "exact"] = "regex"
    pattern: str
    ignore_case: bool = False

    @field_validator("id", "name", "pattern")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Rule fields cannot be empty.")
        return value

    @model_validator(mode="after")
    def validate_regex(self) -> RedactionRule:
        if self.type == "regex":
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"Invalid rule regex: {exc}") from exc
        return self


class RulesFile(StrictModel):
    rules: list[RedactionRule] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_rule_ids(self) -> RulesFile:
        identifiers = [rule.id for rule in self.rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Rule IDs must be unique.")
        return self


def load_rules_file(path: str | Path) -> RulesFile:
    rules_path = Path(path)
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file does not exist: {rules_path}")
    if not rules_path.is_file():
        raise ValueError(f"Rules path is not a file: {rules_path}")

    with rules_path.open("r", encoding="utf-8") as file:
        raw_rules = yaml.safe_load(file)

    if raw_rules is None:
        raise ValueError(f"Rules file is empty: {rules_path}")
    if not isinstance(raw_rules, dict):
        raise ValueError("Top-level rules YAML must be a mapping/object.")
    return RulesFile.model_validate(raw_rules)


def snapshot_configured_rules(config: PipelineConfig) -> PipelineConfig:
    """Embed external rules so a run never depends on the original file."""

    rules = config.rules
    if not rules.enabled or rules.embedded is not None:
        return config
    assert rules.rules_path is not None
    snapshot = rules.model_copy(
        update={"rules_path": None, "embedded": load_rules_file(rules.rules_path)}
    )
    return config.model_copy(update={"rules": snapshot})


def find_rule_candidates(text: str, rules_file: RulesFile) -> list[DetectionCandidate]:
    """Return rule findings in normalized-source coordinates."""

    candidates: list[DetectionCandidate] = []
    for rule in rules_file.rules:
        flags = re.IGNORECASE if rule.ignore_case else 0
        pattern = re.escape(rule.pattern) if rule.type == "exact" else rule.pattern
        for match in re.compile(pattern, flags=flags).finditer(text):
            if match.start() == match.end():
                continue
            candidates.append(
                DetectionCandidate(
                    backend_span_id=f"{rule.id}:{len(candidates) + 1}",
                    category=rule.category,
                    native_category=rule.category.value,
                    subtype=rule.id,
                    text=match.group(0),
                    start_char=match.start(),
                    end_char=match.end(),
                    native_payload={"rule_id": rule.id, "rule_name": rule.name},
                )
            )
    return candidates


__all__ = [
    "RedactionRule",
    "RulesFile",
    "find_rule_candidates",
    "load_rules_file",
    "snapshot_configured_rules",
]
