from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass

from health_deid.core.ids import build_content_id
from health_deid.models.ledger import Finding, SpanGroup

RESOLVER_VERSION = "1"
_SOURCE_PRIORITY = {"review": 0, "rule": 1, "llm": 2, "aws": 3}
_NAME_JOIN_SEPARATORS = frozenset(" \t\r\n.,'-")


@dataclass(frozen=True, slots=True)
class ResolutionResult:
    groups: list[SpanGroup]
    findings_sha256: str


class _DisjointSet:
    """Track connected findings while overlap relationships are discovered."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, index: int) -> int:
        while self._parent[index] != index:
            self._parent[index] = self._parent[self._parent[index]]
            index = self._parent[index]

        return index

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)

        if left_root != right_root:
            self._parent[right_root] = left_root


def resolve_findings(
    source_text: str,
    findings: list[Finding],
    *,
    record_id: str,
) -> ResolutionResult:
    """Resolve immutable findings without merging unrelated adjacent spans."""

    ordered = sorted(findings, key=_position_key)
    _validate_findings(source_text, ordered)

    digest = _findings_digest(ordered)
    if not ordered:
        return ResolutionResult(groups=[], findings_sha256=digest)

    connections = _DisjointSet(len(ordered))
    _connect_overlapping_findings(ordered, connections)
    _connect_linked_names(source_text, ordered, connections)

    groups = _build_groups(ordered, connections, record_id=record_id)
    return ResolutionResult(groups=groups, findings_sha256=digest)


def _validate_findings(source_text: str, findings: list[Finding]) -> None:
    for finding in findings:
        if finding.end_char > len(source_text):
            raise ValueError(f"Finding {finding.finding_id} exceeds normalized input text.")

        actual_text = source_text[finding.start_char : finding.end_char]
        if actual_text != finding.exact_text:
            raise ValueError(f"Finding {finding.finding_id} text does not match its offsets.")


def _connect_overlapping_findings(
    findings: list[Finding],
    connections: _DisjointSet,
) -> None:
    active: list[int] = []
    for index, finding in enumerate(findings):
        active = [other for other in active if findings[other].end_char > finding.start_char]

        for other in active:
            connections.union(index, other)

        active.append(index)


def _connect_linked_names(
    source_text: str,
    findings: list[Finding],
    connections: _DisjointSet,
) -> None:
    linked_names: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, finding in enumerate(findings):
        if finding.category.value == "NAME" and finding.source_group_id:
            linked_names[(finding.source_name, finding.source_group_id)].append(index)

    for indexes in linked_names.values():
        for left, right in zip(indexes, indexes[1:], strict=False):
            gap = source_text[findings[left].end_char : findings[right].start_char]
            if gap and set(gap).issubset(_NAME_JOIN_SEPARATORS):
                connections.union(left, right)


def _build_groups(
    findings: list[Finding],
    connections: _DisjointSet,
    *,
    record_id: str,
) -> list[SpanGroup]:
    components: dict[int, list[Finding]] = defaultdict(list)
    for index, finding in enumerate(findings):
        components[connections.find(index)].append(finding)

    groups: list[SpanGroup] = []
    for component in components.values():
        primary = min(component, key=_primary_key)
        start = min(item.start_char for item in component)
        end = max(item.end_char for item in component)
        finding_ids = sorted(item.finding_id for item in component)
        group_id = build_content_id(
            "group",
            record_id,
            start,
            end,
            finding_ids,
        )

        groups.append(
            SpanGroup(
                group_id=group_id,
                record_id=record_id,
                category=primary.category,
                start_char=start,
                end_char=end,
                finding_ids=finding_ids,
            )
        )

    groups.sort(key=lambda group: (group.start_char, group.end_char, group.group_id))
    return groups


def _position_key(finding: Finding) -> tuple[int, int, str, str]:
    return finding.start_char, finding.end_char, finding.category.value, finding.finding_id


def _primary_key(finding: Finding) -> tuple[int, float, int, int, str, str]:
    confidence = finding.confidence if finding.confidence is not None else -1.0
    return (
        _SOURCE_PRIORITY[finding.source_kind],
        -confidence,
        -(finding.end_char - finding.start_char),
        finding.start_char,
        finding.category.value,
        finding.finding_id,
    )


def _findings_digest(findings: list[Finding]) -> str:
    payload = [
        {
            "id": item.finding_id,
            "category": item.category.value,
            "start": item.start_char,
            "end": item.end_char,
            "text": item.exact_text,
        }
        for item in findings
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
