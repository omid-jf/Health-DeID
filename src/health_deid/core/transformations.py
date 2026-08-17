"""Compile, render, and apply text and structured PHI transformations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from health_deid.core.dates import (
    DateShift,
    generalize_age_90_plus,
    generalize_year_only,
    shift_structured_date,
)
from health_deid.core.ids import build_content_id
from health_deid.core.taxonomy import PHI_CATEGORY_TO_PLACEHOLDER, PhiCategory
from health_deid.models.ledger import RenderedText, RenderingEvent, SpanGroup, TransformEvent
from health_deid.models.policy import (
    DateShiftSurrogate,
    GeneralizationStrategy,
    TransformationAction,
    TransformationPolicy,
)

ReplacementProvider = Callable[[SpanGroup, str], str]
StructuredSurrogateProvider = Callable[[str, PhiCategory, str], Any]


def compile_transform_events(
    source_text: str,
    groups: list[SpanGroup],
    *,
    record_id: str,
    plan_revision: int,
    policy: TransformationPolicy,
    purpose: str,
    surrogate_provider: ReplacementProvider | None = None,
    date_shift_provider: ReplacementProvider | None = None,
) -> list[TransformEvent]:
    if purpose not in {"draft", "final"}:
        raise ValueError("Plan purpose must be draft or final.")
    events: list[TransformEvent] = []
    for group in groups:
        original = source_text[group.start_char : group.end_char]
        category_policy = policy.categories[group.category]
        replacement = _replacement_for(
            group,
            original,
            action=category_policy.action,
            generalization=category_policy.generalization,
            purpose=purpose,
            surrogate_provider=surrogate_provider,
            date_shift_provider=date_shift_provider,
        )
        events.append(
            TransformEvent(
                event_id=build_content_id(
                    "event",
                    record_id,
                    plan_revision,
                    purpose,
                    group.group_id,
                ),
                record_id=record_id,
                group_id=group.group_id,
                plan_revision=plan_revision,
                action=category_policy.action,
                strategy=(
                    category_policy.generalization.value
                    if category_policy.generalization is not None
                    else category_policy.surrogate.method
                    if category_policy.surrogate is not None
                    else None
                ),
                category=group.category,
                original_text=original,
                replacement_text=replacement,
                input_start_char=group.start_char,
                input_end_char=group.end_char,
            )
        )
    return events


def _replacement_for(
    group: SpanGroup,
    original: str,
    *,
    action: TransformationAction,
    generalization: GeneralizationStrategy | None,
    purpose: str,
    surrogate_provider: ReplacementProvider | None,
    date_shift_provider: ReplacementProvider | None,
) -> str:
    if action is TransformationAction.RETAIN:
        return original
    if purpose == "draft" or action is TransformationAction.REDACT:
        return PHI_CATEGORY_TO_PLACEHOLDER[group.category]
    if action is TransformationAction.GENERALIZE:
        if generalization is GeneralizationStrategy.YEAR_ONLY:
            return generalize_year_only(original)
        if generalization is GeneralizationStrategy.AGE_90_PLUS:
            return generalize_age_90_plus(original)
        raise ValueError(f"Unsupported generalization for {group.category.value}.")
    if group.category is PhiCategory.DATE:
        if date_shift_provider is None:
            raise ValueError("A date-shift provider is required for DATE surrogation.")
        return date_shift_provider(group, original)
    if surrogate_provider is None:
        raise ValueError("A surrogate provider is required for surrogate actions.")
    return surrogate_provider(group, original)


def render_events(
    source_text: str,
    events: list[TransformEvent],
    *,
    rendering_id: str,
) -> RenderedText:
    ordered = sorted(events, key=lambda event: (event.input_start_char, event.input_end_char))
    cursor = 0
    output_cursor = 0
    parts: list[str] = []
    rendering_events: list[RenderingEvent] = []
    for index, event in enumerate(ordered, start=1):
        if event.input_start_char < cursor:
            raise ValueError("Transformation events cannot overlap.")
        if event.input_end_char > len(source_text):
            raise ValueError("Transformation event exceeds input text.")
        if source_text[event.input_start_char : event.input_end_char] != event.original_text:
            raise ValueError("Transformation event original_text does not match source offsets.")
        if event.replacement_text is None:
            raise ValueError("Transformation event has no replacement_text.")
        unchanged = source_text[cursor : event.input_start_char]
        parts.append(unchanged)
        output_cursor += len(unchanged)
        output_start = output_cursor
        parts.append(event.replacement_text)
        output_cursor += len(event.replacement_text)
        rendering_events.append(
            RenderingEvent(
                rendering_event_id=build_content_id(
                    "render-event",
                    rendering_id,
                    event.event_id,
                    index,
                ),
                rendering_id=rendering_id,
                event_id=event.event_id,
                category=event.category,
                replacement_text=event.replacement_text,
                output_start_char=output_start,
                output_end_char=output_cursor,
            )
        )
        cursor = event.input_end_char
    parts.append(source_text[cursor:])
    return RenderedText(text="".join(parts), events=rendering_events)


def transform_structured_metadata(
    metadata: dict[str, Any],
    mappings: dict[str, PhiCategory],
    *,
    policy: TransformationPolicy,
    date_shift: DateShift | None,
    surrogate_provider: StructuredSurrogateProvider | None = None,
) -> tuple[dict[str, Any], list[tuple[str, PhiCategory, object, object]]]:
    output = dict(metadata)
    events: list[tuple[str, PhiCategory, object, object]] = []
    for column, category in mappings.items():
        original = metadata.get(column)
        if original is None:
            continue
        category_policy = policy.categories[category]
        if category_policy.action is TransformationAction.RETAIN:
            replacement: Any = original
        elif category_policy.action is TransformationAction.REDACT:
            replacement = PHI_CATEGORY_TO_PLACEHOLDER[category]
        elif category_policy.action is TransformationAction.GENERALIZE:
            text = str(original)
            if category_policy.generalization is GeneralizationStrategy.YEAR_ONLY:
                replacement = generalize_year_only(text)
            else:
                replacement = generalize_age_90_plus(text)
        elif category is PhiCategory.DATE:
            if date_shift is None:
                raise ValueError("Structured DATE surrogation requires an entity date shift.")
            date_policy = policy.categories[PhiCategory.DATE].surrogate
            assert isinstance(date_policy, DateShiftSurrogate)
            replacement = shift_structured_date(
                original,
                shift=date_shift,
                fallback=date_policy.fallback,
            )
        else:
            if surrogate_provider is None:
                raise ValueError("Structured surrogation requires a surrogate provider.")
            replacement = surrogate_provider(column, category, str(original))
        output[column] = replacement
        events.append((column, category, original, replacement))
    return output, events


__all__ = ["compile_transform_events", "render_events", "transform_structured_metadata"]
