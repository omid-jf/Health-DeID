from __future__ import annotations

from datetime import UTC, datetime

import pytest

from health_deid.core.dates import DateShift
from health_deid.core.resolution import resolve_findings
from health_deid.core.taxonomy import PhiCategory
from health_deid.core.transformations import (
    compile_transform_events,
    render_events,
    transform_structured_metadata,
)
from health_deid.models.ledger import Finding, SpanGroup
from health_deid.models.policy import (
    CategoryPolicy,
    DateShiftSurrogate,
    FakerSurrogate,
    TransformationAction,
    TransformationPolicy,
)


def _finding(
    finding_id: str,
    text: str,
    start: int,
    end: int,
    *,
    category: PhiCategory = PhiCategory.NAME,
    source_kind: str = "llm",
    source_name: str = "detector",
    source_group_id: str | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        record_id="record-1",
        source_kind=source_kind,
        source_name=source_name,
        category=category,
        exact_text=text[start:end],
        start_char=start,
        end_char=end,
        source_group_id=source_group_id,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _group(
    group_id: str,
    category: PhiCategory,
    start: int,
    end: int,
) -> SpanGroup:
    return SpanGroup(
        group_id=group_id,
        record_id="record-1",
        category=category,
        start_char=start,
        end_char=end,
        finding_ids=[f"finding-{group_id}"],
    )


def _policy_with(
    *overrides: tuple[PhiCategory, CategoryPolicy],
) -> TransformationPolicy:
    categories = dict(TransformationPolicy().categories)
    categories.update(overrides)
    return TransformationPolicy(categories=categories)


def _faker() -> FakerSurrogate:
    return FakerSurrogate(secret_reference="faker-key")


def test_resolution_merges_overlaps_but_not_merely_adjacent_spans() -> None:
    text = "JaneSmith"
    overlapping = resolve_findings(
        text,
        [
            _finding("wide", text, 0, 6),
            _finding("middle", text, 2, 8, source_kind="rule"),
            _finding("nested", text, 4, 9, source_kind="aws"),
        ],
        record_id="record-1",
    )
    adjacent = resolve_findings(
        text,
        [
            _finding("first", text, 0, 4),
            _finding("second", text, 4, 9),
        ],
        record_id="record-1",
    )

    assert [(group.start_char, group.end_char) for group in overlapping.groups] == [(0, 9)]
    assert overlapping.groups[0].finding_ids == ["middle", "nested", "wide"]
    assert [(group.start_char, group.end_char) for group in adjacent.groups] == [
        (0, 4),
        (4, 9),
    ]


def test_resolution_only_joins_split_names_with_an_explicit_source_group() -> None:
    text = "Jane Smith and Alex Jones"
    linked = resolve_findings(
        text,
        [
            _finding("jane", text, 0, 4, source_group_id="person-1"),
            _finding("smith", text, 5, 10, source_group_id="person-1"),
            _finding("alex", text, 15, 19),
            _finding("jones", text, 20, 25),
        ],
        record_id="record-1",
    )

    assert [(group.start_char, group.end_char) for group in linked.groups] == [
        (0, 10),
        (15, 19),
        (20, 25),
    ]


def test_resolution_does_not_join_source_groups_across_semantic_text() -> None:
    text = "Jane and Smith"
    resolution = resolve_findings(
        text,
        [
            _finding("jane", text, 0, 4, source_group_id="person-1"),
            _finding("smith", text, 9, 14, source_group_id="person-1"),
        ],
        record_id="record-1",
    )

    assert [(group.start_char, group.end_char) for group in resolution.groups] == [
        (0, 4),
        (9, 14),
    ]


def test_resolution_handles_empty_input_and_rejects_invalid_source_coordinates() -> None:
    empty = resolve_findings("", [], record_id="record-1")

    assert empty.groups == []
    assert len(empty.findings_sha256) == 64

    outside = _finding("outside", "Jane", 0, 4)
    with pytest.raises(ValueError, match="exceeds normalized input text"):
        resolve_findings("Jan", [outside], record_id="record-1")
    with pytest.raises(ValueError, match="does not match its offsets"):
        resolve_findings("Joan", [outside], record_id="record-1")


def test_literal_placeholder_text_is_not_treated_as_a_transform_event() -> None:
    text = "Literal [R_NAME]; patient Jane."
    start = text.index("Jane")
    resolution = resolve_findings(
        text,
        [_finding("jane", text, start, start + len("Jane"))],
        record_id="record-1",
    )
    events = compile_transform_events(
        text,
        resolution.groups,
        record_id="record-1",
        plan_revision=1,
        policy=TransformationPolicy(),
        purpose="final",
    )
    rendered = render_events(text, events, rendering_id="rendering-1")

    assert rendered.text == "Literal [R_NAME]; patient [R_NAME]."
    assert len(rendered.events) == 1
    assert rendered.events[0].output_start_char == rendered.text.rindex("[R_NAME]")


def test_validation_plan_masks_surrogates_without_calling_a_generator() -> None:
    policy = _policy_with(
        (
            PhiCategory.EMAIL,
            CategoryPolicy(
                action=TransformationAction.SURROGATE,
                surrogate=_faker(),
            ),
        )
    )
    source = "user@example.test"
    group = _group("email", PhiCategory.EMAIL, 0, len(source))

    events = compile_transform_events(
        source,
        [group],
        record_id="record-1",
        plan_revision=3,
        policy=policy,
        purpose="draft",
    )

    assert events[0].replacement_text == "[R_EMAIL]"
    assert events[0].strategy == "faker"
    with pytest.raises(ValueError, match="surrogate provider"):
        compile_transform_events(
            source,
            [group],
            record_id="record-1",
            plan_revision=3,
            policy=policy,
            purpose="final",
        )


def test_final_plan_applies_retention_generalization_and_generic_surrogation() -> None:
    policy = _policy_with(
        (
            PhiCategory.NAME,
            CategoryPolicy(
                action=TransformationAction.SURROGATE,
                surrogate=_faker(),
            ),
        )
    )
    source = "Jane, Engineer, age 102 on 03/14/2024"
    groups = [
        _group("name", PhiCategory.NAME, 0, 4),
        _group("profession", PhiCategory.PROFESSION, 6, 14),
        _group("age", PhiCategory.AGE, 20, 23),
        _group("date", PhiCategory.DATE, 27, 37),
    ]

    events = compile_transform_events(
        source,
        groups,
        record_id="record-1",
        plan_revision=1,
        policy=policy,
        purpose="final",
        surrogate_provider=lambda _group, _original: "Alex",
    )
    rendered = render_events(source, events, rendering_id="rendering-generalized")

    assert rendered.text == "Alex, Engineer, age 90+ on [R_DATE]/[R_DATE]/2024"
    assert [event.replacement_text for event in events] == [
        "Alex",
        "Engineer",
        "90+",
        "[R_DATE]/[R_DATE]/2024",
    ]
    with pytest.raises(ValueError, match="purpose"):
        compile_transform_events(
            source,
            groups,
            record_id="record-1",
            plan_revision=1,
            policy=policy,
            purpose="preview",
        )


def test_planning_defensively_rejects_an_unknown_generalization() -> None:
    categories = dict(TransformationPolicy().categories)
    categories[PhiCategory.NAME] = CategoryPolicy.model_construct(
        action=TransformationAction.GENERALIZE,
        generalization=None,
        surrogate=None,
    )
    malformed_policy = TransformationPolicy.model_construct(
        policy_version=1,
        categories=categories,
        date_shift=None,
    )

    with pytest.raises(ValueError, match="Unsupported generalization for NAME"):
        compile_transform_events(
            "Jane",
            [_group("name", PhiCategory.NAME, 0, 4)],
            record_id="record-1",
            plan_revision=1,
            policy=malformed_policy,
            purpose="final",
        )


def test_final_plan_routes_date_surrogation_to_the_date_provider() -> None:
    policy = _policy_with(
        (
            PhiCategory.DATE,
            CategoryPolicy(
                action=TransformationAction.SURROGATE,
                surrogate=DateShiftSurrogate(secret_reference="date-key"),
            ),
        ),
    )
    source = "01/02/2026"
    group = _group("date", PhiCategory.DATE, 0, len(source))

    events = compile_transform_events(
        source,
        [group],
        record_id="record-1",
        plan_revision=1,
        policy=policy,
        purpose="final",
        date_shift_provider=lambda _group, _original: "01/09/2026",
    )

    assert events[0].replacement_text == "01/09/2026"
    with pytest.raises(ValueError, match="date-shift provider"):
        compile_transform_events(
            source,
            [group],
            record_id="record-1",
            plan_revision=1,
            policy=policy,
            purpose="final",
        )


def test_rendering_keeps_adjacent_events_separate_and_rejects_overlap() -> None:
    source = "JaneSmith"
    groups = [
        _group("first", PhiCategory.NAME, 0, 4),
        _group("second", PhiCategory.NAME, 4, 9),
    ]
    events = compile_transform_events(
        source,
        groups,
        record_id="record-1",
        plan_revision=1,
        policy=TransformationPolicy(),
        purpose="final",
    )

    rendered = render_events(source, list(reversed(events)), rendering_id="rendering-1")

    assert rendered.text == "[R_NAME][R_NAME]"
    assert len(rendered.events) == 2
    overlapping = events[1].model_copy(update={"input_start_char": 3, "original_text": source[3:9]})
    with pytest.raises(ValueError, match="cannot overlap"):
        render_events(source, [events[0], overlapping], rendering_id="rendering-2")


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"input_end_char": 5, "original_text": "JaneS"}, "exceeds input text"),
        ({"original_text": "Joan"}, "does not match source offsets"),
        ({"replacement_text": None}, "has no replacement_text"),
    ],
)
def test_rendering_rejects_inconsistent_events(
    updates: dict[str, object],
    message: str,
) -> None:
    source = "Jane"
    event = compile_transform_events(
        source,
        [_group("name", PhiCategory.NAME, 0, 4)],
        record_id="record-1",
        plan_revision=1,
        policy=TransformationPolicy(),
        purpose="final",
    )[0]

    with pytest.raises(ValueError, match=message):
        render_events(
            source,
            [event.model_copy(update=updates)],
            rendering_id="invalid-rendering",
        )


def test_structured_transformations_use_policy_without_mutating_input() -> None:
    policy = _policy_with(
        (
            PhiCategory.NAME,
            CategoryPolicy(
                action=TransformationAction.SURROGATE,
                surrogate=_faker(),
            ),
        )
    )
    metadata = {
        "patient_name": "Jane Smith",
        "email": "jane@example.test",
        "profession": "Engineer",
        "missing": None,
        "unmapped": "unchanged",
    }
    calls: list[tuple[str, PhiCategory, str]] = []

    def surrogate(column: str, category: PhiCategory, original: str) -> str:
        calls.append((column, category, original))
        return "Test Person"

    output, events = transform_structured_metadata(
        metadata,
        {
            "patient_name": PhiCategory.NAME,
            "email": PhiCategory.EMAIL,
            "profession": PhiCategory.PROFESSION,
            "missing": PhiCategory.ID,
        },
        policy=policy,
        date_shift=None,
        surrogate_provider=surrogate,
    )

    assert metadata["patient_name"] == "Jane Smith"
    assert output == {
        "patient_name": "Test Person",
        "email": "[R_EMAIL]",
        "profession": "Engineer",
        "missing": None,
        "unmapped": "unchanged",
    }
    assert calls == [("patient_name", PhiCategory.NAME, "Jane Smith")]
    assert [event[0] for event in events] == ["patient_name", "email", "profession"]


def test_structured_surrogation_requires_a_provider() -> None:
    policy = _policy_with(
        (
            PhiCategory.NAME,
            CategoryPolicy(
                action=TransformationAction.SURROGATE,
                surrogate=_faker(),
            ),
        )
    )

    with pytest.raises(ValueError, match="surrogate provider"):
        transform_structured_metadata(
            {"patient_name": "Jane"},
            {"patient_name": PhiCategory.NAME},
            policy=policy,
            date_shift=None,
        )


def test_structured_generalization_and_missing_date_shift_are_explicit() -> None:
    output, events = transform_structured_metadata(
        {"age": 102, "date": "03/14/2024"},
        {"age": PhiCategory.AGE, "date": PhiCategory.DATE},
        policy=TransformationPolicy(),
        date_shift=None,
    )

    assert output == {"age": "90+", "date": "[R_DATE]/[R_DATE]/2024"}
    assert len(events) == 2

    date_shift_policy = _policy_with(
        (
            PhiCategory.DATE,
            CategoryPolicy(
                action=TransformationAction.SURROGATE,
                surrogate=DateShiftSurrogate(secret_reference="date-key"),
            ),
        ),
    )
    with pytest.raises(ValueError, match="requires an entity date shift"):
        transform_structured_metadata(
            {"date": "03/14/2024"},
            {"date": PhiCategory.DATE},
            policy=date_shift_policy,
            date_shift=None,
        )

    shifted, shifted_events = transform_structured_metadata(
        {"date": "03/14/2024"},
        {"date": PhiCategory.DATE},
        policy=date_shift_policy,
        date_shift=DateShift(weeks=1),
    )
    assert shifted == {"date": "03/21/2024"}
    assert shifted_events[0][3] == "03/21/2024"

    fallback, fallback_events = transform_structured_metadata(
        {"date": "approximately 2024"},
        {"date": PhiCategory.DATE},
        policy=date_shift_policy,
        date_shift=DateShift(weeks=1),
    )
    assert fallback == {"date": "[R_DATE] 2024"}
    assert fallback_events[0][3] == "[R_DATE] 2024"
