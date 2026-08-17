from __future__ import annotations

from datetime import date, datetime

import pytest

from health_deid.core.dates import (
    DATE_SHIFT_ALGORITHM_VERSION,
    DateShift,
    _match_alpha_case,
    derive_date_shift,
    generalize_age_90_plus,
    generalize_year_only,
    shift_date_text,
    shift_structured_date,
)
from health_deid.models.policy import DateShiftFallback, DateShiftSurrogate


def test_date_shift_is_deterministic_nonzero_and_expressed_in_whole_weeks() -> None:
    policy = DateShiftSurrogate(
        minimum_weeks=-8,
        maximum_weeks=8,
        secret_reference="date-key",
    )

    first = derive_date_shift(secret=b"secret", entity_id="entity-1", policy=policy)
    repeated = derive_date_shift(secret=b"secret", entity_id="entity-1", policy=policy)

    assert first == repeated
    assert -8 <= first.weeks <= 8
    assert first.weeks != 0
    assert first.days == first.weeks * 7
    assert first.algorithm_version == DATE_SHIFT_ALGORITHM_VERSION

    fixed = derive_date_shift(
        secret=b"secret",
        entity_id="entity-2",
        policy=DateShiftSurrogate(
            minimum_weeks=3,
            maximum_weeks=3,
            secret_reference="date-key",
        ),
    )
    assert fixed.weeks == 3


def test_date_shift_rejects_empty_secret_and_empty_effective_range() -> None:
    policy = DateShiftSurrogate(secret_reference="date-key")
    with pytest.raises(ValueError, match="secret cannot be empty"):
        derive_date_shift(secret=b"", entity_id="entity", policy=policy)

    malformed = DateShiftSurrogate.model_construct(
        minimum_weeks=0,
        maximum_weeks=0,
        fallback=DateShiftFallback.YEAR_ONLY,
        secret_reference="date-key",
    )
    with pytest.raises(ValueError, match="no permitted non-zero offsets"):
        derive_date_shift(secret=b"secret", entity_id="entity", policy=malformed)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("2024", "2024"),
        ("23", "23"),
        ("12", "[R_DATE]"),
        ("01/07/2023", "[R_DATE]/[R_DATE]/2023"),
        ("01-07-23", "[R_DATE]-[R_DATE]-23"),
        ("March 2023", "[R_DATE] 2023"),
        ("Jan 15, 2023", "[R_DATE] [R_DATE], 2023"),
        ("2023-01-07", "2023-[R_DATE]-[R_DATE]"),
        ("03/14", "[R_DATE]/[R_DATE]"),
        ("Jan 15", "[R_DATE] [R_DATE]"),
        ("", ""),
    ],
)
def test_year_only_generalization_preserves_only_actual_year_tokens(
    source: str,
    expected: str,
) -> None:
    assert generalize_year_only(source) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("89", "89"),
        ("90", "90+"),
        ("102-year-old", "90+-year-old"),
        ("age unknown", "age unknown"),
    ],
)
def test_age_generalization_only_changes_explicit_ages_at_least_90(
    source: str,
    expected: str,
) -> None:
    assert generalize_age_90_plus(source) == expected


@pytest.mark.parametrize(
    ("source", "weeks", "expected"),
    [
        ("01/02/2024", 1, "01/09/2024"),
        ("1-2-24", 1, "1-9-24"),
        ("2024-01-02", 1, "2024-01-09"),
        ("March 2, 2024", 1, "March 9, 2024"),
        ("Mar 02 2024", 1, "Mar 09 2024"),
        ("03/2024", 5, "04/2024"),
        ("March 2024", 5, "April 2024"),
        ("03/02", 1, "03/09"),
        ("March 2", 1, "March 9"),
        ("2 March", 1, "9 March"),
        ("12/30", 1, "01/06"),
    ],
)
def test_date_shifting_preserves_supported_written_formats(
    source: str,
    weeks: int,
    expected: str,
) -> None:
    assert (
        shift_date_text(
            source,
            shift=DateShift(weeks),
            fallback=DateShiftFallback.REDACT,
        )
        == expected
    )


def test_week_shifts_preserve_weekday_across_a_leap_year() -> None:
    source = "02/29/2024"
    shifted = shift_date_text(
        source,
        shift=DateShift(52),
        fallback=DateShiftFallback.REDACT,
    )

    assert shifted == "02/27/2025"
    assert (
        datetime.strptime(source, "%m/%d/%Y").weekday()
        == datetime.strptime(shifted, "%m/%d/%Y").weekday()
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("01/01/2024–01/10/2024", "01/08/2024–01/17/2024"),
        ("01/01/2024 through 01/10/2024", "01/08/2024 through 01/17/2024"),
        ("12/30-01/02", "01/06-01/09"),
        ("March 1-3", "March 8-10"),
        ("march 1–3", "march 8–10"),
    ],
)
def test_date_ranges_shift_both_endpoints_and_preserve_separators(
    source: str,
    expected: str,
) -> None:
    assert (
        shift_date_text(
            source,
            shift=DateShift(1),
            fallback=DateShiftFallback.REDACT,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("source", "fallback", "expected"),
    [
        ("not a date", DateShiftFallback.REDACT, "[R_DATE]"),
        ("Spring 2024", DateShiftFallback.YEAR_ONLY, "[R_DATE] 2024"),
        ("12/31/9999", DateShiftFallback.REDACT, "[R_DATE]"),
        ("March 20-31", DateShiftFallback.REDACT, "[R_DATE]"),
        ("March 3-1", DateShiftFallback.REDACT, "[R_DATE]"),
        ("03/01-02/29", DateShiftFallback.REDACT, "[R_DATE]"),
        ("12/30/9999–12/31/9999", DateShiftFallback.REDACT, "[R_DATE]"),
    ],
)
def test_date_shift_fallbacks_are_explicit(
    source: str,
    fallback: DateShiftFallback,
    expected: str,
) -> None:
    assert shift_date_text(source, shift=DateShift(1), fallback=fallback) == expected


def test_textual_date_shifting_preserves_source_case() -> None:
    assert (
        shift_date_text(
            "MARCH 1, 2024",
            shift=DateShift(1),
            fallback=DateShiftFallback.REDACT,
        )
        == "MARCH 8, 2024"
    )
    assert (
        shift_date_text(
            "march 1, 2024",
            shift=DateShift(1),
            fallback=DateShiftFallback.REDACT,
        )
        == "march 8, 2024"
    )
    assert _match_alpha_case("March", "123") == "March"


def test_structured_dates_support_date_datetime_string_and_range_values() -> None:
    shift = DateShift(1)

    assert shift_structured_date(date(2024, 1, 2), shift=shift) == "2024-01-09"
    assert shift_structured_date(datetime(2024, 1, 2, 3, 4, 5), shift=shift) == (
        "2024-01-09T03:04:05"
    )
    assert shift_structured_date("01/02/2024", shift=shift) == "01/09/2024"
    assert shift_structured_date("01/01/2024 - 01/10/2024", shift=shift) == (
        "01/08/2024 - 01/17/2024"
    )

    with pytest.raises(ValueError, match="cannot be parsed safely"):
        shift_structured_date("not a date", shift=shift)

    assert (
        shift_structured_date(
            "service date in 2024",
            shift=shift,
            fallback=DateShiftFallback.YEAR_ONLY,
        )
        == "[R_DATE] [R_DATE] [R_DATE] 2024"
    )
    assert (
        shift_structured_date(
            "not a date",
            shift=shift,
            fallback=DateShiftFallback.REDACT,
        )
        == "[R_DATE]"
    )
    with pytest.raises(OverflowError):
        shift_structured_date(date.max, shift=shift)
    assert (
        shift_structured_date(
            date.max,
            shift=shift,
            fallback=DateShiftFallback.REDACT,
        )
        == "[R_DATE]"
    )
    with pytest.raises(OverflowError):
        shift_structured_date("12/31/9999", shift=shift)
    assert (
        shift_structured_date(
            "12/31/9999",
            shift=shift,
            fallback=DateShiftFallback.REDACT,
        )
        == "[R_DATE]"
    )
