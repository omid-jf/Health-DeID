from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import cast

from health_deid.models.policy import DateShiftFallback, DateShiftSurrogate

DATE_SHIFT_ALGORITHM_VERSION = "hmac-sha256-week-v1"
_YEARLESS_ANCHOR = 2000  # Leap year: permits deterministic parsing of February 29.
_TOKEN_PATTERN = re.compile(r"[A-Za-z]+|\d+")
_YEAR_4 = re.compile(r"^(?:18|19|20|21)\d{2}$")
_AGE_NUMBER = re.compile(r"\d{1,3}")
_FORMATS = (
    "%m/%d/%Y",
    "%m-%d-%Y",
    "%Y-%m-%d",
    "%m/%d/%y",
    "%m-%d-%y",
    "%B %d, %Y",
    "%b %d, %Y",
    "%B %d %Y",
    "%b %d %Y",
    "%m/%Y",
    "%m-%Y",
    "%B %Y",
    "%b %Y",
)
_YEARLESS_FORMATS = (
    "%m/%d",
    "%m-%d",
    "%B %d",
    "%b %d",
    "%d %B",
    "%d %b",
)
_RANGE_SEPARATOR = re.compile(
    r"\s+(?:to|through)\s+|\s*[–—]\s*|\s+-\s+|(?<=\d)-(?=(?:[A-Za-z]|\d{1,2}/))",
    re.IGNORECASE,
)
_COMPACT_TEXT_RANGE = re.compile(
    r"^(?P<month>[A-Za-z]+)(?P<space>\s+)(?P<start>\d{1,2})"
    r"(?P<separator>\s*[–—-]\s*)(?P<end>\d{1,2})$"
)


@dataclass(frozen=True, slots=True)
class DateShift:
    weeks: int
    algorithm_version: str = DATE_SHIFT_ALGORITHM_VERSION

    @property
    def days(self) -> int:
        return self.weeks * 7


@dataclass(frozen=True, slots=True)
class _ParsedDate:
    value: date
    format_string: str
    yearless: bool


def derive_date_shift(
    *,
    secret: bytes,
    entity_id: str,
    policy: DateShiftSurrogate,
    namespace: str = "health-deid/date-shift/v1",
) -> DateShift:
    if not secret:
        raise ValueError("Date-shift secret cannot be empty.")
    allowed = [
        weeks for weeks in range(policy.minimum_weeks, policy.maximum_weeks + 1) if weeks != 0
    ]
    if not allowed:
        raise ValueError("Date-shift policy has no permitted non-zero offsets.")
    digest = hmac.new(
        secret,
        f"{namespace}\0{entity_id}".encode(),
        hashlib.sha256,
    ).digest()
    return DateShift(weeks=allowed[int.from_bytes(digest[:8], "big") % len(allowed)])


def generalize_year_only(text: str) -> str:
    tokens = list(_TOKEN_PATTERN.finditer(text))
    year_positions = _year_token_positions(tokens)
    if len(tokens) == 1 and year_positions:
        return text
    output: list[str] = []
    cursor = 0
    for index, token in enumerate(tokens):
        output.append(text[cursor : token.start()])
        value = token.group(0)
        output.append(value if index in year_positions else "[R_DATE]")
        cursor = token.end()
    output.append(text[cursor:])
    return "".join(output)


def generalize_age_90_plus(text: str) -> str:
    match = _AGE_NUMBER.search(text)
    if match is None or int(match.group(0)) < 90:
        return text
    return text[: match.start()] + "90+" + text[match.end() :]


def shift_date_text(
    text: str,
    *,
    shift: DateShift,
    fallback: DateShiftFallback,
) -> str:
    shifted_range = _shift_date_range(text, shift)
    if shifted_range is not None:
        return shifted_range
    parsed = _parse_date(text)
    if parsed is None:
        return _date_fallback(text, fallback)
    try:
        shifted = parsed.value + timedelta(days=shift.days)
    except OverflowError:
        return _date_fallback(text, fallback)
    return _render_date(shifted, parsed, text)


def shift_structured_date(
    value: str | date | datetime,
    *,
    shift: DateShift,
    fallback: DateShiftFallback | None = None,
) -> str:
    try:
        if isinstance(value, datetime):
            return (value + timedelta(days=shift.days)).isoformat()
        if isinstance(value, date):
            return (value + timedelta(days=shift.days)).isoformat()
    except OverflowError:
        if fallback is not None:
            source = cast(date | datetime, value).isoformat()
            return _date_fallback(source, fallback)
        raise
    shifted_range = _shift_date_range(value, shift)
    if shifted_range is not None:
        return shifted_range
    parsed = _parse_date(value)
    if parsed is None:
        if fallback is not None:
            return _date_fallback(value, fallback)
        raise ValueError(f"Structured date cannot be parsed safely: {value!r}")
    try:
        shifted = parsed.value + timedelta(days=shift.days)
    except OverflowError:
        if fallback is not None:
            return _date_fallback(value, fallback)
        raise
    return _render_date(shifted, parsed, value)


def _parse_date(text: str) -> _ParsedDate | None:
    for format_string in _FORMATS:
        try:
            return _ParsedDate(
                datetime.strptime(text, format_string).date(),
                format_string,
                False,
            )
        except ValueError:
            continue
    for format_string in _YEARLESS_FORMATS:
        try:
            value = datetime.strptime(f"{_YEARLESS_ANCHOR} {text}", f"%Y {format_string}").date()
            return _ParsedDate(value, format_string, True)
        except ValueError:
            continue
    return None


def _shift_date_range(text: str, shift: DateShift) -> str | None:
    candidates: list[str] = []
    for separator in _RANGE_SEPARATOR.finditer(text):
        left_source = text[: separator.start()]
        right_source = text[separator.end() :]
        left = _parse_date(left_source)
        right = _parse_date(right_source)
        if left is None or right is None or left.yearless != right.yearless:
            continue
        if left.yearless and right.value < left.value:
            try:
                right = _ParsedDate(
                    right.value.replace(year=right.value.year + 1),
                    right.format_string,
                    True,
                )
            except ValueError:
                continue
        try:
            left_value = left.value + timedelta(days=shift.days)
            right_value = right.value + timedelta(days=shift.days)
        except OverflowError:
            continue
        candidates.append(
            _render_date(left_value, left, left_source)
            + separator.group(0)
            + _render_date(right_value, right, right_source)
        )
    if len(candidates) == 1:
        return candidates[0]

    compact = _COMPACT_TEXT_RANGE.fullmatch(text)
    if compact is None:
        return None
    month = compact.group("month")
    left = _parse_date(f"{month} {compact.group('start')}")
    right = _parse_date(f"{month} {compact.group('end')}")
    if left is None or right is None or right.value < left.value:
        return None
    left_value = left.value + timedelta(days=shift.days)
    right_value = right.value + timedelta(days=shift.days)
    if (left_value.year, left_value.month) != (right_value.year, right_value.month):
        return None
    left_source = f"{month} {compact.group('start')}"
    left_rendered = _render_date(
        left_value,
        left,
        left_source,
    )
    shifted_month, shifted_day = left_rendered.rsplit(" ", 1)
    return (
        shifted_month
        + compact.group("space")
        + shifted_day
        + compact.group("separator")
        + str(right_value.day).zfill(len(compact.group("end")))
    )


def _render_date(value: date, parsed: _ParsedDate, source: str) -> str:
    """Render a parsed date while retaining numeric zero-padding and alpha case."""

    numbers = re.findall(r"\d+", source)
    format_string = parsed.format_string
    if format_string in {"%m/%d/%Y", "%m-%d-%Y", "%m/%d/%y", "%m-%d-%y"}:
        separator = "/" if "/" in format_string else "-"
        year = f"{value.year:04d}" if format_string.endswith("%Y") else f"{value.year % 100:02d}"
        return separator.join(
            (
                str(value.month).zfill(len(numbers[0])),
                str(value.day).zfill(len(numbers[1])),
                year,
            )
        )
    if format_string == "%Y-%m-%d":
        return "-".join(
            (
                f"{value.year:04d}",
                str(value.month).zfill(len(numbers[1])),
                str(value.day).zfill(len(numbers[2])),
            )
        )
    if format_string in {"%m/%Y", "%m-%Y"}:
        separator = "/" if "/" in format_string else "-"
        return separator.join((str(value.month).zfill(len(numbers[0])), f"{value.year:04d}"))
    if format_string in {"%m/%d", "%m-%d"}:
        separator = "/" if "/" in format_string else "-"
        return separator.join(
            (
                str(value.month).zfill(len(numbers[0])),
                str(value.day).zfill(len(numbers[1])),
            )
        )

    month_format = "%B" if "%B" in format_string else "%b"
    month = value.strftime(month_format)
    if "%d" not in format_string:
        rendered = f"{month} {value.year:04d}"
        return _match_alpha_case(rendered, source)
    day_source = next((item for item in numbers if len(item) <= 2), str(value.day))
    day = str(value.day).zfill(len(day_source))
    if format_string.startswith("%d"):
        rendered = f"{day} {month}"
    else:
        rendered = f"{month} {day}"
        if "," in format_string:
            rendered += ","
    if "%Y" in format_string:
        rendered += f" {value.year:04d}"
    return _match_alpha_case(rendered, source)


def _date_fallback(text: str, fallback: DateShiftFallback) -> str:
    if fallback is DateShiftFallback.REDACT:
        return "[R_DATE]"
    return generalize_year_only(text)


def _year_token_positions(tokens: list[re.Match[str]]) -> set[int]:
    four_digit_years = {
        index for index, token in enumerate(tokens) if _YEAR_4.match(token.group(0))
    }
    if four_digit_years:
        return four_digit_years
    if len(tokens) >= 3:
        final = tokens[-1].group(0)
        return {len(tokens) - 1} if len(final) == 2 and final.isdigit() else set()
    if len(tokens) == 1:
        value = tokens[0].group(0)
        if len(value) == 2 and value.isdigit() and int(value) > 12:
            return {0}
    return set()


def _match_alpha_case(rendered: str, source: str) -> str:
    source_alpha = next((character for character in source if character.isalpha()), None)
    if source_alpha is None:
        return rendered
    if source.isupper():
        return rendered.upper()
    if source.islower():
        return rendered.lower()
    return rendered
