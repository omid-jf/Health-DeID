from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, Tag, field_validator, model_validator

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.common import StrictModel


class TransformationAction(StrEnum):
    RETAIN = "retain"
    REDACT = "redact"
    GENERALIZE = "generalize"
    SURROGATE = "surrogate"


class GeneralizationStrategy(StrEnum):
    YEAR_ONLY = "year_only"
    AGE_90_PLUS = "age_90_plus"


class ConsistencyScope(StrEnum):
    OCCURRENCE = "occurrence"
    RECORD = "record"
    ENTITY = "entity"


class DateShiftFallback(StrEnum):
    REDACT = "redact"
    YEAR_ONLY = "year_only"


class FakerSurrogate(StrictModel):
    method: Literal["faker"] = "faker"
    consistency: ConsistencyScope = ConsistencyScope.ENTITY
    secret_reference: str

    @field_validator("secret_reference")
    @classmethod
    def nonempty_secret(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Faker secret reference cannot be blank.")
        return value


class CustomListSurrogate(StrictModel):
    """Select deterministic replacements from a user-provided list."""

    method: Literal["custom_list"] = "custom_list"
    consistency: ConsistencyScope = ConsistencyScope.ENTITY
    values: list[str]
    secret_reference: str

    @field_validator("values")
    @classmethod
    def valid_values(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if not cleaned or any(not value for value in cleaned):
            raise ValueError("A custom list requires at least one non-empty value.")
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("Custom-list values must be unique.")
        return cleaned

    @field_validator("secret_reference")
    @classmethod
    def nonempty_secret(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Custom-list secret reference cannot be blank.")
        return value


class DateShiftSurrogate(StrictModel):
    """Shift every date for one entity by the same whole-week offset."""

    method: Literal["date_shift"] = "date_shift"
    consistency: Literal[ConsistencyScope.ENTITY] = ConsistencyScope.ENTITY
    minimum_weeks: int = -52
    maximum_weeks: int = 52
    fallback: DateShiftFallback = DateShiftFallback.YEAR_ONLY
    secret_reference: str

    @field_validator("secret_reference")
    @classmethod
    def nonempty_secret(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Date-shift secret reference cannot be blank.")
        return value

    @model_validator(mode="after")
    def valid_range(self) -> DateShiftSurrogate:
        if self.minimum_weeks > self.maximum_weeks:
            raise ValueError("minimum_weeks cannot exceed maximum_weeks.")
        if self.minimum_weeks == 0 and self.maximum_weeks == 0:
            raise ValueError("The date-shift range must include a non-zero offset.")
        return self


SurrogatePolicy = Annotated[
    Annotated[FakerSurrogate, Tag("faker")]
    | Annotated[CustomListSurrogate, Tag("custom_list")]
    | Annotated[DateShiftSurrogate, Tag("date_shift")],
    Field(discriminator="method"),
]


class CategoryPolicy(StrictModel):
    action: TransformationAction
    generalization: GeneralizationStrategy | None = None
    surrogate: SurrogatePolicy | None = None

    @model_validator(mode="after")
    def valid_action(self) -> CategoryPolicy:
        if self.action is TransformationAction.GENERALIZE:
            if self.generalization is None:
                raise ValueError("A generalize action requires a strategy.")
            if self.surrogate is not None:
                raise ValueError("A generalize action cannot include a surrogate.")
            return self
        if self.generalization is not None:
            raise ValueError("generalization is only valid for a generalize action.")
        if self.action is TransformationAction.SURROGATE:
            if self.surrogate is None:
                raise ValueError("A surrogate action requires replacement settings.")
            return self
        if self.surrogate is not None:
            raise ValueError("surrogate is only valid for a surrogate action.")
        return self


def _default_categories() -> dict[PhiCategory, CategoryPolicy]:
    policies = {
        category: CategoryPolicy(action=TransformationAction.REDACT) for category in PhiCategory
    }
    policies[PhiCategory.DATE] = CategoryPolicy(
        action=TransformationAction.GENERALIZE,
        generalization=GeneralizationStrategy.YEAR_ONLY,
    )
    policies[PhiCategory.AGE] = CategoryPolicy(
        action=TransformationAction.GENERALIZE,
        generalization=GeneralizationStrategy.AGE_90_PLUS,
    )
    policies[PhiCategory.PROFESSION] = CategoryPolicy(action=TransformationAction.RETAIN)
    return policies


class TransformationPolicy(StrictModel):
    """Transformation selected for every supported PHI category."""

    policy_version: Literal[1] = 1
    categories: dict[PhiCategory, CategoryPolicy] = Field(default_factory=_default_categories)

    @field_validator("categories")
    @classmethod
    def every_category(
        cls, values: dict[PhiCategory, CategoryPolicy]
    ) -> dict[PhiCategory, CategoryPolicy]:
        missing = set(PhiCategory).difference(values)
        if missing:
            names = ", ".join(sorted(category.value for category in missing))
            raise ValueError(f"Category policy is missing: {names}")
        return values

    @model_validator(mode="after")
    def valid_category_methods(self) -> TransformationPolicy:
        for category, policy in self.categories.items():
            if policy.action is TransformationAction.GENERALIZE:
                expected = {
                    PhiCategory.DATE: GeneralizationStrategy.YEAR_ONLY,
                    PhiCategory.AGE: GeneralizationStrategy.AGE_90_PLUS,
                }.get(category)
                if policy.generalization is not expected:
                    raise ValueError(f"Generalization is not valid for {category.value}.")
            if policy.action is not TransformationAction.SURROGATE:
                continue
            assert policy.surrogate is not None
            if category is PhiCategory.DATE and not isinstance(
                policy.surrogate, DateShiftSurrogate
            ):
                raise ValueError("DATE replacement must use date_shift.")
            if category is not PhiCategory.DATE and isinstance(
                policy.surrogate, DateShiftSurrogate
            ):
                raise ValueError("date_shift can only be used for DATE.")
        return self


class SurrogateRequest(StrictModel):
    event_id: str
    record_id: str
    entity_id: str
    category: PhiCategory
    original_text: str

    @field_validator("event_id", "record_id", "entity_id", "original_text")
    @classmethod
    def nonempty_text(cls, value: str) -> str:
        if not value:
            raise ValueError("Surrogate request fields cannot be empty.")
        return value


class SurrogateResult(StrictModel):
    assignment_id: str
    method: Literal["faker", "custom_list"]
    category: PhiCategory
    consistency: ConsistencyScope
    scope_key_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    container_key_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidates: tuple[str, ...] = Field(min_length=1, exclude=True)
    pool_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @property
    def surrogate_text(self) -> str:
        return self.candidates[0]
