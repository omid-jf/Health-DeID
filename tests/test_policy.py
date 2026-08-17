from __future__ import annotations

import pytest
from pydantic import ValidationError

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.policy import (
    CategoryPolicy,
    ConsistencyScope,
    CustomListSurrogate,
    DateShiftSurrogate,
    FakerSurrogate,
    GeneralizationStrategy,
    SurrogateRequest,
    SurrogateResult,
    TransformationAction,
    TransformationPolicy,
)


def _categories() -> dict[str, dict[str, object]]:
    return TransformationPolicy().model_dump(mode="json")["categories"]


def test_default_policy_is_complete() -> None:
    policy = TransformationPolicy()

    assert set(policy.categories) == set(PhiCategory)
    assert policy.categories[PhiCategory.DATE].generalization is GeneralizationStrategy.YEAR_ONLY
    assert policy.categories[PhiCategory.AGE].generalization is GeneralizationStrategy.AGE_90_PLUS
    assert policy.categories[PhiCategory.PROFESSION].action is TransformationAction.RETAIN


def test_policy_requires_every_category() -> None:
    categories = _categories()
    categories.pop("NAME")

    with pytest.raises(ValidationError, match="Category policy is missing: NAME"):
        TransformationPolicy(categories=categories)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"action": "generalize"}, "requires a strategy"),
        (
            {
                "action": "generalize",
                "generalization": "year_only",
                "surrogate": {"method": "faker", "secret_reference": "key"},
            },
            "cannot include a surrogate",
        ),
        ({"action": "retain", "generalization": "year_only"}, "only valid"),
        ({"action": "surrogate"}, "requires replacement settings"),
        (
            {
                "action": "redact",
                "surrogate": {"method": "faker", "secret_reference": "key"},
            },
            "only valid",
        ),
    ],
)
def test_category_action_contracts(payload: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CategoryPolicy.model_validate(payload)


def test_faker_and_custom_list_settings() -> None:
    faker = FakerSurrogate(
        consistency="record",
        secret_reference=" env:FAKER_KEY ",
    )
    custom = CustomListSurrogate(
        consistency="occurrence",
        values=[" Alpha ", "Beta"],
        secret_reference=" list-key ",
    )

    assert faker.consistency is ConsistencyScope.RECORD
    assert faker.secret_reference == "env:FAKER_KEY"
    assert custom.values == ["Alpha", "Beta"]
    assert custom.secret_reference == "list-key"

    for payload in ({"secret_reference": " "},):
        with pytest.raises(ValidationError, match="cannot be blank"):
            FakerSurrogate.model_validate(payload)
    for values in ([], [""], ["same", "same"]):
        with pytest.raises(ValidationError):
            CustomListSurrogate(values=values, secret_reference="key")
    with pytest.raises(ValidationError, match="cannot be blank"):
        CustomListSurrogate(values=["one"], secret_reference=" ")


def test_date_shift_settings_are_entity_scoped_and_nonzero() -> None:
    settings = DateShiftSurrogate(
        minimum_weeks=-26,
        maximum_weeks=26,
        secret_reference=" env:DATE_KEY ",
    )

    assert settings.consistency is ConsistencyScope.ENTITY
    assert settings.secret_reference == "env:DATE_KEY"
    with pytest.raises(ValidationError, match="cannot be blank"):
        DateShiftSurrogate(secret_reference=" ")
    with pytest.raises(ValidationError, match="cannot exceed"):
        DateShiftSurrogate(minimum_weeks=2, maximum_weeks=1, secret_reference="key")
    with pytest.raises(ValidationError, match="non-zero"):
        DateShiftSurrogate(minimum_weeks=0, maximum_weeks=0, secret_reference="key")
    with pytest.raises(ValidationError):
        DateShiftSurrogate(consistency="record", secret_reference="key")


def test_surrogate_method_must_match_category() -> None:
    date_categories = _categories()
    date_categories["DATE"] = {
        "action": "surrogate",
        "surrogate": {"method": "faker", "secret_reference": "key"},
    }
    with pytest.raises(ValidationError, match="DATE replacement must use date_shift"):
        TransformationPolicy(categories=date_categories)

    name_categories = _categories()
    name_categories["NAME"] = {
        "action": "surrogate",
        "surrogate": {"method": "date_shift", "secret_reference": "key"},
    }
    with pytest.raises(ValidationError, match="only be used for DATE"):
        TransformationPolicy(categories=name_categories)


@pytest.mark.parametrize(
    ("category", "strategy"),
    [("DATE", "age_90_plus"), ("AGE", "year_only"), ("NAME", "year_only")],
)
def test_generalization_strategy_must_match_category(category: str, strategy: str) -> None:
    categories = _categories()
    categories[category] = {"action": "generalize", "generalization": strategy}

    with pytest.raises(ValidationError, match=f"not valid for {category}"):
        TransformationPolicy(categories=categories)


def test_surrogate_request_and_result_contracts() -> None:
    with pytest.raises(ValidationError, match="cannot be empty"):
        SurrogateRequest(
            event_id="",
            record_id="r1",
            entity_id="e1",
            category="NAME",
            original_text="Jane",
        )

    result = SurrogateResult(
        assignment_id="a1",
        method="faker",
        category="NAME",
        consistency="entity",
        scope_key_hmac="a" * 64,
        container_key_hmac="b" * 64,
        candidates=("Alex", "Taylor"),
    )
    assert result.surrogate_text == "Alex"
