from __future__ import annotations

from health_deid.core.taxonomy import (
    AWS_COMPREHEND_TO_PHI_CATEGORY,
    DETECTOR_PHI_CATEGORIES,
    PHI_CATEGORY_TO_PLACEHOLDER,
    PLACEHOLDER_TO_PHI_CATEGORY,
    AwsComprehendPhiType,
    PhiCategory,
    map_aws_phi_type,
)


def test_every_aws_type_maps_to_a_canonical_category() -> None:
    assert set(AWS_COMPREHEND_TO_PHI_CATEGORY) == set(AwsComprehendPhiType)
    assert map_aws_phi_type("ADDRESS") is PhiCategory.LOCATION
    assert map_aws_phi_type("FUTURE_AWS_TYPE") is PhiCategory.UNMAPPED


def test_every_canonical_category_has_a_unique_placeholder() -> None:
    assert set(PHI_CATEGORY_TO_PLACEHOLDER) == set(PhiCategory)
    assert len(set(PHI_CATEGORY_TO_PLACEHOLDER.values())) == len(PhiCategory)
    assert PLACEHOLDER_TO_PHI_CATEGORY["[R_LOC]"] is PhiCategory.LOCATION


def test_detector_categories_exclude_only_unmapped() -> None:
    assert PhiCategory.UNMAPPED not in DETECTOR_PHI_CATEGORIES
    assert set(DETECTOR_PHI_CATEGORIES) == set(PhiCategory).difference({PhiCategory.UNMAPPED})
