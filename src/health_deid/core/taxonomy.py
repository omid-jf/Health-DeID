from __future__ import annotations

from enum import StrEnum

TAXONOMY_VERSION = "1"


class PhiCategory(StrEnum):
    """Backend-independent categories used by findings, policy, and rendering."""

    NAME = "NAME"
    DATE = "DATE"
    AGE = "AGE"
    ID = "ID"
    LOCATION = "LOCATION"
    PHONE_OR_FAX = "PHONE_OR_FAX"
    EMAIL = "EMAIL"
    URL = "URL"
    IP_ADDRESS = "IP_ADDRESS"
    BIOMETRIC = "BIOMETRIC"
    PHOTO = "PHOTO"
    OTHER_ID = "OTHER_ID"
    PROFESSION = "PROFESSION"
    UNMAPPED = "UNMAPPED"


class AwsComprehendPhiType(StrEnum):
    """Native entity types returned by AWS Comprehend Medical DetectPHI."""

    NAME = "NAME"
    DATE = "DATE"
    AGE = "AGE"
    ID = "ID"
    ADDRESS = "ADDRESS"
    PHONE_OR_FAX = "PHONE_OR_FAX"
    EMAIL = "EMAIL"
    URL = "URL"
    PROFESSION = "PROFESSION"


AWS_COMPREHEND_TO_PHI_CATEGORY: dict[AwsComprehendPhiType, PhiCategory] = {
    AwsComprehendPhiType.NAME: PhiCategory.NAME,
    AwsComprehendPhiType.DATE: PhiCategory.DATE,
    AwsComprehendPhiType.AGE: PhiCategory.AGE,
    AwsComprehendPhiType.ID: PhiCategory.ID,
    AwsComprehendPhiType.ADDRESS: PhiCategory.LOCATION,
    AwsComprehendPhiType.PHONE_OR_FAX: PhiCategory.PHONE_OR_FAX,
    AwsComprehendPhiType.EMAIL: PhiCategory.EMAIL,
    AwsComprehendPhiType.URL: PhiCategory.URL,
    AwsComprehendPhiType.PROFESSION: PhiCategory.PROFESSION,
}


PHI_CATEGORY_TO_PLACEHOLDER: dict[PhiCategory, str] = {
    PhiCategory.NAME: "[R_NAME]",
    PhiCategory.DATE: "[R_DATE]",
    PhiCategory.AGE: "[R_AGE]",
    PhiCategory.ID: "[R_ID]",
    PhiCategory.LOCATION: "[R_LOC]",
    PhiCategory.PHONE_OR_FAX: "[R_PHONE_OR_FAX]",
    PhiCategory.EMAIL: "[R_EMAIL]",
    PhiCategory.URL: "[R_URL]",
    PhiCategory.IP_ADDRESS: "[R_IP]",
    PhiCategory.BIOMETRIC: "[R_BIO]",
    PhiCategory.PHOTO: "[R_PHO]",
    PhiCategory.OTHER_ID: "[R_OID]",
    PhiCategory.PROFESSION: "[R_PROFESSION]",
    PhiCategory.UNMAPPED: "[R_UNMAPPED]",
}


PLACEHOLDER_TO_PHI_CATEGORY: dict[str, PhiCategory] = {
    placeholder: category for category, placeholder in PHI_CATEGORY_TO_PLACEHOLDER.items()
}


DETECTOR_PHI_CATEGORIES: tuple[PhiCategory, ...] = tuple(
    category for category in PhiCategory if category is not PhiCategory.UNMAPPED
)

LLM_PHI_CATEGORIES: tuple[PhiCategory, ...] = DETECTOR_PHI_CATEGORIES


def map_aws_phi_type(backend_type: str) -> PhiCategory:
    """Map an AWS type without silently dropping a future or malformed value."""

    try:
        aws_type = AwsComprehendPhiType(backend_type)
    except ValueError:
        return PhiCategory.UNMAPPED

    return AWS_COMPREHEND_TO_PHI_CATEGORY[aws_type]
