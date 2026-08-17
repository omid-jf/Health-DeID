from __future__ import annotations

import pytest
from pydantic import ValidationError

from health_deid.models.input import EntityIdConfig, EntityIdSource


def test_entity_id_can_come_from_an_explicit_column() -> None:
    config = EntityIdConfig(source="column", column=" patient_id ")

    assert config.source is EntityIdSource.COLUMN
    assert config.column == "patient_id"
    assert config.source_column(record_id_column="note_id") == "patient_id"


def test_entity_id_can_explicitly_reuse_record_id() -> None:
    config = EntityIdConfig(source="record_id", column=None)

    assert config.source is EntityIdSource.RECORD_ID
    assert config.column is None
    assert config.source_column(record_id_column="note_id") == "note_id"


def test_entity_id_column_source_requires_a_column() -> None:
    with pytest.raises(ValidationError, match="column is required"):
        EntityIdConfig(source="column")


def test_record_id_source_forbids_a_column() -> None:
    with pytest.raises(ValidationError, match="must be omitted"):
        EntityIdConfig(source="record_id", column="patient_id")


def test_entity_id_column_cannot_be_blank() -> None:
    with pytest.raises(ValidationError, match="cannot be blank"):
        EntityIdConfig(source="column", column=" ")
