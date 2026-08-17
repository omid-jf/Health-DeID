from __future__ import annotations

import hashlib

import pytest

import health_deid.backends.surrogates as surrogate_module
from health_deid.backends.surrogates import generate_surrogate
from health_deid.core.secret_refs import EnvironmentSecretResolver, MappingSecretResolver
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.policy import (
    ConsistencyScope,
    CustomListSurrogate,
    FakerSurrogate,
    SurrogateRequest,
)


def _request(
    *,
    event_id: str = "event-1",
    record_id: str = "record-1",
    entity_id: str = "entity-1",
    original_text: str = "Jane Smith",
    category: PhiCategory = PhiCategory.NAME,
) -> SurrogateRequest:
    return SurrogateRequest(
        event_id=event_id,
        record_id=record_id,
        entity_id=entity_id,
        category=category,
        original_text=original_text,
    )


@pytest.mark.parametrize(
    ("scope", "same_updates", "different_updates"),
    [
        (
            ConsistencyScope.OCCURRENCE,
            {"record_id": "record-2", "entity_id": "entity-2", "original_text": "Alex"},
            {"event_id": "event-2"},
        ),
        (
            ConsistencyScope.RECORD,
            {"event_id": "event-2", "entity_id": "entity-2", "original_text": " JANE smith "},
            {"record_id": "record-2"},
        ),
        (
            ConsistencyScope.ENTITY,
            {"event_id": "event-2", "record_id": "record-2", "original_text": " JANE smith "},
            {"entity_id": "entity-2"},
        ),
    ],
)
def test_consistency_scopes_use_the_selected_container(
    scope: ConsistencyScope,
    same_updates: dict[str, str],
    different_updates: dict[str, str],
) -> None:
    policy = CustomListSurrogate(
        consistency=scope,
        values=["Alex", "Morgan", "Taylor"],
        secret_reference="key",
    )
    secrets = MappingSecretResolver({"key": "secret"})
    request = _request()
    first = generate_surrogate(request, policy, secrets=secrets)
    same = generate_surrogate(request.model_copy(update=same_updates), policy, secrets=secrets)
    different = generate_surrogate(
        request.model_copy(update=different_updates), policy, secrets=secrets
    )

    assert first.scope_key_hmac == same.scope_key_hmac
    assert first.scope_key_hmac != different.scope_key_hmac


def test_custom_list_is_deterministic_secret_keyed_and_rotatable() -> None:
    policy = CustomListSurrogate(
        values=["Alex", "Morgan", "Taylor"],
        secret_reference="key",
    )
    request = _request()
    first = generate_surrogate(
        request, policy, secrets=MappingSecretResolver({"key": "first-secret"})
    )
    repeated = generate_surrogate(
        request, policy, secrets=MappingSecretResolver({"key": "first-secret"})
    )
    changed = generate_surrogate(
        request, policy, secrets=MappingSecretResolver({"key": "second-secret"})
    )

    assert first == repeated
    assert first.surrogate_text in policy.values
    assert first.pool_sha256 == hashlib.sha256(b"Alex\nMorgan\nTaylor").hexdigest()
    assert first.scope_key_hmac != changed.scope_key_hmac
    assert "first-secret" not in first.model_dump_json()


@pytest.mark.parametrize(
    "category",
    [
        PhiCategory.NAME,
        PhiCategory.AGE,
        PhiCategory.LOCATION,
        PhiCategory.PHONE_OR_FAX,
        PhiCategory.EMAIL,
        PhiCategory.URL,
        PhiCategory.IP_ADDRESS,
        PhiCategory.PROFESSION,
        PhiCategory.ID,
    ],
)
def test_faker_generates_deterministic_candidates_for_supported_categories(
    category: PhiCategory,
) -> None:
    policy = FakerSurrogate(secret_reference="key")
    secrets = MappingSecretResolver({"key": "secret"})

    result = generate_surrogate(_request(category=category), policy, secrets=secrets)
    repeated = generate_surrogate(_request(category=category), policy, secrets=secrets)

    assert result == repeated
    assert result.method == "faker"
    assert result.surrogate_text
    assert len(result.candidates) >= 1


def test_secret_resolvers_reject_missing_or_empty_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="empty value"):
        MappingSecretResolver({"empty": b""}).resolve("empty")

    resolver = EnvironmentSecretResolver()
    assert resolver.resolve("literal:generated-key") == b"generated-key"
    with pytest.raises(ValueError, match="cannot be empty"):
        resolver.resolve("literal:")
    monkeypatch.delenv("HEALTH_DEID_TEST_SECRET", raising=False)
    with pytest.raises(KeyError, match="is not set"):
        resolver.resolve("HEALTH_DEID_TEST_SECRET")
    monkeypatch.setenv("HEALTH_DEID_TEST_SECRET", "")
    with pytest.raises(ValueError, match="is empty"):
        resolver.resolve("HEALTH_DEID_TEST_SECRET")
    monkeypatch.setenv("HEALTH_DEID_TEST_SECRET", "configured")
    assert resolver.resolve("HEALTH_DEID_TEST_SECRET") == b"configured"


def test_faker_reports_when_a_provider_cannot_generate_a_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(surrogate_module, "_faker_value", lambda fake, category: "")
    with pytest.raises(ValueError, match="could not generate"):
        generate_surrogate(
            _request(),
            FakerSurrogate(secret_reference="key"),
            secrets=MappingSecretResolver({"key": "secret"}),
        )
