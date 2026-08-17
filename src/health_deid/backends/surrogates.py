"""Synthetic replacements backed by Faker or a user-provided list."""

from __future__ import annotations

import hashlib
import hmac
from typing import Literal

from faker import Faker

from health_deid.core.ids import build_content_id
from health_deid.core.secret_refs import SecretResolver
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.policy import (
    ConsistencyScope,
    CustomListSurrogate,
    FakerSurrogate,
    SurrogateRequest,
    SurrogateResult,
)


def generate_surrogate(
    request: SurrogateRequest,
    policy: FakerSurrogate | CustomListSurrogate,
    *,
    secrets: SecretResolver,
) -> SurrogateResult:
    """Build deterministic candidates; persistence chooses the first unused value."""

    secret = secrets.resolve(policy.secret_reference)
    scope_key = _scope_key(request, policy.consistency)
    container_key = _container_key(request, policy.consistency)
    digest = hmac.new(secret, scope_key.encode(), hashlib.sha256).digest()
    scope_hmac = hmac.new(secret, ("scope\0" + scope_key).encode(), hashlib.sha256).hexdigest()
    container_hmac = hmac.new(
        secret, ("container\0" + container_key).encode(), hashlib.sha256
    ).hexdigest()

    if isinstance(policy, CustomListSurrogate):
        start = int.from_bytes(digest[:8], "big") % len(policy.values)
        candidates = tuple(
            policy.values[(start + index) % len(policy.values)]
            for index in range(len(policy.values))
        )
        pool_hash = hashlib.sha256("\n".join(policy.values).encode()).hexdigest()
        method: Literal["faker", "custom_list"] = "custom_list"
    else:
        candidates = _faker_candidates(request.category, digest)
        pool_hash = None
        method = "faker"

    return SurrogateResult(
        assignment_id=build_content_id(
            "surrogate-assignment", request.category.value, method, scope_hmac
        ),
        method=method,
        category=request.category,
        consistency=policy.consistency,
        scope_key_hmac=scope_hmac,
        container_key_hmac=container_hmac,
        candidates=candidates,
        pool_sha256=pool_hash,
    )


def _scope_key(request: SurrogateRequest, consistency: ConsistencyScope) -> str:
    normalized = " ".join(request.original_text.casefold().split())
    prefix = f"health-deid/surrogate/v2\0{request.category.value}\0{consistency.value}\0"
    if consistency is ConsistencyScope.OCCURRENCE:
        return prefix + request.event_id
    if consistency is ConsistencyScope.RECORD:
        return prefix + request.record_id + "\0" + normalized
    return prefix + request.entity_id + "\0" + normalized


def _container_key(request: SurrogateRequest, consistency: ConsistencyScope) -> str:
    scope = request.entity_id if consistency is ConsistencyScope.ENTITY else request.record_id
    return f"health-deid/surrogate-container/v2\0{request.category.value}\0{scope}"


def _faker_candidates(category: PhiCategory, digest: bytes) -> tuple[str, ...]:
    fake = Faker("en_US")
    values: list[str] = []
    for counter in range(128):
        seed = int.from_bytes(
            hashlib.sha256(digest + counter.to_bytes(2, "big")).digest()[:8], "big"
        )
        fake.seed_instance(seed)
        value = str(_faker_value(fake, category)).strip()
        if value and value not in values:
            values.append(value)
    if not values:
        raise ValueError(f"Faker could not generate a value for {category.value}.")
    return tuple(values)


def _faker_value(fake: Faker, category: PhiCategory) -> object:
    providers = {
        PhiCategory.NAME: fake.name,
        PhiCategory.AGE: lambda: fake.random_int(min=1, max=89),
        PhiCategory.LOCATION: fake.address,
        PhiCategory.PHONE_OR_FAX: fake.phone_number,
        PhiCategory.EMAIL: fake.email,
        PhiCategory.URL: fake.url,
        PhiCategory.IP_ADDRESS: fake.ipv4,
        PhiCategory.PROFESSION: fake.job,
    }
    provider = providers.get(category, fake.uuid4)
    return provider()


__all__ = ["generate_surrogate"]
