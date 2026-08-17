from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Protocol


class SecretResolver(Protocol):
    def resolve(self, reference: str) -> bytes: ...


class MappingSecretResolver:
    def __init__(self, secrets: Mapping[str, str | bytes]) -> None:
        self._secrets = dict(secrets)

    def resolve(self, reference: str) -> bytes:
        try:
            value = self._secrets[reference]
        except KeyError as exc:
            raise KeyError(f"No secret is configured for reference {reference!r}.") from exc
        encoded = value.encode("utf-8") if isinstance(value, str) else value
        if not encoded:
            raise ValueError(f"Secret reference {reference!r} resolved to an empty value.")
        return encoded


class EnvironmentSecretResolver:
    def resolve(self, reference: str) -> bytes:
        if reference.startswith("literal:"):
            value = reference.removeprefix("literal:")
            if not value:
                raise ValueError("Embedded consistency keys cannot be empty.")
            return value.encode("utf-8")
        environment_value = os.environ.get(reference)
        if environment_value is None:
            raise KeyError(f"Environment variable {reference!r} is not set.")
        if not environment_value:
            raise ValueError(f"Environment variable {reference!r} is empty.")
        return environment_value.encode("utf-8")
