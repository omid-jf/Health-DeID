"""Minimal extension contracts for paid detector and validator backends."""

from __future__ import annotations

from abc import ABC, abstractmethod

from health_deid.models.backend import DetectionResult, ValidationResult


class PhiDetector(ABC):
    """One-call detector adapter; orchestration owns persistence."""

    @abstractmethod
    def detect(self, text: str) -> DetectionResult:
        raise NotImplementedError


class PhiValidator(ABC):
    """One automated audit of a de-identified record."""

    @abstractmethod
    def validate(
        self,
        *,
        original_text: str,
        deidentified_text: str,
    ) -> ValidationResult:
        raise NotImplementedError


__all__ = ["PhiDetector", "PhiValidator"]
