"""Base detector protocol and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from scrubsmith.core.findings_resolution import resolve_overlapping_findings
from scrubsmith.core.models import Category, Finding


class Detector(Protocol):
    """Protocol for sensitive-data detectors."""

    category: Category
    name: str

    def detect(self, text: str) -> list[Finding]:
        """Return findings for sensitive spans in text."""
        ...


class RegexDetector(ABC):
    """Base class for regex-based detectors."""

    category: Category
    name: str

    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        """Detect sensitive spans."""
        ...

    @staticmethod
    def merge_non_overlapping(findings: list[Finding]) -> list[Finding]:
        """Resolve overlaps within a single detector's findings."""
        return resolve_overlapping_findings(findings)
