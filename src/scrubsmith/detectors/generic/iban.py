"""IBAN detector with checksum validation."""

from __future__ import annotations

import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector
from scrubsmith.detectors.validation import validate_iban

IBAN_PATTERN = re.compile(
    r"(?<![A-Z0-9])"
    r"([A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?[\dA-Z\s]{8,24})"
    r"(?![A-Z0-9])",
    re.IGNORECASE,
)


class IBANDetector(RegexDetector):
    """Detect IBAN identifiers with checksum validation."""

    category = Category.IBAN
    name = "generic.iban"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in IBAN_PATTERN.finditer(text):
            candidate = match.group(1)
            normalized = re.sub(r"\s", "", candidate).upper()
            if not validate_iban(normalized):
                continue
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(1),
                    end=match.end(1),
                    confidence=Confidence.HIGH,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                )
            )
        return findings
