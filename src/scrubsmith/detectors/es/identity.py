"""Spanish DNI and NIE identity detector."""

from __future__ import annotations

import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector
from scrubsmith.detectors.validation import validate_spanish_id

DNI_PATTERN = re.compile(
    r"(?<![\dA-Z])"
    r"(\d{8}[\s-]?[A-Z])"
    r"(?![\dA-Z])",
    re.IGNORECASE,
)

NIE_PATTERN = re.compile(
    r"(?<![\dA-Z])"
    r"([XYZ]\d{7}[\s-]?[A-Z])"
    r"(?![\dA-Z])",
    re.IGNORECASE,
)


class SpanishIdentityDetector(RegexDetector):
    """Detect validated Spanish DNI and NIE identifiers."""

    category = Category.SPANISH_ID
    name = "es.identity"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in (DNI_PATTERN, NIE_PATTERN):
            for match in pattern.finditer(text):
                candidate = match.group(1)
                if not validate_spanish_id(candidate):
                    continue
                findings.append(
                    Finding(
                        category=self.category,
                        start=match.start(1),
                        end=match.end(1),
                        confidence=Confidence.HIGH,
                        detector=self.name,
                        severity=Severity.HIGH,
                    )
                )
        return self.merge_non_overlapping(findings)
