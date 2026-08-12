"""Email address detector."""

from __future__ import annotations

import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector

# Conservative email pattern - requires TLD of at least 2 chars
EMAIL_PATTERN = re.compile(
    r"(?<![\w.@+-])"  # not preceded by email chars
    r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    r"(?![\w.-])",
)


class EmailDetector(RegexDetector):
    """Detect email addresses with high confidence."""

    category = Category.EMAIL
    name = "generic.email"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in EMAIL_PATTERN.finditer(text):
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
