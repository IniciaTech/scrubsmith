"""Credit card detector with Luhn validation."""

from __future__ import annotations

import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector
from scrubsmith.detectors.validation import is_likely_technical_number, luhn_check

# Match groups of 4 digits separated by spaces or dashes, or continuous 13-19 digits
CREDIT_CARD_PATTERN = re.compile(
    r"(?<![\d])"
    r"("
    r"(?:\d{4}[\s-]?){3}\d{1,7}"  # grouped format
    r"|"
    r"\d{13,19}"  # continuous
    r")"
    r"(?![\d])"
)


class CreditCardDetector(RegexDetector):
    """Detect credit card numbers passing Luhn validation."""

    category = Category.CREDIT_CARD
    name = "generic.credit_card"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in CREDIT_CARD_PATTERN.finditer(text):
            if is_likely_technical_number(text, match.start(1), match.end(1)):
                continue
            candidate = match.group(1)
            digits = re.sub(r"\D", "", candidate)
            if not luhn_check(digits):
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
        return findings
