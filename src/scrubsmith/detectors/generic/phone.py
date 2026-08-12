"""Phone number detector with Spanish and international support."""

from __future__ import annotations

import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector
from scrubsmith.detectors.validation import is_likely_technical_number

# Spanish mobile: 6xx, 7xx; landline: 8xx, 9xx (9 digits after optional +34)
SPANISH_PHONE_PATTERN = re.compile(
    r"(?<![\d])"
    r"(?:"
    r"(?:\+34[\s.-]?)?"  # optional country code
    r"(?:[6-9]\d{2}[\s.-]?\d{3}[\s.-]?\d{3})"  # 9 digit Spanish number
    r")"
    r"(?![\d])"
)

# International E.164-ish: + followed by 10-14 digits with reasonable separators
INTERNATIONAL_PHONE_PATTERN = re.compile(
    r"(?<![\d+])"
    r"(\+[1-9]\d{0,2}[\s.-]?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{2,4}(?:[\s.-]?\d{1,4})?)"
    r"(?![\d])"
)


class PhoneDetector(RegexDetector):
    """Detect Spanish and high-confidence international phone numbers."""

    category = Category.PHONE
    name = "generic.phone"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_spanish(text))
        findings.extend(self._detect_international(text))
        return self.merge_non_overlapping(findings)

    def _detect_spanish(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in SPANISH_PHONE_PATTERN.finditer(text):
            if is_likely_technical_number(text, match.start(), match.end()):
                continue
            digits = re.sub(r"\D", "", match.group())
            # Must have 9 digits (with or without 34 prefix)
            if len(digits) == 11 and digits.startswith("34"):
                digits = digits[2:]
            if len(digits) != 9:
                continue
            if digits[0] not in "6789":
                continue
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(),
                    end=match.end(),
                    confidence=Confidence.HIGH,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                )
            )
        return findings

    def _detect_international(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in INTERNATIONAL_PHONE_PATTERN.finditer(text):
            if is_likely_technical_number(text, match.start(), match.end()):
                continue
            digits = re.sub(r"\D", "", match.group(1))
            # Skip if already matched as Spanish
            if 10 <= len(digits) <= 15:
                findings.append(
                    Finding(
                        category=self.category,
                        start=match.start(1),
                        end=match.end(1),
                        confidence=Confidence.MEDIUM,
                        detector=self.name,
                        severity=Severity.MEDIUM,
                    )
                )
        return findings
