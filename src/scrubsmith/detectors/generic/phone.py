"""Phone number detector with Spanish and international support."""

from __future__ import annotations

import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector
from scrubsmith.detectors.validation import (
    has_phone_field_context,
    is_after_list_delimiter,
    is_embedded_in_alphanumeric_token,
    is_likely_technical_number,
    is_non_phone_structured_field_value,
    is_valid_spanish_local_digits,
)

# Candidate extraction: optional country prefix plus a 9-digit Spanish local number.
SPANISH_PHONE_CANDIDATE = re.compile(
    r"(?<![\d])"
    r"(?P<raw>"
    r"(?:(?:\+34|0034)[\s.-]?)?"
    r"[6-9]\d{2}[\s.-]?\d{3}[\s.-]?\d{3}"
    r")"
    r"(?![\d])"
)

# International numbers require an explicit leading + prefix.
INTERNATIONAL_PHONE_CANDIDATE = re.compile(
    r"(?<![\d+])"
    r"(?P<raw>"
    r"\+[1-9]\d{0,2}(?:[\s.-]+\d{1,6}){2,5}"
    r")"
    r"(?![\d])"
)

# Explicit phone-related fields may contain bare digit sequences without a + prefix.
PHONE_FIELD_CANDIDATE = re.compile(
    r"(?i)"
    r"(?:phone|telephone|mobile|tel|mobile_phone|phone_number)\s*[:=]\s*"
    r"(?P<raw>\d{9,15})"
    r"(?![\d])"
)


class PhoneDetector(RegexDetector):
    """Detect Spanish and international phone numbers with token-boundary validation."""

    category = Category.PHONE
    name = "generic.phone"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_spanish(text))
        findings.extend(self._detect_international(text))
        findings.extend(self._detect_phone_field(text))
        return self.merge_non_overlapping(findings)

    def _detect_spanish(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in SPANISH_PHONE_CANDIDATE.finditer(text):
            start = match.start("raw")
            end = match.end("raw")
            raw = match.group("raw")

            if is_likely_technical_number(text, start, end):
                continue
            if is_embedded_in_alphanumeric_token(text, start, end):
                continue

            digits = self._normalize_spanish_digits(raw)
            if not is_valid_spanish_local_digits(digits):
                continue

            confidence = self._spanish_confidence(text, start, raw)
            if confidence == Confidence.MEDIUM:
                if is_after_list_delimiter(text, start):
                    continue
                if is_non_phone_structured_field_value(text, start):
                    continue

            findings.append(
                Finding(
                    category=self.category,
                    start=start,
                    end=end,
                    confidence=confidence,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                )
            )
        return findings

    def _detect_international(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in INTERNATIONAL_PHONE_CANDIDATE.finditer(text):
            start = match.start("raw")
            end = match.end("raw")
            raw = match.group("raw")

            if is_likely_technical_number(text, start, end):
                continue
            if is_embedded_in_alphanumeric_token(text, start, end):
                continue

            digits = re.sub(r"\D", "", raw)
            if not 10 <= len(digits) <= 15:
                continue
            # Skip +34 numbers handled by the Spanish path.
            if digits.startswith("34") and len(digits) == 11:
                continue

            findings.append(
                Finding(
                    category=self.category,
                    start=start,
                    end=end,
                    confidence=Confidence.HIGH,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                )
            )
        return findings

    def _detect_phone_field(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in PHONE_FIELD_CANDIDATE.finditer(text):
            start = match.start("raw")
            end = match.end("raw")
            raw = match.group("raw")

            if is_likely_technical_number(text, start, end):
                continue
            if is_embedded_in_alphanumeric_token(text, start, end):
                continue

            digits = re.sub(r"\D", "", raw)
            if not 9 <= len(digits) <= 15:
                continue
            if len(digits) == 9 and not is_valid_spanish_local_digits(digits):
                continue

            findings.append(
                Finding(
                    category=self.category,
                    start=start,
                    end=end,
                    confidence=Confidence.HIGH,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                )
            )
        return findings

    @staticmethod
    def _normalize_spanish_digits(raw: str) -> str:
        digits = re.sub(r"\D", "", raw)
        if digits.startswith("0034"):
            return digits[4:]
        if len(digits) == 11 and digits.startswith("34"):
            return digits[2:]
        return digits

    @staticmethod
    def _spanish_confidence(text: str, start: int, raw: str) -> Confidence:
        if re.search(r"(?:\+34|0034)", raw):
            return Confidence.HIGH
        if re.search(r"[\s.-]", raw):
            return Confidence.HIGH
        if has_phone_field_context(text, start):
            return Confidence.HIGH
        return Confidence.MEDIUM
