"""IPv4 and IPv6 address detector."""

from __future__ import annotations

import ipaddress
import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector
from scrubsmith.detectors.validation import is_dotted_software_version

IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?![\d.])"
)

IPV6_PATTERN = re.compile(
    r"(?<![:\w])"
    r"("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)"
    r")"
    r"(?![:\w])"
)


class IPDetector(RegexDetector):
    """Detect IPv4 and IPv6 addresses."""

    category = Category.IP
    name = "generic.ip"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_ipv4(text))
        findings.extend(self._detect_ipv6(text))
        return self.merge_non_overlapping(findings)

    def _detect_ipv4(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in IPV4_PATTERN.finditer(text):
            candidate = match.group(1)
            # Skip if followed by port
            end = match.end(1)
            if end < len(text) and text[end : end + 1] == ":":
                continue
            try:
                ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            parts = candidate.split(".")
            if any(int(p) > 255 for p in parts):
                continue
            if is_dotted_software_version(text, match.start(1)):
                continue
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(1),
                    end=match.end(1),
                    confidence=Confidence.HIGH,
                    detector=self.name,
                    severity=Severity.LOW,
                )
            )
        return findings

    def _detect_ipv6(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in IPV6_PATTERN.finditer(text):
            candidate = match.group(1)
            try:
                ipaddress.IPv6Address(candidate)
            except ipaddress.AddressValueError:
                continue
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(1),
                    end=match.end(1),
                    confidence=Confidence.HIGH,
                    detector=self.name,
                    severity=Severity.LOW,
                )
            )
        return findings
