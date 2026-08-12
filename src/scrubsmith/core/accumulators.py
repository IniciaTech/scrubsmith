"""Bounded accumulators for streaming scan and verification."""

from __future__ import annotations

from scrubsmith.core.context import TransformationContext
from scrubsmith.core.findings_resolution import resolve_overlapping_findings
from scrubsmith.core.models import (
    Category,
    Confidence,
    Finding,
    ScanSummary,
    VerificationReport,
    VerificationStatus,
)
from scrubsmith.detectors.base import Detector


def is_high_risk(finding: Finding) -> bool:
    if finding.category == Category.SECRET:
        return finding.confidence == Confidence.HIGH
    if finding.category in (Category.CREDIT_CARD, Category.SPANISH_ID):
        return finding.confidence == Confidence.HIGH
    if finding.category == Category.EMAIL and finding.confidence == Confidence.HIGH:
        return True
    return finding.severity.value in ("critical", "high") and finding.confidence == Confidence.HIGH


class ScanAccumulator:
    """Incrementally aggregate scan findings with bounded memory."""

    def __init__(self) -> None:
        self.summary = ScanSummary()
        self._high_risk_findings = 0
        self._uncertain_findings = 0

    def add_finding(self, finding: Finding) -> None:
        self.summary.add_finding(finding)
        if is_high_risk(finding):
            self._high_risk_findings += 1
        elif finding.confidence in (Confidence.MEDIUM, Confidence.LOW):
            self._uncertain_findings += 1

    def add_pem_secret(self) -> None:
        """Record a multiline PEM/private-key block as a single secret finding."""
        self.summary.potential_secrets += 1
        self.summary.high_confidence += 1
        self.summary.critical_severity += 1
        self.summary.total_findings += 1
        self._high_risk_findings += 1

    @property
    def status(self) -> VerificationStatus:
        if self._high_risk_findings > 0:
            return VerificationStatus.FAIL
        if self._uncertain_findings > 0:
            return VerificationStatus.REVIEW_REQUIRED
        return VerificationStatus.PASS


class VerificationAccumulator:
    """Incrementally aggregate post-sanitization verification with bounded memory."""

    def __init__(
        self,
        context: TransformationContext | None = None,
        *,
        allowed_replacements: frozenset[str] | None = None,
    ) -> None:
        self._context = context
        self._static_allowed = allowed_replacements or frozenset()
        self.high_risk_findings = 0
        self.uncertain_findings = 0

    def _allowed_values(self) -> frozenset[str]:
        if self._context is not None:
            return self._context.generated_replacements
        return self._static_allowed

    def feed_segment(self, text: str, detectors: list[Detector]) -> None:
        """Detect in a segment, skip known generated replacements, aggregate counts."""
        segment_findings: list[Finding] = []
        for detector in detectors:
            segment_findings.extend(detector.detect(text))

        allowed = self._allowed_values()
        for finding in resolve_overlapping_findings(segment_findings):
            matched = text[finding.start : finding.end]
            if matched in allowed:
                continue
            if is_high_risk(finding):
                self.high_risk_findings += 1
            elif self._is_uncertain(finding):
                self.uncertain_findings += 1

    def _is_uncertain(self, finding: Finding) -> bool:
        if finding.confidence in (Confidence.MEDIUM, Confidence.LOW):
            return True
        return finding.category == Category.IP and finding.confidence == Confidence.HIGH

    def report(self) -> VerificationReport:
        if self.high_risk_findings > 0:
            status = VerificationStatus.FAIL
        elif self.uncertain_findings > 0:
            status = VerificationStatus.REVIEW_REQUIRED
        else:
            status = VerificationStatus.PASS

        return VerificationReport(
            status=status,
            high_risk_findings=self.high_risk_findings,
            uncertain_findings=self.uncertain_findings,
        )
