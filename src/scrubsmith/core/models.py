"""Core data models for detection, transformation, and verification."""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Literal

from pydantic import BaseModel


class Confidence(StrEnum):
    """Detection confidence level."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(StrEnum):
    """Finding severity for prioritization and verification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(StrEnum):
    """Category of detected sensitive data."""

    SECRET = "secret"
    EMAIL = "email"
    PHONE = "phone"
    IP = "ip"
    IBAN = "iban"
    SPANISH_ID = "spanish_id"
    CREDIT_CARD = "credit_card"


class Strategy(StrEnum):
    """Transformation strategy for a finding category."""

    REDACT = "redact"
    FAKE = "fake"
    HASH = "hash"


class VerificationStatus(StrEnum):
    """Post-sanitization verification pass outcome."""

    PASS = "PASS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAIL = "FAIL"


class Finding(BaseModel):
    """A detected sensitive value span in source text."""

    model_config = {"frozen": True}

    category: Category
    start: int
    end: int
    confidence: Confidence
    detector: str
    severity: Severity


class ScanSummary(BaseModel):
    """Aggregated scan counts without exposing matched values."""

    total_findings: int = 0
    emails: int = 0
    phone_numbers: int = 0
    spanish_dni_nie: int = 0
    ip_addresses: int = 0
    ibans: int = 0
    credit_cards: int = 0
    potential_secrets: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    critical_severity: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0

    def add_finding(self, finding: Finding) -> None:
        """Increment counters for a finding."""
        self.total_findings += 1
        if finding.category == Category.EMAIL:
            self.emails += 1
        elif finding.category == Category.PHONE:
            self.phone_numbers += 1
        elif finding.category == Category.SPANISH_ID:
            self.spanish_dni_nie += 1
        elif finding.category == Category.IP:
            self.ip_addresses += 1
        elif finding.category == Category.IBAN:
            self.ibans += 1
        elif finding.category == Category.CREDIT_CARD:
            self.credit_cards += 1
        elif finding.category == Category.SECRET:
            self.potential_secrets += 1

        if finding.confidence == Confidence.HIGH:
            self.high_confidence += 1
        elif finding.confidence == Confidence.MEDIUM:
            self.medium_confidence += 1
        else:
            self.low_confidence += 1

        if finding.severity == Severity.CRITICAL:
            self.critical_severity += 1
        elif finding.severity == Severity.HIGH:
            self.high_severity += 1
        elif finding.severity == Severity.MEDIUM:
            self.medium_severity += 1
        else:
            self.low_severity += 1


class SanitizationStats(BaseModel):
    """Statistics from a sanitization run."""

    lines_processed: int = 0
    values_transformed: int = 0
    pii_pseudonymized: int = 0
    sensitive_values_redacted: int = 0
    secrets_redacted: int = 0
    incomplete_pem_blocks: int = 0
    oversized_pem_blocks: int = 0


class VerificationReport(BaseModel):
    """Result of the post-sanitization verification pass."""

    status: VerificationStatus
    high_risk_findings: int = 0
    uncertain_findings: int = 0


class SanitizationReport(BaseModel):
    """Complete sanitization report without sensitive values."""

    stats: SanitizationStats
    verification: VerificationReport


class ExitCode(IntEnum):
    """CLI exit codes for CI integration."""

    SUCCESS = 0
    REVIEW_REQUIRED = 1
    FAIL = 2
    ERROR = 3


def verification_to_exit_code(status: VerificationStatus) -> ExitCode:
    """Map verification status to CLI exit code."""
    if status == VerificationStatus.PASS:
        return ExitCode.SUCCESS
    if status == VerificationStatus.REVIEW_REQUIRED:
        return ExitCode.REVIEW_REQUIRED
    return ExitCode.FAIL


ReportFormat = Literal["json", "text"]
