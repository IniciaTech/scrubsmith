"""Tests for scan and sanitization report formatting."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.models import (
    SanitizationReport,
    SanitizationStats,
    ScanSummary,
    VerificationReport,
    VerificationStatus,
)
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.reporting import format_sanitization_report, format_scan_report

SCAN_CATEGORY_LABELS = (
    "Emails:",
    "Phone numbers:",
    "Spanish DNI/NIE:",
    "IP addresses:",
    "IBAN:",
    "Credit cards:",
    "Potential secrets:",
    "Total findings:",
)


def test_scan_report_lists_every_category_counter() -> None:
    summary = ScanSummary(
        emails=1,
        phone_numbers=2,
        spanish_dni_nie=3,
        ip_addresses=4,
        ibans=5,
        credit_cards=6,
        potential_secrets=7,
        total_findings=28,
    )
    output = format_scan_report(summary, VerificationStatus.REVIEW_REQUIRED)
    for label in SCAN_CATEGORY_LABELS:
        assert label in output
    assert "Total findings:          28" in output


def test_scan_report_total_reconciles_with_category_sum() -> None:
    summary = ScanSummary(
        emails=104,
        phone_numbers=0,
        spanish_dni_nie=0,
        ip_addresses=28752,
        ibans=0,
        credit_cards=44,
        potential_secrets=2,
        total_findings=104 + 28752 + 44 + 2,
    )
    output = format_scan_report(summary, VerificationStatus.FAIL)
    assert "Credit cards:            44" in output
    assert f"Total findings:          {summary.total_findings}" in output


def test_sanitization_report_shows_strategy_based_counters() -> None:
    report = SanitizationReport(
        stats=SanitizationStats(
            lines_processed=10,
            values_transformed=5,
            pii_pseudonymized=3,
            sensitive_values_redacted=1,
            secrets_redacted=2,
        ),
        verification=VerificationReport(status=VerificationStatus.PASS),
    )
    output = format_sanitization_report(report)
    assert "PII pseudonymized:" in output
    assert "Sensitive values redacted:" in output
    assert "Secrets redacted:" in output


def test_credit_card_redaction_counts_as_sensitive_not_pii() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config)
    _, stats = sanitizer.sanitize_text("card=4111111111111111\n")
    assert stats.values_transformed == 1
    assert stats.sensitive_values_redacted == 1
    assert stats.pii_pseudonymized == 0
    assert stats.secrets_redacted == 0


def test_email_pseudonymization_counts_as_pii() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config)
    _, stats = sanitizer.sanitize_text("user@example.org login\n")
    assert stats.values_transformed == 1
    assert stats.pii_pseudonymized == 1
    assert stats.sensitive_values_redacted == 0


def test_secret_counts_as_secrets_redacted() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config)
    _, stats = sanitizer.sanitize_text("password=SuperSecret123\n")
    assert stats.values_transformed == 1
    assert stats.secrets_redacted == 1
    assert stats.pii_pseudonymized == 0
    assert stats.sensitive_values_redacted == 0
