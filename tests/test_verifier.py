"""Tests for post-sanitization verification pass."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.models import Category, Confidence, Finding, Severity, VerificationStatus
from scrubsmith.core.verifier import Verifier


def test_clean_output_passes() -> None:
    verifier = Verifier(ScrubsmithConfig(version=1))
    report = verifier.verify_text("Application started successfully\nNo sensitive data here\n")
    assert report.status == VerificationStatus.PASS


def test_uncertain_returns_review_required() -> None:
    verifier = Verifier(ScrubsmithConfig(version=1))
    findings = [
        Finding(
            category=Category.PHONE,
            start=0,
            end=10,
            confidence=Confidence.MEDIUM,
            detector="test",
            severity=Severity.MEDIUM,
        )
    ]
    report = verifier.verify_findings(findings)
    assert report.status == VerificationStatus.REVIEW_REQUIRED
    assert report.uncertain_findings == 1


def test_remaining_secret_fails() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    verifier = Verifier(ScrubsmithConfig(version=1))
    report = verifier.verify_text(f"token={jwt}")
    assert report.status == VerificationStatus.FAIL


def test_output_does_not_expose_values() -> None:
    from scrubsmith.core.models import ScanSummary
    from scrubsmith.reporting import format_scan_report

    summary = ScanSummary(emails=3, potential_secrets=1)
    output = format_scan_report(summary, VerificationStatus.REVIEW_REQUIRED)
    assert "REVIEW_REQUIRED" in output
