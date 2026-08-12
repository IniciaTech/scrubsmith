"""Tests for overlapping finding resolution."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import REDACTED_PLACEHOLDER, TransformationContext
from scrubsmith.core.findings_resolution import resolve_overlapping_findings
from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.detectors.generic.secrets import SecretsDetector

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_password_assignment_wins_over_embedded_email() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"overlap"))
    text = "password=john@company.org"
    sanitized = sanitizer.sanitize_line(text)
    assert sanitized == f"password={REDACTED_PLACEHOLDER}"
    assert "example.com" not in sanitized
    assert "@" not in sanitized.replace(f"password={REDACTED_PLACEHOLDER}", "")


def test_bearer_jwt_collapses_to_single_secret_replacement() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"overlap"))
    text = f"Authorization: Bearer {JWT_SAMPLE}"
    findings = sanitizer.detect(text)
    secret_findings = [f for f in findings if f.category == Category.SECRET]
    assert len(secret_findings) == 1
    sanitized = sanitizer.sanitize_line(text)
    assert JWT_SAMPLE not in sanitized
    assert sanitized.count(REDACTED_PLACEHOLDER) == 1


def test_resolve_prefers_secret_over_email() -> None:
    email = Finding(
        category=Category.EMAIL,
        start=9,
        end=26,
        confidence=Confidence.HIGH,
        detector="email",
        severity=Severity.MEDIUM,
    )
    secret = Finding(
        category=Category.SECRET,
        start=9,
        end=26,
        confidence=Confidence.HIGH,
        detector="password",
        severity=Severity.CRITICAL,
    )
    resolved = resolve_overlapping_findings([email, secret])
    assert len(resolved) == 1
    assert resolved[0].category == Category.SECRET


def test_resolve_non_overlapping_keeps_both() -> None:
    email = Finding(
        category=Category.EMAIL,
        start=0,
        end=10,
        confidence=Confidence.HIGH,
        detector="email",
        severity=Severity.MEDIUM,
    )
    phone = Finding(
        category=Category.PHONE,
        start=20,
        end=30,
        confidence=Confidence.HIGH,
        detector="phone",
        severity=Severity.MEDIUM,
    )
    resolved = resolve_overlapping_findings([email, phone])
    assert len(resolved) == 2


def test_secrets_detector_overlap_resolution_is_deterministic() -> None:
    detector = SecretsDetector()
    text = f"Authorization: Bearer {JWT_SAMPLE}"
    findings = detector.detect(text)
    resolved = resolve_overlapping_findings(findings)
    assert len(resolved) >= 1
    assert all(f.category == Category.SECRET for f in resolved)
