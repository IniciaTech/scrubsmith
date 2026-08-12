"""Tests for email detector and transformation."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import RESERVED_EMAIL_DOMAIN, TransformationContext
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.detectors.generic.email import EmailDetector


def test_valid_email_detected() -> None:
    detector = EmailDetector()
    text = "Contact user@company.org for help"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "user@company.org"


def test_multiple_emails() -> None:
    detector = EmailDetector()
    text = "From a@test.com to b@test.com"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_repeated_email_consistent_replacement() -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"test-seed")
    sanitizer = Sanitizer(config, context=context)
    text = "a@test.com and a@test.com again"
    result, _ = sanitizer.sanitize_text(text)
    emails = [part for part in result.split() if RESERVED_EMAIL_DOMAIN in part]
    assert len(emails) == 2
    assert emails[0] == emails[1]


def test_malformed_string_no_false_email() -> None:
    detector = EmailDetector()
    text = "not-an-email@ or @missing-local.com"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_reserved_example_domain_is_detected_in_strict_scan() -> None:
    detector = EmailDetector()
    text = "safe@example.test and safe@example.com"
    findings = detector.detect(text)
    assert len(findings) == 2


def test_generated_domain_is_reserved() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"s"))
    result, _ = sanitizer.sanitize_text("hello@world.io")
    assert RESERVED_EMAIL_DOMAIN in result
    assert "world.io" not in result
