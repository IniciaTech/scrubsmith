"""Tests for phone number detector."""

from scrubsmith.detectors.generic.phone import PhoneDetector


def test_spanish_mobile() -> None:
    detector = PhoneDetector()
    findings = detector.detect("Call 612345678 for info")
    assert len(findings) == 1


def test_spanish_landline() -> None:
    detector = PhoneDetector()
    findings = detector.detect("Office 912345678")
    assert len(findings) == 1


def test_international_format() -> None:
    detector = PhoneDetector()
    findings = detector.detect("Contact +1 415 555 0100")
    assert len(findings) >= 1


def test_technical_numeric_not_phone() -> None:
    detector = PhoneDetector()
    # UUID-like or timestamp should not match
    findings = detector.detect("request_id=12345678901234567890")
    assert len(findings) == 0


def test_port_like_not_phone() -> None:
    detector = PhoneDetector()
    findings = detector.detect("connected to 127.0.0.1:8080")
    phone_findings = [f for f in findings if f.category.value == "phone"]
    assert len(phone_findings) == 0
