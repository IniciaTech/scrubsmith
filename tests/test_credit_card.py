"""Tests for credit card detector."""

from scrubsmith.detectors.generic.credit_card import CreditCardDetector
from scrubsmith.detectors.validation import luhn_check


def test_valid_luhn_test_number() -> None:
    # Visa test number
    number = "4111111111111111"
    assert luhn_check(number)
    detector = CreditCardDetector()
    findings = detector.detect(f"card={number}")
    assert len(findings) == 1


def test_invalid_luhn() -> None:
    number = "4111111111111112"
    assert not luhn_check(number)
    detector = CreditCardDetector()
    findings = detector.detect(f"card={number}")
    assert len(findings) == 0


def test_technical_numeric_not_credit_card() -> None:
    detector = CreditCardDetector()
    findings = detector.detect("hash=abcdef1234567890")
    assert len(findings) == 0
