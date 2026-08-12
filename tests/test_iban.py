"""Tests for IBAN detector."""

from scrubsmith.detectors.generic.iban import IBANDetector
from scrubsmith.detectors.validation import validate_iban


def test_valid_iban() -> None:
    # Synthetic valid IBAN (GB example from IBAN test vectors style)
    iban = "GB82WEST12345698765432"
    assert validate_iban(iban)
    detector = IBANDetector()
    findings = detector.detect(f"Account {iban}")
    assert len(findings) == 1


def test_invalid_iban() -> None:
    assert not validate_iban("GB00WEST12345698765432")
    detector = IBANDetector()
    findings = detector.detect("Account GB00WEST12345698765432")
    assert len(findings) == 0
