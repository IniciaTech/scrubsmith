"""Tests for Spanish DNI/NIE detector."""

from scrubsmith.detectors.es.identity import SpanishIdentityDetector
from scrubsmith.detectors.validation import validate_dni, validate_nie


def test_valid_dni() -> None:
    # 12345678Z is valid (12345678 % 23 = 14 -> Z)
    assert validate_dni("12345678Z")
    detector = SpanishIdentityDetector()
    findings = detector.detect("ID: 12345678Z")
    assert len(findings) == 1


def test_invalid_dni() -> None:
    assert not validate_dni("12345678A")
    detector = SpanishIdentityDetector()
    findings = detector.detect("ID: 12345678A")
    assert len(findings) == 0


def test_valid_nie() -> None:
    # X1234567L - X->0, 01234567 % 23 = 11 -> L
    assert validate_nie("X1234567L")
    detector = SpanishIdentityDetector()
    findings = detector.detect("NIE X1234567L")
    assert len(findings) == 1


def test_invalid_nie() -> None:
    assert not validate_nie("X1234567A")
    detector = SpanishIdentityDetector()
    findings = detector.detect("NIE X1234567A")
    assert len(findings) == 0
