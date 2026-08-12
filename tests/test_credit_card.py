"""Tests for credit card detector."""

from scrubsmith.detectors.generic.credit_card import CreditCardDetector
from scrubsmith.detectors.validation import luhn_check

DETECTOR = CreditCardDetector()
VISA_TEST_NUMBER = "4111111111111111"


def test_valid_luhn_test_number() -> None:
    assert luhn_check(VISA_TEST_NUMBER)
    findings = DETECTOR.detect(f"card={VISA_TEST_NUMBER}")
    assert len(findings) == 1


def test_separated_card_number() -> None:
    findings = DETECTOR.detect("payment 4111-1111-1111-1111 approved")
    assert len(findings) == 1


def test_invalid_luhn() -> None:
    number = "4111111111111112"
    assert not luhn_check(number)
    assert DETECTOR.detect(f"card={number}") == []


def test_embedded_in_letters_no_finding() -> None:
    assert DETECTOR.detect(f"abc{VISA_TEST_NUMBER}def") == []


def test_embedded_in_technical_filename_no_finding() -> None:
    text = f"autoptimize_single_78f{VISA_TEST_NUMBER}cee09f.php"
    assert DETECTOR.detect(text) == []


def test_tracking_token_with_luhn_substring_no_finding() -> None:
    text = (
        "fbclid=IwAR1a2b3c4d5e6f7890"
        f"{VISA_TEST_NUMBER}"
        "abcdefghijklmnopqrstuvwxyz"
    )
    assert DETECTOR.detect(text) == []


def test_cache_path_regression_no_finding() -> None:
    text = (
        "GET /wp-content/cache/autoptimize/"
        f"autoptimize_single_78f{VISA_TEST_NUMBER}cee09f.php HTTP/1.1"
    )
    assert DETECTOR.detect(text) == []


def test_technical_numeric_not_credit_card() -> None:
    findings = DETECTOR.detect("hash=abcdef1234567890")
    assert len(findings) == 0
