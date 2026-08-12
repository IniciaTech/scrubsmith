"""Tests for phone number detector."""

from scrubsmith.core.models import Confidence
from scrubsmith.detectors.generic.phone import PhoneDetector

DETECTOR = PhoneDetector()


def test_spanish_mobile() -> None:
    findings = DETECTOR.detect("Call 612345678 for info")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.MEDIUM


def test_spanish_landline() -> None:
    findings = DETECTOR.detect("Office 912345678")
    assert len(findings) == 1


def test_international_format() -> None:
    findings = DETECTOR.detect("Contact +1 415 555 0100")
    assert len(findings) >= 1


def test_spanish_with_plus34_prefix() -> None:
    findings = DETECTOR.detect("Contact +34 612 345 678 today")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_spanish_with_0034_prefix() -> None:
    findings = DETECTOR.detect("Dial 0034 612345678 now")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_embedded_in_hex_string() -> None:
    findings = DETECTOR.detect("78f792b41dfe4097675e09123456789cee09f")
    assert len(findings) == 0


def test_embedded_after_letters() -> None:
    findings = DETECTOR.detect("abc612345678")
    assert len(findings) == 0


def test_embedded_before_letters() -> None:
    findings = DETECTOR.detect("612345678abc")
    assert len(findings) == 0


def test_embedded_in_cache_filename() -> None:
    text = "autoptimize_single_78f792b41dfe4097675e09123456789cee09f.php"
    assert DETECTOR.detect(text) == []


def test_autoptimize_cache_path_regression() -> None:
    text = (
        "GET /wp-content/cache/autoptimize/"
        "autoptimize_single_78f792b41dfe4097675e09123456789cee09f.php HTTP/1.1"
    )
    assert DETECTOR.detect(text) == []


def test_tracking_identifier_no_phone() -> None:
    text = (
        "fbclid=IwAR1a2b3c4d5e6f7890abcdefghijklmnopqrstuvwxyz612345678more"
        "igshid=YmMyMTA2M2Y612345678abcdefghijklmnopqrstuvwxyz"
    )
    assert DETECTOR.detect(text) == []


def test_user_agent_version_no_phone() -> None:
    text = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.612345678 Safari/537.36"
    )
    assert DETECTOR.detect(text) == []


def test_phone_with_punctuation() -> None:
    findings = DETECTOR.detect("phone=(612345678)")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_phone_in_query_parameter() -> None:
    findings = DETECTOR.detect("GET /api?phone=612345678 HTTP/1.1")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_cache_token_with_embedded_digits() -> None:
    findings = DETECTOR.detect("cache612345678abcd")
    assert len(findings) == 0


def test_token_with_embedded_digits() -> None:
    findings = DETECTOR.detect("token_612345678abc")
    assert len(findings) == 0


def test_technical_numeric_not_phone() -> None:
    findings = DETECTOR.detect("request_id=12345678901234567890")
    assert len(findings) == 0


def test_port_like_not_phone() -> None:
    findings = DETECTOR.detect("connected to 127.0.0.1:8080")
    phone_findings = [f for f in findings if f.category.value == "phone"]
    assert len(phone_findings) == 0


def test_spanish_separated_bare() -> None:
    findings = DETECTOR.detect("Dial 612 345 678 today")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_tel_field_context() -> None:
    findings = DETECTOR.detect("tel: 912345678")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


# --- User-Agent / technical metadata regressions ---


def test_instagram_user_agent_metadata_no_phone() -> None:
    text = "Instagram 302.0.0.0 Android (28/9; IABMV/1; 1030250346) Safari/604.1"
    assert DETECTOR.detect(text) == []


def test_user_agent_semicolon_delimited_nine_digit_metadata_no_phone() -> None:
    """9-digit Spanish-shaped metadata after semicolon must not match."""
    text = "Instagram 302.0.0.0 Android (28/9; IABMV/1; 803025034) Safari/604.1"
    assert DETECTOR.detect(text) == []


def test_bare_ten_digit_technical_id_no_phone() -> None:
    assert DETECTOR.detect("1030250346") == []


def test_bare_eleven_digit_technical_id_no_phone() -> None:
    assert DETECTOR.detect("12345678901") == []


def test_bare_twelve_digit_technical_id_no_phone() -> None:
    assert DETECTOR.detect("123456789012") == []


def test_bare_fifteen_digit_technical_id_no_phone() -> None:
    assert DETECTOR.detect("123456789012345") == []


def test_user_id_field_no_phone() -> None:
    assert DETECTOR.detect("user_id=1030250346") == []


def test_device_id_field_no_phone() -> None:
    assert DETECTOR.detect("device_id=1030250346") == []


def test_order_field_no_phone() -> None:
    assert DETECTOR.detect("order=12345678901") == []


def test_tracking_id_field_no_phone() -> None:
    assert DETECTOR.detect("tracking_id=123456789012") == []


def test_build_field_no_phone() -> None:
    assert DETECTOR.detect("build=1234567890") == []


def test_explicit_phone_field_ten_digit_finding() -> None:
    findings = DETECTOR.detect("phone=1030250346")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_international_plus_forty_four() -> None:
    findings = DETECTOR.detect("Contact +44 7700 900123")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_international_plus_thirty_three() -> None:
    findings = DETECTOR.detect("Dial +33 6 12 34 56 78")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_telephone_field_international_digits() -> None:
    findings = DETECTOR.detect("telephone: 33123456789")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_phone_field_international_without_plus() -> None:
    findings = DETECTOR.detect("phone=447700900123")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


# --- Structured non-phone field regressions ---


def test_user_id_nine_digit_spanish_shape_no_phone() -> None:
    assert DETECTOR.detect("user_id=612345678") == []


def test_order_id_nine_digit_spanish_shape_no_phone() -> None:
    assert DETECTOR.detect("order_id=612345678") == []


def test_customer_id_colon_nine_digit_no_phone() -> None:
    assert DETECTOR.detect("customer_id: 912345678") == []


def test_reference_field_nine_digit_no_phone() -> None:
    assert DETECTOR.detect("reference=612345678") == []


def test_build_field_nine_digit_no_phone() -> None:
    assert DETECTOR.detect("build=912345678") == []


def test_tracking_id_nine_digit_no_phone() -> None:
    assert DETECTOR.detect("tracking_id=712345678") == []


def test_phone_number_field_key_matches() -> None:
    findings = DETECTOR.detect("phone_number: 612345678")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_mobile_field_key_matches() -> None:
    findings = DETECTOR.detect("mobile=612345678")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_contact_prose_still_matches() -> None:
    findings = DETECTOR.detect("Contact 912345678")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.MEDIUM


