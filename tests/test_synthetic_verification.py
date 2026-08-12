"""Tests that Scrubsmith-generated synthetic values pass verification."""

import ipaddress

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import RESERVED_EMAIL_DOMAIN, TransformationContext
from scrubsmith.core.models import VerificationStatus
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.core.verifier import Verifier
from scrubsmith.detectors.validation import is_documentation_ip

SAMPLES = {
    "email": "customer@acme-corp.io",
    "phone": "612345678",
    "ipv4": "81.42.18.50",
    "ipv6": "2001:db8:1::1",
    "iban": "GB82WEST12345698765432",
    "dni": "12345678Z",
    "nie": "X1234567L",
    "credit_card": "4111111111111111",
    "password": "password=SuperSecret123",
    "jwt": (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ),
}


def _sanitize_and_verify(text: str) -> VerificationStatus:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"synthetic-test-seed")
    sanitizer = Sanitizer(config, context=context)
    verifier = Verifier(config)
    sanitized, _ = sanitizer.sanitize_text(text)
    return verifier.verify_text(
        sanitized,
        allowed_replacements=context.generated_replacements,
    ).status


def test_email_synthetic_passes_verification() -> None:
    assert _sanitize_and_verify(f"user={SAMPLES['email']}") == VerificationStatus.PASS


def test_phone_synthetic_passes_verification() -> None:
    sanitized_status = _sanitize_and_verify(f"call {SAMPLES['phone']}")
    assert sanitized_status == VerificationStatus.PASS


def test_ipv4_synthetic_uses_documentation_range() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"ip-doc"))
    sanitized, _ = sanitizer.sanitize_text(f"host {SAMPLES['ipv4']}")
    token = sanitized.split()[-1].strip()
    assert is_documentation_ip(token)


def test_generated_ip_replacement_passes_verification() -> None:
    assert _sanitize_and_verify(f"host {SAMPLES['ipv4']}") == VerificationStatus.PASS


def test_ipv6_synthetic_passes_post_sanitization_verifier() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"ip6-doc"))
    sanitized, _ = sanitizer.sanitize_text(f"addr {SAMPLES['ipv6']}")
    token = sanitized.split()[-1].strip()
    parsed = ipaddress.IPv6Address(token)
    assert parsed in ipaddress.IPv6Network("2001:db8::/32")
    assert _sanitize_and_verify(f"addr {SAMPLES['ipv6']}") == VerificationStatus.PASS


def test_iban_synthetic_passes_verification() -> None:
    assert _sanitize_and_verify(f"account {SAMPLES['iban']}") == VerificationStatus.PASS


def test_dni_synthetic_passes_verification() -> None:
    assert _sanitize_and_verify(f"id {SAMPLES['dni']}") == VerificationStatus.PASS


def test_nie_synthetic_passes_verification() -> None:
    assert _sanitize_and_verify(f"id {SAMPLES['nie']}") == VerificationStatus.PASS


def test_credit_card_redacted_passes_verification() -> None:
    assert _sanitize_and_verify(f"card={SAMPLES['credit_card']}") == VerificationStatus.PASS


def test_secrets_redacted_passes_verification() -> None:
    assert _sanitize_and_verify(SAMPLES["password"]) == VerificationStatus.PASS
    assert _sanitize_and_verify(SAMPLES["jwt"]) == VerificationStatus.PASS


def test_combined_sample_passes_verification() -> None:
    text = (
        f"email={SAMPLES['email']} phone={SAMPLES['phone']} "
        f"ip={SAMPLES['ipv4']} iban={SAMPLES['iban']} id={SAMPLES['dni']}"
    )
    assert _sanitize_and_verify(text) == VerificationStatus.PASS


def test_generated_email_uses_reserved_domain() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"domain"))
    sanitized, _ = sanitizer.sanitize_text(SAMPLES["email"])
    assert RESERVED_EMAIL_DOMAIN in sanitized
