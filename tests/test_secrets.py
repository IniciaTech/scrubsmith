"""Tests for secrets detector."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import REDACTED_PLACEHOLDER, TransformationContext
from scrubsmith.core.models import VerificationStatus
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.core.verifier import Verifier
from scrubsmith.detectors.generic.secrets import SecretsDetector

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_bearer_token() -> None:
    detector = SecretsDetector()
    text = f"Authorization: Bearer {JWT_SAMPLE}"
    findings = detector.detect(text)
    assert len(findings) >= 1


def test_jwt_detected() -> None:
    detector = SecretsDetector()
    findings = detector.detect(JWT_SAMPLE)
    assert len(findings) == 1


def test_api_key_assignment() -> None:
    detector = SecretsDetector()
    findings = detector.detect("api_key=sk-live-abc123xyz")
    assert len(findings) == 1


def test_password_assignment() -> None:
    detector = SecretsDetector()
    findings = detector.detect("password=SuperSecret123")
    assert len(findings) == 1


def test_session_token() -> None:
    detector = SecretsDetector()
    findings = detector.detect("session_token=sess_abc123def456")
    assert len(findings) == 1


def test_pem_private_key() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyH9\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    detector = SecretsDetector()
    findings = detector.detect(pem)
    assert len(findings) == 1


def test_similar_but_not_secret() -> None:
    detector = SecretsDetector()
    findings = detector.detect("password_policy=min_length_8")
    assert len(findings) == 0


def test_secrets_redacted_not_faked() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"s"))
    text = "password=SuperSecret123"
    result, stats = sanitizer.sanitize_text(text)
    assert REDACTED_PLACEHOLDER in result
    assert "SuperSecret123" not in result
    assert stats.secrets_redacted == 1


def test_sanitized_secrets_pass_verification() -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"s")
    sanitizer = Sanitizer(config, context=context)
    text = f"Authorization: Bearer {JWT_SAMPLE}"
    result, _ = sanitizer.sanitize_text(text)
    verifier = Verifier(config)
    report = verifier.verify_text(result, allowed_replacements=context.generated_replacements)
    assert report.status != VerificationStatus.FAIL
