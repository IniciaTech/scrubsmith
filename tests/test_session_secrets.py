"""Tests for session credential detection."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import REDACTED_PLACEHOLDER, TransformationContext
from scrubsmith.core.models import Category, VerificationStatus
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.core.verifier import Verifier
from scrubsmith.detectors.generic.secrets import SecretsDetector

DETECTOR = SecretsDetector()

# Synthetic session token — not derived from production data.
SYNTH_SESSION = "SYNTH_SESS_tok_ab12cd34ef56gh78"
SYNTH_UUID = "550e8400-e29b-41d4-a716-446655440000"
SYNTH_PAYLOAD = "SYNTH_PAYLOAD_opaque_base64_ab12cd34ef56gh78XYZ=="


def _assert_secret_token(text: str) -> None:
    findings = DETECTOR.detect(text)
    secret_findings = [f for f in findings if f.category == Category.SECRET]
    assert secret_findings, f"expected SECRET finding in: {text!r}"
    matched = text[secret_findings[0].start : secret_findings[0].end]
    assert matched == SYNTH_SESSION


def _assert_no_session_secret(text: str) -> None:
    findings = DETECTOR.detect(text)
    session_secrets = [
        f
        for f in findings
        if f.category == Category.SECRET and "session" in f.detector
    ]
    assert not session_secrets, f"unexpected session SECRET in: {text!r}"


def test_sessions_sql_with_backticks() -> None:
    text = f"select * from `sessions` where `id` = {SYNTH_SESSION} limit 1"
    _assert_secret_token(text)


def test_sessions_sql_without_backticks() -> None:
    text = f"select * from sessions where id = {SYNTH_SESSION}"
    _assert_secret_token(text)


def test_session_id_assignment() -> None:
    _assert_secret_token(f"session_id={SYNTH_SESSION}")


def test_session_id_camel_case_colon() -> None:
    _assert_secret_token(f"sessionId: {SYNTH_SESSION}")


def test_session_json_field() -> None:
    _assert_secret_token(f'{{"session_id":"{SYNTH_SESSION}"}}')


def test_phpsessid_cookie_pair() -> None:
    _assert_secret_token(f"PHPSESSID={SYNTH_SESSION}")


def test_session_cookie_related_key() -> None:
    _assert_secret_token(f"session-token={SYNTH_SESSION}")


def test_user_id_not_secret() -> None:
    _assert_no_session_secret(f"user_id={SYNTH_SESSION}")


def test_users_sql_not_secret() -> None:
    _assert_no_session_secret(f"select * from users where id = {SYNTH_SESSION}")


def test_uuid_reference_without_session_context_not_secret() -> None:
    _assert_no_session_secret(f"reference_id={SYNTH_UUID}")


def test_uuid_session_id_assignment_is_secret() -> None:
    findings = DETECTOR.detect(f"session_id={SYNTH_UUID}")
    secret_findings = [f for f in findings if f.category == Category.SECRET]
    assert secret_findings
    matched = f"session_id={SYNTH_UUID}"[secret_findings[0].start : secret_findings[0].end]
    assert matched == SYNTH_UUID


def test_uuid_sessions_sql_quoted_is_secret() -> None:
    text = f"select * from sessions where id = '{SYNTH_UUID}' limit 1"
    findings = DETECTOR.detect(text)
    secret_findings = [f for f in findings if f.category == Category.SECRET]
    assert secret_findings
    assert text[secret_findings[0].start : secret_findings[0].end] == SYNTH_UUID


def test_uuid_sessions_sql_unquoted_is_secret() -> None:
    text = f"select * from sessions where id = {SYNTH_UUID} limit 1"
    findings = DETECTOR.detect(text)
    secret_findings = [f for f in findings if f.category == Category.SECRET]
    assert secret_findings
    assert text[secret_findings[0].start : secret_findings[0].end] == SYNTH_UUID


def test_product_id_without_session_context_not_secret() -> None:
    _assert_no_session_secret("product_id=PRD-2026-001234567890")


def test_sanitize_sql_session_redacts_token_only() -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config, context=TransformationContext(seed=b"session-sql"))
    text = f"SQLSTATE: select * from `sessions` where `id` = {SYNTH_SESSION} limit 1"
    result, stats = sanitizer.sanitize_text(text)
    assert SYNTH_SESSION not in result
    assert REDACTED_PLACEHOLDER in result
    assert "`sessions`" in result
    assert "where `id` =" in result
    assert stats.secrets_redacted == 1


def test_sanitized_session_passes_post_sanitization_verifier() -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"session-verify")
    sanitizer = Sanitizer(config, context=context)
    text = f"select * from sessions where id = {SYNTH_SESSION} limit 1"
    result, _ = sanitizer.sanitize_text(text)
    verifier = Verifier(config)
    report = verifier.verify_text(result, allowed_replacements=context.generated_replacements)
    assert SYNTH_SESSION not in result
    assert report.status == VerificationStatus.PASS


def _update_sessions_sql(*, backticks: bool, quoted_id: bool, quoted_payload: bool) -> str:
    table = "`sessions`" if backticks else "sessions"
    payload_col = "`payload`" if backticks else "payload"
    id_col = "`id`" if backticks else "id"
    payload_val = f"'{SYNTH_PAYLOAD}'" if quoted_payload else SYNTH_PAYLOAD
    session_val = f"'{SYNTH_SESSION}'" if quoted_id else SYNTH_SESSION
    return (
        f"update {table} set {payload_col} = {payload_val}, "
        f"last_activity = 1234567890, user_id = 1, "
        f"ip_address = 192.0.2.1, user_agent = 'Mozilla/5.0' "
        f"where {id_col} = {session_val}"
    )


def _session_update_findings(text: str) -> dict[str, list[str]]:
    findings = DETECTOR.detect(text)
    grouped: dict[str, list[str]] = {}
    for finding in findings:
        if finding.category != Category.SECRET:
            continue
        grouped.setdefault(finding.detector, []).append(text[finding.start : finding.end])
    return grouped


def test_update_sessions_payload_and_id_with_backticks() -> None:
    text = _update_sessions_sql(backticks=True, quoted_id=True, quoted_payload=True)
    grouped = _session_update_findings(text)
    assert SYNTH_PAYLOAD in grouped.get("generic.secrets.sessions_payload", [])
    assert SYNTH_SESSION in grouped.get("generic.secrets.sessions_sql", [])


def test_update_sessions_without_backticks() -> None:
    text = _update_sessions_sql(backticks=False, quoted_id=True, quoted_payload=True)
    grouped = _session_update_findings(text)
    assert SYNTH_PAYLOAD in grouped.get("generic.secrets.sessions_payload", [])
    assert SYNTH_SESSION in grouped.get("generic.secrets.sessions_sql", [])


def test_update_sessions_unquoted_id_and_payload() -> None:
    text = _update_sessions_sql(backticks=False, quoted_id=False, quoted_payload=False)
    grouped = _session_update_findings(text)
    assert SYNTH_PAYLOAD in grouped.get("generic.secrets.sessions_payload", [])
    assert SYNTH_SESSION in grouped.get("generic.secrets.sessions_sql", [])


def test_update_non_sessions_table_not_secret() -> None:
    text = (
        f"update users set payload = '{SYNTH_PAYLOAD}' "
        f"where id = '{SYNTH_SESSION}'"
    )
    _assert_no_session_secret(text)


def test_sanitize_update_sessions_preserves_sql_structure() -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"session-update")
    sanitizer = Sanitizer(config, context=context)
    text = _update_sessions_sql(backticks=True, quoted_id=True, quoted_payload=True)
    result, stats = sanitizer.sanitize_text(text)
    assert SYNTH_PAYLOAD not in result
    assert SYNTH_SESSION not in result
    assert result.count(REDACTED_PLACEHOLDER) >= 2
    assert "update `sessions`" in result
    assert "`payload` =" in result
    assert "last_activity = 1234567890" in result
    assert "user_id = 1" in result
    assert "where `id` =" in result
    assert stats.secrets_redacted >= 2


def test_sanitized_update_sessions_passes_verifier() -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"session-update-verify")
    sanitizer = Sanitizer(config, context=context)
    text = _update_sessions_sql(backticks=True, quoted_id=True, quoted_payload=True)
    result, _ = sanitizer.sanitize_text(text)
    verifier = Verifier(config)
    report = verifier.verify_text(result, allowed_replacements=context.generated_replacements)
    assert SYNTH_PAYLOAD not in result
    assert SYNTH_SESSION not in result
    assert report.status == VerificationStatus.PASS
