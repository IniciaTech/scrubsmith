"""Tests for --scrubsmith-output scan mode vs strict raw scanning."""

from pathlib import Path

from typer.testing import CliRunner

from scrubsmith.cli import app
from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.accumulators import ScanAccumulator
from scrubsmith.core.models import VerificationStatus
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.core.scan_policy import ScanMode
from scrubsmith.core.verifier import Verifier
from scrubsmith.sources.logs import LogSanitizer

runner = CliRunner()
VERIFIER = Verifier(ScrubsmithConfig(version=1))


def _summary_for(text: str, *, scrubsmith_output: bool = False):
    mode = ScanMode.SCRUBSMITH_OUTPUT if scrubsmith_output else ScanMode.STRICT
    _, summary = VERIFIER.scan(text, scan_mode=mode)
    return summary


def _status_for(text: str, *, scrubsmith_output: bool = False) -> VerificationStatus:
    mode = ScanMode.SCRUBSMITH_OUTPUT if scrubsmith_output else ScanMode.STRICT
    acc = ScanAccumulator()
    for line in text.splitlines(keepends=True):
        VERIFIER._scan_line(line, acc, None, scan_mode=mode)
    return acc.status


# 1. Strict scan detects Scrubsmith-shaped email in raw context
def test_strict_scan_detects_scrubsmith_shaped_email() -> None:
    status = _status_for("login user-a1b2c3@example.test\n")
    assert status == VerificationStatus.FAIL


# 2. Strict scan detects documentation-range IP
def test_strict_scan_detects_documentation_ip() -> None:
    summary = _summary_for("client connected from 192.0.2.46\n")
    assert summary.ip_addresses == 1


# 3. --scrubsmith-output ignores correctly formatted Scrubsmith email
def test_scrubsmith_output_ignores_scrubsmith_email() -> None:
    status = _status_for("login user-a1b2c3@example.test\n", scrubsmith_output=True)
    assert status == VerificationStatus.PASS


# 4. --scrubsmith-output ignores documentation-range IP
def test_scrubsmith_output_ignores_documentation_ip() -> None:
    status = _status_for("client connected from 192.0.2.46\n", scrubsmith_output=True)
    assert status == VerificationStatus.PASS


# 5. --scrubsmith-output ignores supported synthetic tokens
def test_scrubsmith_output_ignores_synthetic_tokens() -> None:
    text = (
        "phone phone-8e5e4b\n"
        "dni dni-27dff0\n"
        "nie nie-a1b2c3\n"
        "iban iban-deadbe\n"
    )
    status = _status_for(text, scrubsmith_output=True)
    assert status == VerificationStatus.PASS


# 6. --scrubsmith-output still detects unrelated real-looking email
def test_scrubsmith_output_still_detects_real_email() -> None:
    status = _status_for("contact maria@acme-corp.io\n", scrubsmith_output=True)
    assert status == VerificationStatus.FAIL


# 7. --scrubsmith-output still detects unrelated real IP
def test_scrubsmith_output_still_detects_real_ip() -> None:
    summary = _summary_for("host 81.42.18.50\n", scrubsmith_output=True)
    assert summary.ip_addresses == 1


# 8. --scrubsmith-output still detects secrets
def test_scrubsmith_output_still_detects_secrets() -> None:
    jwt = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0In0.fake-signature\n"
    )
    assert (
        _status_for("password=SuperSecret123\n", scrubsmith_output=True)
        == VerificationStatus.FAIL
    )
    assert _status_for(jwt, scrubsmith_output=True) == VerificationStatus.FAIL


# 9. Similar but non-Scrubsmith values are not incorrectly allowlisted
def test_scrubsmith_output_does_not_allowlist_lookalikes() -> None:
    text = (
        "admin@example.test\n"
        "user-nothex@example.test\n"
        "phone-ABCDEF\n"
        "phone-12345\n"
        "dni-zzzzzz\n"
    )
    status = _status_for(text, scrubsmith_output=True)
    assert status == VerificationStatus.FAIL


# 10. Manual workflow: sanitize → scan --scrubsmith-output → PASS
def test_sanitize_then_scrubsmith_output_scan_passes(tmp_path: Path) -> None:
    config = ScrubsmithConfig(version=1)
    input_file = tmp_path / "input.log"
    output_file = tmp_path / "output.safe.log"
    input_file.write_text(
        "\n".join(
            [
                "2026-08-12 INFO User john@example.com logged in from 81.42.18.50",
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.fake",
                "password=SuperSecret123",
                "Customer phone: +34 612 345 678",
                "Customer DNI: 12345678Z",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = LogSanitizer(config).sanitize_file(input_file, output_file)
    assert report.verification.status == VerificationStatus.PASS

    verifier = Verifier(config)
    _, strict_status = verifier.scan_file_with_status(output_file, scan_mode=ScanMode.STRICT)
    assert strict_status == VerificationStatus.FAIL

    _, output_status = verifier.scan_file_with_status(
        output_file, scan_mode=ScanMode.SCRUBSMITH_OUTPUT
    )
    assert output_status == VerificationStatus.PASS


# 11. Strict scan of sanitized output without flag reports generated values
def test_strict_scan_of_sanitized_output_may_fail(tmp_path: Path) -> None:
    config = ScrubsmithConfig(version=1)
    sanitizer = Sanitizer(config)
    sanitized, _ = sanitizer.sanitize_text("user john@example.com from 81.42.18.50\n")

    out = tmp_path / "safe.log"
    out.write_text(sanitized, encoding="utf-8")

    verifier = Verifier(config)
    _, status = verifier.scan_file_with_status(out, scan_mode=ScanMode.STRICT)
    assert status == VerificationStatus.FAIL


def test_scrubsmith_output_cli_flag(tmp_path: Path) -> None:
    log = tmp_path / "safe.log"
    log.write_text("user user-a1b2c3@example.test from 192.0.2.46\n", encoding="utf-8")

    strict = runner.invoke(app, ["scan", str(log)])
    assert strict.exit_code == 2
    assert "Result: FAIL" in strict.stdout

    output_mode = runner.invoke(app, ["scan", str(log), "--scrubsmith-output"])
    assert output_mode.exit_code == 0
    assert "Result: PASS" in output_mode.stdout
