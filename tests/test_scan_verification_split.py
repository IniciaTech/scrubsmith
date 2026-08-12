"""Tests separating strict scan from generated-value-aware verification."""

from pathlib import Path

from typer.testing import CliRunner

from scrubsmith.cli import app
from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import TransformationContext
from scrubsmith.core.models import VerificationStatus
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.core.verifier import Verifier
from scrubsmith.sources.logs import LogSanitizer

runner = CliRunner()


def test_standalone_scan_detects_documentation_range_ip(tmp_path: Path) -> None:
    log = tmp_path / "raw.log"
    log.write_text("client connected from 192.0.2.42\n", encoding="utf-8")

    verifier = Verifier(ScrubsmithConfig(version=1))
    summary = verifier.scan_file(log)
    assert summary.ip_addresses == 1


def test_standalone_scan_detects_documentation_range_ip_via_cli(tmp_path: Path) -> None:
    log = tmp_path / "raw.log"
    log.write_text("client connected from 192.0.2.42\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(log)])
    assert "IP addresses:" in result.stdout
    summary = Verifier(ScrubsmithConfig(version=1)).scan_file(log)
    assert summary.ip_addresses == 1


def test_generated_ip_replacement_passes_post_sanitization_verifier(tmp_path: Path) -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"verify-ip")
    log_sanitizer = LogSanitizer(config, context=context)
    input_file = tmp_path / "in.log"
    output_file = tmp_path / "out.log"
    input_file.write_text("client connected from 81.42.18.50\n", encoding="utf-8")

    report = log_sanitizer.sanitize_file(input_file, output_file)
    assert report.verification.status == VerificationStatus.PASS
    assert "81.42.18.50" not in output_file.read_text(encoding="utf-8")


def test_unrelated_ip_in_sanitized_output_still_fails_verification() -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"verify-ip")
    sanitizer = Sanitizer(config, context=context)
    verifier = Verifier(config)

    sanitized, _ = sanitizer.sanitize_text("primary host 10.0.0.1")
    leaked = sanitized + " leaked 203.0.113.99\n"
    report = verifier.verify_text(leaked, allowed_replacements=context.generated_replacements)
    assert report.status == VerificationStatus.REVIEW_REQUIRED
    assert report.uncertain_findings >= 1


def test_allowlist_applies_only_to_generated_values_not_entire_range() -> None:
    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"allowlist")
    sanitizer = Sanitizer(config, context=context)
    verifier = Verifier(config)

    sanitized, _ = sanitizer.sanitize_text("host 10.0.0.1")
    generated_ip = next(value for value in context.generated_replacements if value[0].isdigit())

    only_generated = verifier.verify_text(
        f"host {generated_ip}\n",
        allowed_replacements=context.generated_replacements,
    )
    assert only_generated.status == VerificationStatus.PASS

    other_doc_ip = "192.0.2.99"
    assert other_doc_ip not in context.generated_replacements
    with_other = verifier.verify_text(
        f"host {generated_ip} and {other_doc_ip}\n",
        allowed_replacements=context.generated_replacements,
    )
    assert with_other.status == VerificationStatus.REVIEW_REQUIRED
    assert with_other.uncertain_findings == 1
