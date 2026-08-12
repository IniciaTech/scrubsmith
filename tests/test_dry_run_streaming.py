"""Tests for streaming dry-run behavior."""

from pathlib import Path

from typer.testing import CliRunner

from scrubsmith.cli import app
from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.accumulators import VerificationAccumulator
from scrubsmith.core.context import TransformationContext
from scrubsmith.sources.logs import LogSanitizer

runner = CliRunner()


def test_dry_run_creates_no_output_file(tmp_path: Path) -> None:
    log = tmp_path / "input.log"
    output = tmp_path / "output.log"
    log.write_text("user@company.org login\n", encoding="utf-8")

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"dry"))
    sanitizer.sanitize_file(log, output, dry_run=True)
    assert not output.exists()


def test_dry_run_does_not_read_whole_file(tmp_path: Path, monkeypatch) -> None:
    log = tmp_path / "large.log"
    line = "user@company.org event\n"
    with log.open("w", encoding="utf-8") as handle:
        for _ in range(50_000):
            handle.write(line)

    read_text_called = False
    original_read_text = Path.read_text

    def tracking_read_text(self, *args, **kwargs):
        nonlocal read_text_called
        read_text_called = True
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", tracking_read_text)
    result = runner.invoke(app, ["sanitize", "logs", str(log), "--dry-run"])
    assert result.exit_code in (0, 1, 2)
    assert not read_text_called


def test_dry_run_feeds_verification_incrementally(tmp_path: Path, monkeypatch) -> None:
    log = tmp_path / "large.log"
    with log.open("w", encoding="utf-8") as handle:
        for _ in range(10_000):
            handle.write("user@company.org line\n")

    feed_calls = 0
    original_feed = VerificationAccumulator.feed_segment

    def counting_feed(self, text, detectors):
        nonlocal feed_calls
        feed_calls += 1
        return original_feed(self, text, detectors)

    monkeypatch.setattr(VerificationAccumulator, "feed_segment", counting_feed)

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"dry"))
    sanitizer.sanitize_file(log, dry_run=True)
    assert feed_calls == 10_000


def test_dry_run_matches_normal_sanitization_counts(tmp_path: Path) -> None:
    log = tmp_path / "sample.log"
    out = tmp_path / "sample.safe.log"
    log.write_text(
        "user@company.org from 81.42.18.50\npassword=SuperSecret123\n",
        encoding="utf-8",
    )

    config = ScrubsmithConfig(version=1)
    context = TransformationContext(seed=b"counts")
    sanitizer = LogSanitizer(config, context=context)
    dry_report = sanitizer.sanitize_file(log, dry_run=True)

    context2 = TransformationContext(seed=b"counts")
    sanitizer2 = LogSanitizer(config, context=context2)
    normal_report = sanitizer2.sanitize_file(log, out)

    assert dry_report.stats.lines_processed == normal_report.stats.lines_processed
    assert dry_report.stats.values_transformed == normal_report.stats.values_transformed
    assert dry_report.stats.secrets_redacted == normal_report.stats.secrets_redacted
    assert dry_report.verification.status == normal_report.verification.status


def test_dry_run_large_file_uses_streaming_path(tmp_path: Path) -> None:
    log = tmp_path / "large-dry.log"
    with log.open("w", encoding="utf-8") as handle:
        for i in range(50_000):
            handle.write(f"event-{i} user@company-{i % 10}.org ok\n")

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"dry-large"))
    report = sanitizer.sanitize_file(log, dry_run=True)
    assert report.stats.lines_processed == 50_000
