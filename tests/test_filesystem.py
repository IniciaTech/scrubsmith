"""Tests for filesystem safety and streaming."""

from pathlib import Path

import pytest

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import REDACTED_PRIVATE_KEY_PLACEHOLDER, TransformationContext
from scrubsmith.sources.logs import LogSanitizer, paths_are_same


def test_dry_run_creates_no_output(tmp_path: Path) -> None:
    input_file = tmp_path / "input.log"
    output_file = tmp_path / "output.log"
    input_file.write_text("email=test@example.org\n", encoding="utf-8")

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"s"))
    report = sanitizer.sanitize_file(input_file, output_file, dry_run=True)

    assert not output_file.exists()
    assert report.stats.lines_processed == 1


def test_source_cannot_be_overwritten(tmp_path: Path) -> None:
    input_file = tmp_path / "same.log"
    input_file.write_text("data\n", encoding="utf-8")

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"s"))

    with pytest.raises(ValueError, match="same"):
        sanitizer.sanitize_file(input_file, input_file)


def test_paths_are_same_detected(tmp_path: Path) -> None:
    f = tmp_path / "file.log"
    f.write_text("x", encoding="utf-8")
    assert paths_are_same(f, f)
    assert paths_are_same(f, tmp_path / "file.log")


def test_normal_output_works(tmp_path: Path) -> None:
    input_file = tmp_path / "input.log"
    output_file = tmp_path / "output.safe.log"
    input_file.write_text("user@company.org login\n", encoding="utf-8")

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"s"))
    report = sanitizer.sanitize_file(input_file, output_file)

    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "company.org" not in content
    assert report.stats.lines_processed == 1


def test_incomplete_output_cleaned_on_failure(tmp_path: Path, monkeypatch) -> None:
    input_file = tmp_path / "input.log"
    output_file = tmp_path / "output.log"
    input_file.write_text("line\n", encoding="utf-8")

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"s"))

    def fail_write(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "open", fail_write)

    with pytest.raises(OSError):
        sanitizer.sanitize_file(input_file, output_file)

    temp_files = list(tmp_path.glob(".scrubsmith-*"))
    for tf in temp_files:
        assert not tf.exists() or tf.stat().st_size == 0


def test_streaming_large_file(tmp_path: Path) -> None:
    input_file = tmp_path / "large.log"
    output_file = tmp_path / "large.safe.log"
    line = "event user@stream.test action=login\n"
    # Write 50k lines (~1.5MB) without reading back whole file in test
    with input_file.open("w", encoding="utf-8") as f:
        for _ in range(50_000):
            f.write(line)

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"stream"))
    report = sanitizer.sanitize_file(input_file, output_file)

    assert report.stats.lines_processed == 50_000
    assert output_file.exists()
    # Spot-check first and last lines
    with output_file.open("r", encoding="utf-8") as f:
        first = f.readline()
        assert "company.org" not in first
    assert output_file.stat().st_size > 0


def test_multiline_pem_streaming(tmp_path: Path) -> None:
    input_file = tmp_path / "pem.log"
    output_file = tmp_path / "pem.safe.log"
    pem = (
        "info: loading key\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyH9\n"
        "-----END RSA PRIVATE KEY-----\n"
        "info: done\n"
    )
    input_file.write_text(pem, encoding="utf-8")

    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"s"))
    sanitizer.sanitize_file(input_file, output_file)

    content = output_file.read_text(encoding="utf-8")
    assert "BEGIN RSA PRIVATE KEY" not in content
    assert REDACTED_PRIVATE_KEY_PLACEHOLDER in content
