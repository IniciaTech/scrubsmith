"""Tests for fail-closed PEM/private-key streaming."""

from pathlib import Path

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import REDACTED_PRIVATE_KEY_PLACEHOLDER, TransformationContext
from scrubsmith.sources.logs import LogSanitizer
from scrubsmith.sources.streaming import (
    PemFailClosedReader,
    StreamChunkKind,
)


def _sanitize(input_file: Path, output_file: Path) -> str:
    config = ScrubsmithConfig(version=1)
    sanitizer = LogSanitizer(config, context=TransformationContext(seed=b"pem"))
    sanitizer.sanitize_file(input_file, output_file)
    return output_file.read_text(encoding="utf-8")


def test_normal_multiline_pem_block(tmp_path: Path) -> None:
    input_file = tmp_path / "pem.log"
    output_file = tmp_path / "pem.safe.log"
    input_file.write_text(
        "info: loading key\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyH9\n"
        "-----END RSA PRIVATE KEY-----\n"
        "info: done\n",
        encoding="utf-8",
    )

    content = _sanitize(input_file, output_file)
    assert "BEGIN RSA PRIVATE KEY" not in content
    assert "MIIEpAIBAAKCAQEA" not in content
    assert REDACTED_PRIVATE_KEY_PLACEHOLDER in content
    assert "info: done" in content


def test_pem_without_end_marker_redacts_to_eof(tmp_path: Path) -> None:
    input_file = tmp_path / "truncated.pem.log"
    output_file = tmp_path / "truncated.safe.log"
    lines = ["-----BEGIN RSA PRIVATE KEY-----\n"] + ["A" * 100 + "\n" for _ in range(200)]
    input_file.write_text("".join(lines), encoding="utf-8")

    content = _sanitize(input_file, output_file)
    assert "-----BEGIN" not in content
    assert "AAAA" not in content
    assert content.count(REDACTED_PRIVATE_KEY_PLACEHOLDER) == 1


def test_pem_exceeding_buffer_limit_never_emits_secret_material(tmp_path: Path) -> None:
    input_file = tmp_path / "huge.pem.log"
    output_file = tmp_path / "huge.safe.log"
    filler = "SECRETKEYLIKEBASE64DATA" * 20
    body = "\n".join(filler for _ in range(500)) + "\n"
    input_file.write_text(
        "before\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        f"{body}"
        "after-should-not-appear-if-still-inside-block\n",
        encoding="utf-8",
    )

    reader = PemFailClosedReader(
        input_file,
        placeholder=REDACTED_PRIVATE_KEY_PLACEHOLDER,
        max_redacting_bytes=512,
    )
    emitted = [chunk.text for chunk in reader.iter_chunks()]
    combined = "".join(emitted)

    assert REDACTED_PRIVATE_KEY_PLACEHOLDER in combined
    assert "SECRETKEYLIKEBASE64DATA" not in combined
    assert "BEGIN RSA PRIVATE KEY" not in combined
    assert reader.stats.oversized_blocks >= 1 or reader.stats.incomplete_blocks >= 1

    content = _sanitize(input_file, output_file)
    assert "SECRETKEYLIKEBASE64DATA" not in content
    assert "BEGIN RSA PRIVATE KEY" not in content


def test_extremely_large_malformed_pem_like_block(tmp_path: Path) -> None:
    input_file = tmp_path / "massive.pem.log"
    output_file = tmp_path / "massive.safe.log"
    with input_file.open("w", encoding="utf-8") as handle:
        handle.write("-----BEGIN RSA PRIVATE KEY-----\n")
        for _ in range(100_000):
            handle.write("YmFzZTY0LWRhdGEt" * 8 + "\n")

    content = _sanitize(input_file, output_file)
    assert "YmFzZTY0LWRhdGEt" not in content
    assert content.count(REDACTED_PRIVATE_KEY_PLACEHOLDER) == 1


def test_content_after_valid_end_marker_processed_normally(tmp_path: Path) -> None:
    input_file = tmp_path / "after.pem.log"
    output_file = tmp_path / "after.safe.log"
    input_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "abc\n"
        "-----END RSA PRIVATE KEY-----\n"
        "tail user@company.org\n",
        encoding="utf-8",
    )

    content = _sanitize(input_file, output_file)
    assert "company.org" not in content
    assert "tail" in content
    assert REDACTED_PRIVATE_KEY_PLACEHOLDER in content


def test_fail_closed_reader_never_yields_raw_pem_lines(tmp_path: Path) -> None:
    input_file = tmp_path / "reader.pem.log"
    input_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nline-should-not-appear\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    reader = PemFailClosedReader(input_file, placeholder=REDACTED_PRIVATE_KEY_PLACEHOLDER)
    chunks = list(reader.iter_chunks())
    assert all(
        chunk.kind == StreamChunkKind.PEM_REDACTED or "PRIVATE KEY" not in chunk.text
        for chunk in chunks
    )
    assert all("line-should-not-appear" not in chunk.text for chunk in chunks)
