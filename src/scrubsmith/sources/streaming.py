"""Shared streaming utilities for line-oriented log processing."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

PEM_BEGIN = "-----BEGIN"
PEM_END = "-----END"
DEFAULT_MAX_PEM_BUFFER_BYTES = 65_536


class StreamChunkKind(StrEnum):
    LINE = "line"
    PEM_REDACTED = "pem_redacted"


@dataclass(frozen=True)
class StreamChunk:
    """A line or fail-closed PEM redaction placeholder emitted by the stream reader."""

    kind: StreamChunkKind
    text: str
    source_line_count: int = 1


@dataclass
class PemStreamStats:
    """Safe metadata about PEM handling during a stream operation."""

    incomplete_blocks: int = 0
    oversized_blocks: int = 0


def iter_file_lines(input_path: Path) -> Iterator[str]:
    """Yield lines from a file without loading it entirely into memory."""
    with input_path.open("r", encoding="utf-8", errors="replace", newline="") as infile:
        yield from infile


def is_pem_begin_line(line: str) -> bool:
    return PEM_BEGIN in line and "PRIVATE KEY" in line


def is_pem_end_line(line: str) -> bool:
    return PEM_END in line and "PRIVATE KEY" in line


def pem_placeholder_line(source_line: str, placeholder: str) -> str:
    """Preserve trailing newline semantics from the triggering source line."""
    if source_line.endswith("\r\n"):
        return f"{placeholder}\r\n"
    if source_line.endswith("\n"):
        return f"{placeholder}\n"
    return placeholder


class PemFailClosedReader:
    """
    Fail-closed PEM/private-key streaming state machine.

    Once a BEGIN PRIVATE KEY marker is seen, no private-key material is ever
    emitted. A single safe placeholder is written and subsequent lines belonging
    to the block are discarded until an END marker or EOF.
    """

    def __init__(
        self,
        input_path: Path,
        *,
        placeholder: str,
        max_redacting_bytes: int = DEFAULT_MAX_PEM_BUFFER_BYTES,
    ) -> None:
        self.input_path = input_path
        self.placeholder = placeholder
        self.max_redacting_bytes = max_redacting_bytes
        self.stats = PemStreamStats()

    def iter_chunks(self) -> Iterator[StreamChunk]:
        mode = "normal"
        redacting_bytes = 0
        oversized_for_current_block = False

        with self.input_path.open("r", encoding="utf-8", errors="replace", newline="") as infile:
            for line in infile:
                if mode == "redacting":
                    redacting_bytes += len(line.encode("utf-8"))
                    if redacting_bytes > self.max_redacting_bytes:
                        oversized_for_current_block = True

                    if is_pem_end_line(line):
                        mode = "normal"
                        redacting_bytes = 0
                        oversized_for_current_block = False
                    continue

                if is_pem_begin_line(line):
                    yield StreamChunk(
                        kind=StreamChunkKind.PEM_REDACTED,
                        text=pem_placeholder_line(line, self.placeholder),
                        source_line_count=1,
                    )
                    if is_pem_end_line(line):
                        continue

                    mode = "redacting"
                    redacting_bytes = len(line.encode("utf-8"))
                    oversized_for_current_block = redacting_bytes > self.max_redacting_bytes
                    continue

                yield StreamChunk(
                    kind=StreamChunkKind.LINE,
                    text=line,
                    source_line_count=1,
                )

        if mode == "redacting":
            self.stats.incomplete_blocks += 1
            if oversized_for_current_block:
                self.stats.oversized_blocks += 1
