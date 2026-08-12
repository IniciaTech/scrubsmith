"""Streaming log file sanitizer."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import TextIO

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.accumulators import VerificationAccumulator
from scrubsmith.core.context import REDACTED_PRIVATE_KEY_PLACEHOLDER, TransformationContext
from scrubsmith.core.models import SanitizationReport, SanitizationStats
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.core.verifier import Verifier
from scrubsmith.sources.streaming import PemFailClosedReader, StreamChunkKind


class LogSanitizer:
    """Stream-process log files without loading entire content into memory."""

    def __init__(
        self,
        config: ScrubsmithConfig,
        context: TransformationContext | None = None,
    ) -> None:
        self.sanitizer = Sanitizer(config, context=context)
        self.verifier = Verifier(config)
        self.context = self.sanitizer.context
        self.config = config

    def sanitize_file(
        self,
        input_path: Path,
        output_path: Path | None = None,
        *,
        dry_run: bool = False,
    ) -> SanitizationReport:
        """Sanitize a log file using streaming I/O with atomic output writes."""
        input_resolved = input_path.resolve()
        if output_path is not None:
            output_resolved = output_path.resolve()
            if input_resolved == output_resolved:
                msg = "Output path must not be the same as input path"
                raise ValueError(msg)

        if not dry_run and output_path is None:
            msg = "Output path is required when not in dry-run mode"
            raise ValueError(msg)

        stats = SanitizationStats()
        verify_acc = VerificationAccumulator(context=self.context)
        pem_reader = PemFailClosedReader(
            input_path,
            placeholder=REDACTED_PRIVATE_KEY_PLACEHOLDER,
        )

        if dry_run:
            self._process_stream(pem_reader, stats, verify_acc, sink=None)
            return self._build_report(stats, verify_acc, pem_reader)

        assert output_path is not None
        output_resolved = output_path.resolve()
        temp_fd, temp_path = tempfile.mkstemp(
            dir=output_resolved.parent,
            prefix=".scrubsmith-",
            suffix=".tmp",
        )
        os.close(temp_fd)

        try:
            with Path(temp_path).open("w", encoding="utf-8", newline="") as out_file:
                self._process_stream(pem_reader, stats, verify_acc, sink=out_file)
            os.replace(temp_path, output_resolved)
        except Exception:
            Path(temp_path).unlink(missing_ok=True)
            raise

        return self._build_report(stats, verify_acc, pem_reader)

    def _process_stream(
        self,
        pem_reader: PemFailClosedReader,
        stats: SanitizationStats,
        verify_acc: VerificationAccumulator,
        sink: TextIO | None,
    ) -> None:
        for chunk in pem_reader.iter_chunks():
            if chunk.kind == StreamChunkKind.PEM_REDACTED:
                output = chunk.text
                stats.secrets_redacted += 1
                stats.lines_processed += chunk.source_line_count
                self.context.record_generated(REDACTED_PRIVATE_KEY_PLACEHOLDER)
            else:
                output = self.sanitizer.sanitize_line(chunk.text, stats)
                stats.lines_processed += chunk.source_line_count

            if sink is not None:
                sink.write(output)
            verify_acc.feed_segment(output, self.verifier.detectors)

    @staticmethod
    def _build_report(
        stats: SanitizationStats,
        verify_acc: VerificationAccumulator,
        pem_reader: PemFailClosedReader,
    ) -> SanitizationReport:
        stats.incomplete_pem_blocks = pem_reader.stats.incomplete_blocks
        stats.oversized_pem_blocks = pem_reader.stats.oversized_blocks
        return SanitizationReport(stats=stats, verification=verify_acc.report())


def paths_are_same(path_a: Path, path_b: Path) -> bool:
    """Check if two paths resolve to the same filesystem location."""
    try:
        return path_a.resolve() == path_b.resolve()
    except OSError:
        return False
