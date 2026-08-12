"""Post-sanitization verification pass."""

from __future__ import annotations

from pathlib import Path

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.accumulators import ScanAccumulator, VerificationAccumulator, is_high_risk
from scrubsmith.core.context import TransformationContext
from scrubsmith.core.findings_resolution import resolve_overlapping_findings
from scrubsmith.core.models import (
    Confidence,
    Finding,
    ScanSummary,
    VerificationReport,
    VerificationStatus,
)
from scrubsmith.detectors.registry import build_detectors
from scrubsmith.sources.streaming import (
    is_pem_begin_line,
    is_pem_end_line,
    iter_file_lines,
)


class Verifier:
    """
    Runs a post-sanitization verification pass over output.

    This re-scans sanitized content with the same built-in detector pipeline
    used during sanitization. It does not trust sanitizer assertions, but it
    is not a separate detection engine: a detector bug could affect both stages.

    Alternative or third-party verification engines may be plugged in later.
    """

    def __init__(self, config: ScrubsmithConfig | None = None) -> None:
        self.config = config or ScrubsmithConfig(version=1)
        self.detectors = build_detectors(self.config)

    def scan(
        self,
        text: str,
        *,
        collect_findings: bool = False,
    ) -> tuple[list[Finding] | None, ScanSummary]:
        """Scan in-memory text. Finding collection is opt-in for tests."""
        accumulator = ScanAccumulator()
        collected: list[Finding] | None = [] if collect_findings else None

        for line in text.splitlines(keepends=True):
            self._scan_line(line, accumulator, collected)

        return collected, accumulator.summary

    def scan_file(self, input_path: Path) -> ScanSummary:
        """Scan a log file incrementally with bounded aggregation."""
        return self._scan_file_accumulator(input_path).summary

    def scan_file_with_status(self, input_path: Path) -> tuple[ScanSummary, VerificationStatus]:
        """Scan a file and return aggregate summary plus scan status."""
        accumulator = self._scan_file_accumulator(input_path)
        return accumulator.summary, accumulator.status

    def _scan_file_accumulator(self, input_path: Path) -> ScanAccumulator:
        accumulator = ScanAccumulator()
        in_pem_block = False

        for line in iter_file_lines(input_path):
            if in_pem_block:
                if is_pem_end_line(line):
                    in_pem_block = False
                continue

            if is_pem_begin_line(line):
                accumulator.add_pem_secret()
                if not is_pem_end_line(line):
                    in_pem_block = True
                continue

            self._scan_line(line, accumulator, None)

        return accumulator

    def _scan_line(
        self,
        line: str,
        accumulator: ScanAccumulator,
        collected: list[Finding] | None,
    ) -> None:
        segment_findings: list[Finding] = []
        for detector in self.detectors:
            segment_findings.extend(detector.detect(line))

        for finding in resolve_overlapping_findings(segment_findings):
            accumulator.add_finding(finding)
            if collected is not None:
                collected.append(finding)

    def verify_text(
        self,
        text: str,
        *,
        allowed_replacements: frozenset[str] | None = None,
        context: TransformationContext | None = None,
    ) -> VerificationReport:
        """Run the post-sanitization verification pass on in-memory text."""
        accumulator = VerificationAccumulator(
            context=context,
            allowed_replacements=allowed_replacements,
        )
        for line in text.splitlines(keepends=True):
            accumulator.feed_segment(line, self.detectors)
        return accumulator.report()

    def verify_stream(
        self,
        input_path: Path,
        *,
        allowed_replacements: frozenset[str] | None = None,
        context: TransformationContext | None = None,
    ) -> VerificationReport:
        """Run the post-sanitization verification pass on a file incrementally."""
        accumulator = VerificationAccumulator(
            context=context,
            allowed_replacements=allowed_replacements,
        )
        for line in iter_file_lines(input_path):
            accumulator.feed_segment(line, self.detectors)
        return accumulator.report()

    def verify_segments(
        self,
        segments: list[str],
        *,
        allowed_replacements: frozenset[str] | None = None,
        context: TransformationContext | None = None,
    ) -> VerificationReport:
        """Verify pre-collected sanitized segments without retaining them together."""
        accumulator = VerificationAccumulator(
            context=context,
            allowed_replacements=allowed_replacements,
        )
        for segment in segments:
            accumulator.feed_segment(segment, self.detectors)
        return accumulator.report()

    def verify_findings(self, findings: list[Finding]) -> VerificationReport:
        """Evaluate pre-collected findings (opt-in API for tests)."""
        return self._evaluate(findings)

    def _evaluate(self, findings: list[Finding]) -> VerificationReport:
        high_risk = 0
        uncertain = 0

        for finding in findings:
            if is_high_risk(finding):
                high_risk += 1
            elif finding.confidence in (Confidence.MEDIUM, Confidence.LOW):
                uncertain += 1

        if high_risk > 0:
            status = VerificationStatus.FAIL
        elif uncertain > 0:
            status = VerificationStatus.REVIEW_REQUIRED
        else:
            status = VerificationStatus.PASS

        return VerificationReport(
            status=status,
            high_risk_findings=high_risk,
            uncertain_findings=uncertain,
        )
