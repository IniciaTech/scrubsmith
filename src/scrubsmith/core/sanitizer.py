"""Sanitization pipeline orchestrating detection and transformation."""

from __future__ import annotations

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import TransformationContext
from scrubsmith.core.findings_resolution import resolve_overlapping_findings
from scrubsmith.core.models import (
    Category,
    Finding,
    SanitizationReport,
    SanitizationStats,
    Strategy,
)
from scrubsmith.core.verifier import Verifier
from scrubsmith.detectors.base import Detector
from scrubsmith.detectors.registry import build_detectors, get_strategy_for_category
from scrubsmith.transformers.base import Transformer, get_transformer


class Sanitizer:
    """
    Applies detectors and transformers to sanitize text.

    Uses a shared TransformationContext so the same pseudonymization engine
    can later be reused across log, JSON, CSV, and database processors.
    """

    def __init__(
        self,
        config: ScrubsmithConfig,
        context: TransformationContext | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        self.config = config
        self.context = context or TransformationContext()
        self.detectors = detectors if detectors is not None else build_detectors(config)
        self._transformers: dict[Strategy, Transformer] = {}

    def _get_transformer(self, strategy: Strategy) -> Transformer:
        if strategy not in self._transformers:
            self._transformers[strategy] = get_transformer(strategy)
        return self._transformers[strategy]

    def detect(self, text: str) -> list[Finding]:
        """Run all enabled detectors and resolve overlapping findings."""
        all_findings: list[Finding] = []
        for detector in self.detectors:
            all_findings.extend(detector.detect(text))
        return resolve_overlapping_findings(all_findings)

    def sanitize_line(self, line: str, stats: SanitizationStats | None = None) -> str:
        """Sanitize a single line of text."""
        findings = self.detect(line)
        if not findings:
            return line

        sanitized = line
        # Apply replacements from end to start to preserve indices.
        for finding in sorted(findings, key=lambda f: f.start, reverse=True):
            strategy = get_strategy_for_category(self.config, finding.category)
            transformer = self._get_transformer(strategy)
            replacement = transformer.transform(sanitized, finding, self.context)
            sanitized = sanitized[: finding.start] + replacement + sanitized[finding.end :]

            if stats is not None:
                stats.values_transformed += 1
                if finding.category == Category.SECRET:
                    stats.secrets_redacted += 1
                elif strategy == Strategy.REDACT:
                    stats.sensitive_values_redacted += 1
                else:
                    stats.pii_pseudonymized += 1

        return sanitized

    def sanitize_text(self, text: str) -> tuple[str, SanitizationStats]:
        """Sanitize multi-line text (used for verification and tests)."""
        stats = SanitizationStats()
        lines = text.splitlines(keepends=True)
        result_parts: list[str] = []
        for line in lines:
            result_parts.append(self.sanitize_line(line, stats))
            stats.lines_processed += 1
        return "".join(result_parts), stats


def sanitize_and_verify(
    sanitizer: Sanitizer,
    text: str,
    verifier: Verifier | None = None,
) -> tuple[str, SanitizationReport]:
    """Sanitize text and run the post-sanitization verification pass."""
    sanitized, stats = sanitizer.sanitize_text(text)
    v = verifier or Verifier(config=sanitizer.config)
    verification = v.verify_text(
        sanitized,
        allowed_replacements=sanitizer.context.generated_replacements,
    )
    report = SanitizationReport(stats=stats, verification=verification)
    return sanitized, report
