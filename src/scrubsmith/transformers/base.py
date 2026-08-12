"""Transformation strategy implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod

from scrubsmith.core.context import REDACTED_PLACEHOLDER, TransformationContext
from scrubsmith.core.models import Category, Finding, Strategy


class Transformer(ABC):
    """Base transformer applying a strategy to a finding."""

    strategy: Strategy

    @abstractmethod
    def transform(self, text: str, finding: Finding, context: TransformationContext) -> str:
        """Return replacement text for the finding span."""
        ...


class RedactTransformer(Transformer):
    """Replace sensitive values with a redaction placeholder."""

    strategy = Strategy.REDACT

    def transform(self, text: str, finding: Finding, context: TransformationContext) -> str:
        return REDACTED_PLACEHOLDER


class FakeTransformer(Transformer):
    """Generate type-compatible synthetic replacements."""

    strategy = Strategy.FAKE

    _FACTORY_MAP: dict[Category, str] = {
        Category.EMAIL: "email",
        Category.PHONE: "phone",
        Category.IBAN: "iban",
        Category.SPANISH_ID: "spanish_id",
    }

    def transform(self, text: str, finding: Finding, context: TransformationContext) -> str:
        factory = self._FACTORY_MAP.get(finding.category, "generic")
        original = text[finding.start : finding.end]
        return context.get_or_create(finding.category, original, factory)


class HashTransformer(Transformer):
    """Generate deterministic pseudonyms using HMAC-derived tokens."""

    strategy = Strategy.HASH

    def transform(self, text: str, finding: Finding, context: TransformationContext) -> str:
        original = text[finding.start : finding.end]
        if finding.category == Category.IP:
            return context.get_or_create(finding.category, original, "ip")
        token = context.derive_token(finding.category, original)
        prefix = finding.category.value.replace("_", "-")
        return f"{prefix}-{token}"


def get_transformer(strategy: Strategy) -> Transformer:
    """Return transformer instance for a strategy."""
    mapping: dict[Strategy, Transformer] = {
        Strategy.REDACT: RedactTransformer(),
        Strategy.FAKE: FakeTransformer(),
        Strategy.HASH: HashTransformer(),
    }
    return mapping[strategy]
