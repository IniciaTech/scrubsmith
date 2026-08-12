"""YAML configuration loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from scrubsmith.core.models import Strategy


class DetectorConfig(BaseModel):
    """Per-detector configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    strategy: Strategy


class DetectorsConfig(BaseModel):
    """All detector configurations."""

    model_config = ConfigDict(extra="forbid")

    email: DetectorConfig = Field(default_factory=lambda: DetectorConfig(strategy=Strategy.FAKE))
    phone: DetectorConfig = Field(default_factory=lambda: DetectorConfig(strategy=Strategy.FAKE))
    ip: DetectorConfig = Field(default_factory=lambda: DetectorConfig(strategy=Strategy.HASH))
    iban: DetectorConfig = Field(default_factory=lambda: DetectorConfig(strategy=Strategy.FAKE))
    spanish_id: DetectorConfig = Field(
        default_factory=lambda: DetectorConfig(strategy=Strategy.FAKE)
    )
    credit_card: DetectorConfig = Field(
        default_factory=lambda: DetectorConfig(strategy=Strategy.REDACT)
    )
    secrets: DetectorConfig = Field(
        default_factory=lambda: DetectorConfig(strategy=Strategy.REDACT)
    )


class ScrubsmithConfig(BaseModel):
    """Root configuration model."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(..., ge=1, le=1)
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)


def default_config() -> ScrubsmithConfig:
    """Return default configuration."""
    return ScrubsmithConfig(version=1)


def load_config(path: Path | None) -> ScrubsmithConfig:
    """Load and validate configuration from a YAML file."""
    if path is None:
        return default_config()

    if not path.is_file():
        msg = f"Configuration file not found: {path}"
        raise FileNotFoundError(msg)

    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML in configuration file: {path}"
        raise ValueError(msg) from exc

    if raw is None:
        return default_config()

    if not isinstance(raw, dict):
        msg = "Configuration root must be a mapping"
        raise ValueError(msg)

    try:
        return ScrubsmithConfig.model_validate(raw)
    except ValidationError as exc:
        msg = f"Invalid configuration: {exc}"
        raise ValueError(msg) from exc
