"""Tests for YAML configuration."""

from pathlib import Path

import pytest

from scrubsmith.config import ScrubsmithConfig, load_config


def test_valid_configuration() -> None:
    config = ScrubsmithConfig(version=1)
    assert config.detectors.email.enabled is True
    assert config.detectors.secrets.strategy.value == "redact"


def test_unknown_field_rejected(tmp_path: Path) -> None:
    cfg_file = tmp_path / "bad.yml"
    cfg_file.write_text(
        "version: 1\nunknown_key: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid configuration"):
        load_config(cfg_file)


def test_invalid_strategy_rejected(tmp_path: Path) -> None:
    cfg_file = tmp_path / "bad.yml"
    cfg_file.write_text(
        "version: 1\ndetectors:\n  email:\n    enabled: true\n    strategy: destroy\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid configuration"):
        load_config(cfg_file)


def test_malformed_yaml(tmp_path: Path) -> None:
    cfg_file = tmp_path / "bad.yml"
    cfg_file.write_text("version: [1,\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_config(cfg_file)


def test_load_from_file(tmp_path: Path) -> None:
    cfg_file = tmp_path / "good.yml"
    cfg_file.write_text(
        "version: 1\ndetectors:\n  ip:\n    enabled: true\n    strategy: hash\n",
        encoding="utf-8",
    )
    config = load_config(cfg_file)
    assert config.detectors.ip.strategy.value == "hash"
