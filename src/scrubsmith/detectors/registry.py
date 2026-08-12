"""Detector registry and factory."""

from __future__ import annotations

from scrubsmith.config import DetectorsConfig, ScrubsmithConfig
from scrubsmith.core.models import Category, Strategy
from scrubsmith.detectors.base import Detector
from scrubsmith.detectors.es.identity import SpanishIdentityDetector
from scrubsmith.detectors.generic.credit_card import CreditCardDetector
from scrubsmith.detectors.generic.email import EmailDetector
from scrubsmith.detectors.generic.iban import IBANDetector
from scrubsmith.detectors.generic.ip import IPDetector
from scrubsmith.detectors.generic.phone import PhoneDetector
from scrubsmith.detectors.generic.secrets import SecretsDetector

_CATEGORY_TO_CONFIG_KEY: dict[Category, str] = {
    Category.EMAIL: "email",
    Category.PHONE: "phone",
    Category.IP: "ip",
    Category.IBAN: "iban",
    Category.SPANISH_ID: "spanish_id",
    Category.CREDIT_CARD: "credit_card",
    Category.SECRET: "secrets",
}


def build_detectors(config: ScrubsmithConfig | None = None) -> list[Detector]:
    """Instantiate enabled detectors from configuration."""
    cfg = config or ScrubsmithConfig(version=1)
    detectors: list[Detector] = []
    detector_config: DetectorsConfig = cfg.detectors

    mapping = {
        "email": (EmailDetector, detector_config.email),
        "phone": (PhoneDetector, detector_config.phone),
        "ip": (IPDetector, detector_config.ip),
        "iban": (IBANDetector, detector_config.iban),
        "spanish_id": (SpanishIdentityDetector, detector_config.spanish_id),
        "credit_card": (CreditCardDetector, detector_config.credit_card),
        "secrets": (SecretsDetector, detector_config.secrets),
    }

    for _name, (cls, det_cfg) in mapping.items():
        if det_cfg.enabled:
            detectors.append(cls())

    return detectors


def get_strategy_for_category(config: ScrubsmithConfig, category: Category) -> Strategy:
    """Return configured strategy for a finding category."""
    key = _CATEGORY_TO_CONFIG_KEY[category]
    det_cfg = getattr(config.detectors, key)
    return det_cfg.strategy if det_cfg.enabled else Strategy.REDACT
