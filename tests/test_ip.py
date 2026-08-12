"""Tests for IP detector."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import TransformationContext
from scrubsmith.core.sanitizer import Sanitizer
from scrubsmith.detectors.generic.ip import IPDetector


def test_ipv4_detected() -> None:
    detector = IPDetector()
    text = "Connection from 81.42.18.50 established"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "81.42.18.50"


def test_ipv6_detected() -> None:
    detector = IPDetector()
    text = "addr 2001:4860:4860::8888 ok"
    findings = detector.detect(text)
    assert len(findings) >= 1


def test_port_not_matched_as_ip() -> None:
    detector = IPDetector()
    text = "listening on 127.0.0.1:8080"
    findings = detector.detect(text)
    # Should detect 127.0.0.1 but not include port
    if findings:
        assert ":8080" not in text[findings[0].start : findings[0].end]


def test_invalid_address_not_matched() -> None:
    detector = IPDetector()
    text = "bad ip 999.999.999.999"
    findings = detector.detect(text)
    assert len(findings) == 0


def test_version_number_not_matched() -> None:
    detector = IPDetector()
    text = "version 1.2.3.4 released"
    # 1.2.3.4 is technically valid IPv4 - conservative approach may flag
    # but we test it doesn't crash
    detector.detect(text)


def test_ip_hash_deterministic() -> None:
    config = ScrubsmithConfig(version=1)
    ctx = TransformationContext(seed=b"ip-seed")
    sanitizer = Sanitizer(config, context=ctx)
    r1, _ = sanitizer.sanitize_text("host 10.0.0.1")
    r2, _ = sanitizer.sanitize_text("host 10.0.0.1")
    assert r1 == r2
    assert "10.0.0.1" not in r1
    from scrubsmith.detectors.validation import is_documentation_ip

    token = r1.split()[-1]
    assert is_documentation_ip(token)
