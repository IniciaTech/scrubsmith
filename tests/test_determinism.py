"""Tests for deterministic pseudonymization."""

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.context import TransformationContext
from scrubsmith.core.sanitizer import Sanitizer


def test_repeated_values_identical() -> None:
    config = ScrubsmithConfig(version=1)
    ctx = TransformationContext(seed=b"deterministic")
    sanitizer = Sanitizer(config, context=ctx)
    result, _ = sanitizer.sanitize_text("a@x.com and a@x.com")
    parts = result.replace(" and ", " ").split()
    assert parts[0] == parts[1]


def test_different_values_different() -> None:
    config = ScrubsmithConfig(version=1)
    ctx = TransformationContext(seed=b"deterministic")
    sanitizer = Sanitizer(config, context=ctx)
    r1, _ = sanitizer.sanitize_text("a@x.com")
    r2, _ = sanitizer.sanitize_text("b@y.com")
    assert r1 != r2


def test_same_seed_same_output() -> None:
    config = ScrubsmithConfig(version=1)
    text = "user@test.org logged in from 192.168.1.1"
    s1 = Sanitizer(config, context=TransformationContext(seed=b"seed-abc"))
    s2 = Sanitizer(config, context=TransformationContext(seed=b"seed-abc"))
    out1, _ = s1.sanitize_text(text)
    out2, _ = s2.sanitize_text(text)
    assert out1 == out2


def test_different_seeds_different_output() -> None:
    config = ScrubsmithConfig(version=1)
    text = "user@test.org"
    s1 = Sanitizer(config, context=TransformationContext(seed=b"seed-one"))
    s2 = Sanitizer(config, context=TransformationContext(seed=b"seed-two"))
    out1, _ = s1.sanitize_text(text)
    out2, _ = s2.sanitize_text(text)
    assert out1 != out2


def test_no_mapping_persisted_to_disk(tmp_path) -> None:
    config = ScrubsmithConfig(version=1)
    ctx = TransformationContext(seed=b"no-persist")
    sanitizer = Sanitizer(config, context=ctx)
    sanitizer.sanitize_text("secret@data.com")
    # Context cache is in-memory only
    assert len(ctx._cache) > 0
    mapping_files = list(tmp_path.glob("*mapping*"))
    assert len(mapping_files) == 0
