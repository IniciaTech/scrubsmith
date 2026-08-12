"""Deterministic transformation context for cross-value correlation."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from typing import Final

from scrubsmith.core.models import Category
from scrubsmith.detectors.validation import validate_nie

RESERVED_EMAIL_DOMAIN: Final = "example.test"
REDACTED_PLACEHOLDER: Final = "[REDACTED]"
REDACTED_PRIVATE_KEY_PLACEHOLDER: Final = "[REDACTED PRIVATE KEY]"

# RFC 5737 / RFC 3849 documentation ranges used for synthetic IPv4/IPv6 output.
_DOC_IPV4_NETWORKS: Final = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]
_DOC_IPV6_NETWORK: Final = ipaddress.IPv6Network("2001:db8::/32")


class TransformationContext:
    """
    In-memory context for deterministic pseudonymization.

    Pseudonyms are derived with HMAC-SHA256 from (category, original value) and
    an operation seed. This provides deterministic correlation within one run,
    not guaranteed anonymization. Low-entropy ``--seed`` values are reproducible
    but may be vulnerable to dictionary guessing; the default ephemeral seed
    is cryptographically random.

    Designed to be shared across source processors in future bundle operations.
    Mappings exist only in memory for the duration of a single operation.

    Current correlation is value-level: ``(category, original value) -> pseudonym``.
    A future bundle/database phase may add entity-level context so fields from the
    same logical record share a coherent synthetic identity.

    The pseudonym cache may grow with the number of unique transformed values in
    one operation. It is not persisted and is not written to disk.
    """

    def __init__(self, seed: bytes | None = None) -> None:
        if seed is None:
            seed = secrets.token_bytes(32)
        self._seed = seed
        self._cache: dict[tuple[Category, str], str] = {}
        self._generated_replacements: set[str] = {
            REDACTED_PLACEHOLDER,
            REDACTED_PRIVATE_KEY_PLACEHOLDER,
        }

    @property
    def seed_hex(self) -> str:
        """Return hex representation of the seed (for reporting only)."""
        return self._seed.hex()

    @property
    def generated_replacements(self) -> frozenset[str]:
        """
        Replacement values produced during this operation.

        Used only by the post-sanitization verification pass to avoid false
        positives on Scrubsmith-generated synthetic values. Standalone scan does
        not use this allowlist.
        """
        return frozenset(self._generated_replacements)

    def derive_token(self, category: Category, value: str, length: int = 6) -> str:
        """Derive a short deterministic token from category and value."""
        digest = hmac.new(
            self._seed,
            f"{category.value}:{value}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return digest[:length]

    def get_or_create(self, category: Category, value: str, factory: str) -> str:
        """Return cached replacement or create one using factory name."""
        key = (category, value)
        if key in self._cache:
            return self._cache[key]

        factories = {
            "email": self._fake_email,
            "phone": self._fake_phone,
            "iban": self._fake_iban,
            "spanish_id": self._fake_spanish_id,
            "ip": self._synthetic_ip,
        }
        factory_fn = factories.get(factory)
        if factory_fn is not None:
            replacement = factory_fn(value)
        else:
            replacement = f"pseudo-{self.derive_token(category, value)}"

        self._cache[key] = replacement
        self._generated_replacements.add(replacement)
        return replacement

    def record_generated(self, value: str) -> None:
        """Record a safe replacement value for post-sanitization verification."""
        self._generated_replacements.add(value)

    def _fake_email(self, value: str) -> str:
        token = self.derive_token(Category.EMAIL, value)
        return f"user-{token}@{RESERVED_EMAIL_DOMAIN}"

    def _fake_phone(self, value: str) -> str:
        token = self.derive_token(Category.PHONE, value)
        return f"phone-{token}"

    def _fake_iban(self, value: str) -> str:
        token = self.derive_token(Category.IBAN, value)
        return f"iban-{token}"

    def _fake_spanish_id(self, value: str) -> str:
        token = self.derive_token(Category.SPANISH_ID, value)
        normalized = value.upper().replace("-", "").replace(" ", "")
        if validate_nie(normalized) or normalized[:1] in {"X", "Y", "Z"}:
            return f"nie-{token}"
        return f"dni-{token}"

    def _synthetic_ip(self, value: str) -> str:
        token = self.derive_token(Category.IP, value, length=8)
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return f"ip-{token}"

        if isinstance(parsed, ipaddress.IPv6Address):
            suffix = int(token, 16) % (2**32)
            return str(ipaddress.IPv6Address(int(_DOC_IPV6_NETWORK.network_address) + suffix))

        offset = int(token, 16) % 762  # 254 * 3 host offsets across the three /24 nets
        network = _DOC_IPV4_NETWORKS[offset // 254]
        host = (offset % 254) + 1
        return str(network.network_address + host)
