"""Recognition of Scrubsmith-generated synthetic value formats."""

from __future__ import annotations

import ipaddress
import re

from scrubsmith.core.context import _DOC_IPV4_NETWORKS, _DOC_IPV6_NETWORK
from scrubsmith.core.models import Category, Finding

# Tokens are lowercase hex substrings of HMAC-SHA256 digests (default length 6).
_TOKEN = r"[0-9a-f]{6}"

SCRUBSMITH_EMAIL_RE = re.compile(rf"^user-{_TOKEN}@example\.test$")
SCRUBSMITH_PHONE_RE = re.compile(rf"^phone-{_TOKEN}$")
SCRUBSMITH_DNI_RE = re.compile(rf"^dni-{_TOKEN}$")
SCRUBSMITH_NIE_RE = re.compile(rf"^nie-{_TOKEN}$")
SCRUBSMITH_IBAN_RE = re.compile(rf"^iban-{_TOKEN}$")


def is_scrubsmith_doc_ipv4(value: str) -> bool:
    """Return True for IPv4 addresses in Scrubsmith documentation output ranges."""
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    for network in _DOC_IPV4_NETWORKS:
        if addr in network and addr != network.network_address:
            return True
    return False


def is_scrubsmith_doc_ipv6(value: str) -> bool:
    """Return True for IPv6 addresses in the Scrubsmith documentation output prefix."""
    try:
        addr = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return addr in _DOC_IPV6_NETWORK


def is_scrubsmith_synthetic_value(matched: str, finding: Finding) -> bool:
    """
    Return True when a matched span matches a well-defined Scrubsmith synthetic format.

    Used only in SCRUBSMITH_OUTPUT scan mode. Does not allow arbitrary values in
    reserved namespaces unless they match the exact generated shape.
    """
    value = matched.strip()

    if finding.category == Category.EMAIL:
        return SCRUBSMITH_EMAIL_RE.fullmatch(value) is not None
    if finding.category == Category.PHONE:
        return SCRUBSMITH_PHONE_RE.fullmatch(value) is not None
    if finding.category == Category.SPANISH_ID:
        return (
            SCRUBSMITH_DNI_RE.fullmatch(value) is not None
            or SCRUBSMITH_NIE_RE.fullmatch(value) is not None
        )
    if finding.category == Category.IBAN:
        return SCRUBSMITH_IBAN_RE.fullmatch(value) is not None
    if finding.category == Category.IP:
        return is_scrubsmith_doc_ipv4(value) or is_scrubsmith_doc_ipv6(value)

    return False
