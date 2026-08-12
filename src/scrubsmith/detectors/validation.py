"""Validation helpers for detectors."""

from __future__ import annotations

import ipaddress
import re

DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"

_DOC_IPV4_NETWORKS = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]
_DOC_IPV6_NETWORK = ipaddress.IPv6Network("2001:db8::/32")


def is_documentation_ip(value: str) -> bool:
    """Return True for RFC documentation/reserved ranges used by Scrubsmith output."""
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv4Address):
        return any(parsed in network for network in _DOC_IPV4_NETWORKS)
    return parsed in _DOC_IPV6_NETWORK


def validate_dni(value: str) -> bool:
    """Validate Spanish DNI control letter."""
    normalized = value.upper().replace("-", "").replace(" ", "")
    if not re.fullmatch(r"\d{8}[A-Z]", normalized):
        return False
    number = int(normalized[:8])
    expected = DNI_LETTERS[number % 23]
    return normalized[8] == expected


def validate_nie(value: str) -> bool:
    """Validate Spanish NIE control letter."""
    normalized = value.upper().replace("-", "").replace(" ", "")
    if not re.fullmatch(r"[XYZ]\d{7}[A-Z]", normalized):
        return False
    prefix_map = {"X": "0", "Y": "1", "Z": "2"}
    numeric = prefix_map[normalized[0]] + normalized[1:8]
    number = int(numeric)
    expected = DNI_LETTERS[number % 23]
    return normalized[8] == expected


def validate_spanish_id(value: str) -> bool:
    """Validate DNI or NIE."""
    normalized = value.upper().replace("-", "").replace(" ", "")
    if normalized[0:1].isdigit():
        return validate_dni(normalized)
    return validate_nie(normalized)


def validate_iban(value: str) -> bool:
    """Validate IBAN checksum (mod 97)."""
    normalized = value.upper().replace(" ", "")
    if len(normalized) < 15 or len(normalized) > 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", normalized):
        return False
    rearranged = normalized[4:] + normalized[:4]
    numeric = ""
    for char in rearranged:
        if char.isdigit():
            numeric += char
        else:
            numeric += str(ord(char) - ord("A") + 10)
    return int(numeric) % 97 == 1


def luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def is_likely_technical_number(text: str, start: int, end: int) -> bool:
    """Return True if numeric span looks like a technical identifier."""
    # Check for port suffix :8080
    if end < len(text) and text[end : end + 1] == ":":
        return True
    if start > 0 and text[start - 1 : start] == ":":
        return True
    # Version numbers like 1.2.3
    return start > 0 and text[start - 1 : start] in {".", "-"}
