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

_SOFTWARE_VERSION_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+._-]*")


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


def is_embedded_in_alphanumeric_token(text: str, start: int, end: int) -> bool:
    """Return True when a span is directly adjacent to alphanumeric characters."""
    if start > 0 and text[start - 1].isalnum():
        return True
    return end < len(text) and text[end].isalnum()


_PHONE_FIELD_KEYS = frozenset(
    {
        "phone",
        "telephone",
        "tel",
        "mobile",
        "mobile_phone",
        "phone_number",
    }
)

_STRUCTURED_FIELD_VALUE = re.compile(r"(?P<key>[a-zA-Z_][\w-]*)\s*[:=]\s*$")


def normalize_field_key(key: str) -> str:
    """Normalize a structured field key for phone-related checks."""
    return key.lower().replace("-", "_")


def is_phone_related_field_key(key: str) -> bool:
    """Return True when a field key explicitly denotes a phone value."""
    normalized = normalize_field_key(key)
    if normalized in _PHONE_FIELD_KEYS:
        return True
    return normalized.replace("_", "") in {
        "phone",
        "telephone",
        "tel",
        "mobile",
        "mobilephone",
        "phonenumber",
    }


def structured_field_key_before_value(
    text: str, start: int, *, window_size: int = 64
) -> str | None:
    """Return the field key when ``start`` begins a structured ``key=value`` value."""
    window = text[max(0, start - window_size) : start]
    match = _STRUCTURED_FIELD_VALUE.search(window)
    if match is None:
        return None
    return match.group("key")


def has_phone_field_context(text: str, start: int) -> bool:
    """Return True when the span follows a phone-related field assignment."""
    window_size = 32
    key = structured_field_key_before_value(text, start, window_size=window_size)
    if key is not None and is_phone_related_field_key(key):
        return True
    window = text[max(0, start - window_size) : start]
    paren_match = re.search(r"(?P<key>[a-zA-Z_][\w-]*)\s*=\s*\(\s*$", window)
    return paren_match is not None and is_phone_related_field_key(paren_match.group("key"))


def is_non_phone_structured_field_value(text: str, start: int) -> bool:
    """Return True when a value belongs to a structured non-phone field assignment."""
    key = structured_field_key_before_value(text, start)
    if key is None:
        return False
    return not is_phone_related_field_key(key)


def is_after_list_delimiter(text: str, start: int) -> bool:
    """
    Return True when a span follows semicolon or slash-delimited metadata lists.

    Used to reject bare numeric tokens in parameter-list contexts such as HTTP
    User-Agent clauses (e.g. ``; 803025034)``) without vendor-specific rules.
    """
    index = start - 1
    while index >= 0 and text[index].isspace():
        index -= 1
    return index >= 0 and text[index] in {";", "/"}


def is_valid_spanish_local_digits(digits: str) -> bool:
    """Return True for a 9-digit Spanish local number."""
    return len(digits) == 9 and digits[0] in "6789"


def is_dotted_software_version(text: str, start: int) -> bool:
    """
    Return True when a dotted numeric span follows ``Product/`` version syntax.

    Rejects IPv4-shaped version strings such as ``Browser/123.45.67.89`` without
    vendor-specific rules. URL path segments (``/api/10.0.0.1``) are not affected.
    """
    if start == 0 or text[start - 1] != "/":
        return False

    token_end = start - 1
    token_start = token_end
    while token_start > 0 and (
        text[token_start - 1].isalnum() or text[token_start - 1] in "._+-"
    ):
        if text[token_start - 1] == ":":
            return False
        token_start -= 1

    token = text[token_start:token_end]
    if not token or not token[0].isalpha():
        return False

    # Product token inside a URL/path (`/api/10.0.0.1`) — not version syntax.
    if token_start > 0 and text[token_start - 1] == "/":
        return False

    return _SOFTWARE_VERSION_TOKEN.fullmatch(token) is not None
