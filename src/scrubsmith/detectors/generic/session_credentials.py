"""Session credential detection helpers."""

from __future__ import annotations

import re
from collections.abc import Callable

from scrubsmith.core.models import Category, Confidence, Finding, Severity

MIN_SESSION_TOKEN_LEN = 16
MAX_SESSION_TOKEN_LEN = 512
MIN_SESSION_PAYLOAD_LEN = 8
MAX_SESSION_PAYLOAD_LEN = 65535

_SESSION_TOKEN_CHARS = re.compile(r"^[A-Za-z0-9_\-+/=]+$")
_SOFTWARE_VERSION_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+._-]*")

# Strong sessions-table SQL context: SELECT or UPDATE ... WHERE id = ...
SESSIONS_TABLE_WHERE_ID = re.compile(
    r"(?is)"
    r"\b(?:from|update)\s+[`']?sessions[`']?\b"
    r".*?"
    r"\bwhere\s+[`']?id[`']?\s*=\s*"
    r"(?:['\"`])?"
    r"(?P<token>[A-Za-z0-9_\-+/=]{"
    + str(MIN_SESSION_TOKEN_LEN)
    + r","
    + str(MAX_SESSION_TOKEN_LEN)
    + r"})"
    r"(?:['\"`])?"
    r"(?=\s|$|[;\)\],]|limit\b)"
)

# UPDATE sessions SET ... payload = ... (opaque session body).
SESSIONS_UPDATE_PAYLOAD = re.compile(
    r"(?is)"
    r"\bupdate\s+[`']?sessions[`']?\b"
    r".*?"
    r"[`']?payload[`']?\s*=\s*"
    r"(?P<raw>"
    r"'(?P<sq>[^']*)'"
    r'|"(?P<dq>[^"]*)"'
    r"|`(?P<bq>[^`]*)`"
    r"|(?P<unquoted>[^\s,;]+)"
    r")"
)

SESSION_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)"
    r"(?<![\w-])"
    r"(?:PHPSESSID|session[_-]?token|session[_-]?id|sessionid|session)"
    r"\s*[=:]\s*"
    r"(?P<token>[^\s,;'\"]+)"
)

SESSION_JSON_FIELD = re.compile(
    r'(?i)["\']session[_-]?id["\']\s*:\s*["\'](?P<token>[^"\']+)["\']'
)

SESSION_PHP_ARRAY = re.compile(
    r"""(?i)['"]session[_-]?id['"]\s*=>\s*['"](?P<token>[^'"]+)['"]"""
)

SESSION_COOKIE_PAIR = re.compile(
    r"(?i)(?<![\w-])(?:PHPSESSID|session[_-]?id|session[_-]?token)\s*=\s*"
    r"(?P<token>[^\s;,]+)"
)


def is_plausible_session_token(value: str) -> bool:
    """Return True for session-like token values with sensible bounds."""
    if value in {"[REDACTED]", "null", "None", "undefined", ""}:
        return False
    if not MIN_SESSION_TOKEN_LEN <= len(value) <= MAX_SESSION_TOKEN_LEN:
        return False
    return _SESSION_TOKEN_CHARS.fullmatch(value) is not None


def is_plausible_session_payload(value: str) -> bool:
    """Return True for opaque session payload values in sessions-table UPDATE."""
    if value in {"[REDACTED]", "null", "None", "undefined", ""}:
        return False
    return MIN_SESSION_PAYLOAD_LEN <= len(value) <= MAX_SESSION_PAYLOAD_LEN


def _extract_payload_value(match: re.Match[str]) -> str | None:
    for group in ("sq", "dq", "bq", "unquoted"):
        value = match.group(group)
        if value is not None:
            return value
    return match.group("raw")


def _finding_for_token(
    text: str,
    token: str,
    *,
    detector: str,
    token_start: int | None = None,
    validator: Callable[[str], bool] = is_plausible_session_token,
) -> Finding | None:
    if not validator(token):
        return None
    if token_start is None:
        token_start = text.find(token)
    if token_start < 0:
        return None
    return Finding(
        category=Category.SECRET,
        start=token_start,
        end=token_start + len(token),
        confidence=Confidence.HIGH,
        detector=detector,
        severity=Severity.CRITICAL,
    )


def detect_session_credentials(text: str, *, detector_prefix: str) -> list[Finding]:
    """Detect session identifiers only when strong session context is present."""
    findings: list[Finding] = []

    for match in SESSIONS_TABLE_WHERE_ID.finditer(text):
        finding = _finding_for_token(
            text,
            match.group("token"),
            detector=f"{detector_prefix}.sessions_sql",
            token_start=match.start("token"),
        )
        if finding is not None:
            findings.append(finding)

    for match in SESSIONS_UPDATE_PAYLOAD.finditer(text):
        payload = _extract_payload_value(match)
        if payload is None:
            continue
        # Locate payload span inside the matched assignment.
        payload_start = match.start("raw")
        if (
            match.group("sq") is not None
            or match.group("dq") is not None
            or match.group("bq") is not None
        ):
            payload_start += 1
        finding = _finding_for_token(
            text,
            payload,
            detector=f"{detector_prefix}.sessions_payload",
            token_start=payload_start,
            validator=is_plausible_session_payload,
        )
        if finding is not None:
            findings.append(finding)

    for pattern, label in (
        (SESSION_CREDENTIAL_ASSIGNMENT, "session_assignment"),
        (SESSION_JSON_FIELD, "session_json"),
        (SESSION_PHP_ARRAY, "session_php"),
        (SESSION_COOKIE_PAIR, "session_cookie"),
    ):
        for match in pattern.finditer(text):
            finding = _finding_for_token(
                text,
                match.group("token"),
                detector=f"{detector_prefix}.{label}",
                token_start=match.start("token"),
            )
            if finding is not None:
                findings.append(finding)

    return findings
