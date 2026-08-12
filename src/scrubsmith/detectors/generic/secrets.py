"""Secret and credential detector."""

from __future__ import annotations

import re

from scrubsmith.core.models import Category, Confidence, Finding, Severity
from scrubsmith.detectors.base import RegexDetector
from scrubsmith.detectors.generic.session_credentials import detect_session_credentials

# JWT: three base64url segments
JWT_PATTERN = re.compile(
    r"(?<![\w-])"
    r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
    r"(?![\w-])"
)

BEARER_PATTERN = re.compile(
    r"(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)",
    re.IGNORECASE,
)

AUTHORIZATION_HEADER = re.compile(
    r"(Authorization\s*:\s*)([^\r\n]+)",
    re.IGNORECASE,
)

API_KEY_ASSIGNMENT = re.compile(
    r"(?i)((?:api[_-]?key|apikey|x-api-key)\s*[=:]\s*)([^\s,;'\"]+)",
)

PASSWORD_ASSIGNMENT = re.compile(
    r"(?i)((?:password|passwd|pwd)\s*[=:]\s*)([^\s,;'\"]+)",
)

SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:secret|client[_-]?secret)\s*[=:]\s*)([^\s,;'\"]+)",
)

ACCESS_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)((?:access[_-]?token|access_token)\s*[=:]\s*)([^\s,;'\"]+)",
)

REFRESH_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)((?:refresh[_-]?token|refresh_token)\s*[=:]\s*)([^\s,;'\"]+)",
)

SESSION_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)((?:session[_-]?token|session[_-]?id|sess(?:ion)?id)\s*[=:]\s*)([^\s,;'\"]+)",
)

COOKIE_HEADER = re.compile(
    r"(Cookie\s*:\s*)([^\r\n]+)",
    re.IGNORECASE,
)

PEM_PRIVATE_KEY_START = "-----BEGIN"
PEM_PRIVATE_KEY_END = "-----END"


class SecretsDetector(RegexDetector):
    """Detect secrets, credentials, and private keys."""

    category = Category.SECRET
    name = "generic.secrets"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_jwt(text))
        findings.extend(self._detect_bearer(text))
        findings.extend(self._detect_authorization(text))
        findings.extend(self._detect_assignments(text))
        findings.extend(self._detect_session_credentials(text))
        findings.extend(self._detect_cookie(text))
        findings.extend(self._detect_pem(text))
        return self.merge_non_overlapping(findings)

    def _detect_jwt(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in JWT_PATTERN.finditer(text):
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(1),
                    end=match.end(1),
                    confidence=Confidence.HIGH,
                    detector=f"{self.name}.jwt",
                    severity=Severity.CRITICAL,
                )
            )
        return findings

    def _detect_bearer(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in BEARER_PATTERN.finditer(text):
            token = match.group(2)
            if len(token) < 10:
                continue
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(2),
                    end=match.end(2),
                    confidence=Confidence.HIGH,
                    detector=f"{self.name}.bearer",
                    severity=Severity.CRITICAL,
                )
            )
        return findings

    def _detect_authorization(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in AUTHORIZATION_HEADER.finditer(text):
            value = match.group(2).strip()
            if value.lower().startswith("bearer "):
                # Bearer handled separately
                continue
            if len(value) < 8:
                continue
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(2),
                    end=match.end(2),
                    confidence=Confidence.HIGH,
                    detector=f"{self.name}.authorization",
                    severity=Severity.CRITICAL,
                )
            )
        return findings

    def _detect_assignments(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        patterns = [
            (API_KEY_ASSIGNMENT, "api_key"),
            (PASSWORD_ASSIGNMENT, "password"),
            (SECRET_ASSIGNMENT, "secret"),
            (ACCESS_TOKEN_ASSIGNMENT, "access_token"),
            (REFRESH_TOKEN_ASSIGNMENT, "refresh_token"),
            (SESSION_TOKEN_ASSIGNMENT, "session_token"),
        ]
        for pattern, label in patterns:
            for match in pattern.finditer(text):
                value = match.group(2)
                if value in {"[REDACTED]", "null", "None", "undefined", ""}:
                    continue
                if len(value) < 4:
                    continue
                findings.append(
                    Finding(
                        category=self.category,
                        start=match.start(2),
                        end=match.end(2),
                        confidence=Confidence.HIGH,
                        detector=f"{self.name}.{label}",
                        severity=Severity.CRITICAL,
                    )
                )
        return findings

    def _detect_session_credentials(self, text: str) -> list[Finding]:
        return detect_session_credentials(text, detector_prefix=self.name)

    def _detect_cookie(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in COOKIE_HEADER.finditer(text):
            findings.append(
                Finding(
                    category=self.category,
                    start=match.start(2),
                    end=match.end(2),
                    confidence=Confidence.HIGH,
                    detector=f"{self.name}.cookie",
                    severity=Severity.HIGH,
                )
            )
        return findings

    def _detect_pem(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        search_start = 0
        while True:
            idx = text.find(PEM_PRIVATE_KEY_START, search_start)
            if idx == -1:
                break
            if "PRIVATE KEY" not in text[idx : idx + 30]:
                search_start = idx + 1
                continue
            end_marker = text.find(PEM_PRIVATE_KEY_END, idx)
            if end_marker == -1:
                findings.append(
                    Finding(
                        category=self.category,
                        start=idx,
                        end=len(text),
                        confidence=Confidence.HIGH,
                        detector=f"{self.name}.pem_incomplete",
                        severity=Severity.CRITICAL,
                    )
                )
                break
            line_end = text.find("\n", end_marker)
            block_end = line_end + 1 if line_end != -1 else len(text)
            findings.append(
                Finding(
                    category=self.category,
                    start=idx,
                    end=block_end,
                    confidence=Confidence.HIGH,
                    detector=f"{self.name}.pem",
                    severity=Severity.CRITICAL,
                )
            )
            search_start = block_end
        return findings
