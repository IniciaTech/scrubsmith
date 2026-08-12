"""Deterministic overlap resolution for detector findings.

When multiple detectors match overlapping spans, a single winning finding is
selected per overlap cluster. Replacements are then applied from end to start
so indices remain valid.

Resolution policy (highest priority wins within each overlap cluster):

1. Category precedence (security-sensitive first):
   SECRET > CREDIT_CARD > SPANISH_ID > EMAIL > IBAN > PHONE > IP
2. Severity: critical > high > medium > low
3. Enclosing span: longer match wins (e.g. a password assignment over an
   email embedded in the secret value)
4. Start position: earlier span wins ties

Examples:
- ``password=john@example.com`` → the password secret assignment wins over
  the embedded email; the entire secret value is redacted.
- ``Authorization: Bearer <JWT>`` → one SECRET finding wins for the token
  span (JWT / Bearer matches collapse to a single replacement).

Alternative verification engines may supply their own findings; this policy
applies to the built-in detector pipeline only.
"""

from __future__ import annotations

from scrubsmith.core.models import Category, Finding, Severity

_CATEGORY_PRECEDENCE: dict[Category, int] = {
    Category.SECRET: 70,
    Category.CREDIT_CARD: 60,
    Category.SPANISH_ID: 50,
    Category.EMAIL: 40,
    Category.IBAN: 30,
    Category.PHONE: 20,
    Category.IP: 10,
}

_SEVERITY_PRECEDENCE: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 30,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
}


def finding_priority(finding: Finding) -> tuple[int, int, int, int]:
    """Return a sortable priority tuple; higher values win overlap conflicts."""
    span_length = finding.end - finding.start
    return (
        _CATEGORY_PRECEDENCE.get(finding.category, 0),
        _SEVERITY_PRECEDENCE.get(finding.severity, 0),
        span_length,
        -finding.start,
    )


def findings_overlap(a: Finding, b: Finding) -> bool:
    """Return True when two findings share at least one character position."""
    return a.start < b.end and b.start < a.end


def _overlap_clusters(findings: list[Finding]) -> list[list[Finding]]:
    """Group findings into clusters of mutually overlapping spans."""
    if not findings:
        return []

    sorted_findings = sorted(findings, key=lambda f: (f.start, f.end))
    clusters: list[list[Finding]] = [[sorted_findings[0]]]
    cluster_end = sorted_findings[0].end

    for finding in sorted_findings[1:]:
        if finding.start < cluster_end:
            clusters[-1].append(finding)
            cluster_end = max(cluster_end, finding.end)
        else:
            clusters.append([finding])
            cluster_end = finding.end

    return clusters


def resolve_overlapping_findings(findings: list[Finding]) -> list[Finding]:
    """Select one winning finding per overlap cluster."""
    if not findings:
        return []

    resolved: list[Finding] = []
    for cluster in _overlap_clusters(findings):
        winner = max(cluster, key=finding_priority)
        resolved.append(winner)

    return sorted(resolved, key=lambda f: (f.start, f.end))
