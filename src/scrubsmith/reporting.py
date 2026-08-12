"""Report formatting utilities."""

from __future__ import annotations

import json
from pathlib import Path

from scrubsmith.core.models import SanitizationReport, ScanSummary, VerificationStatus


def format_scan_report(summary: ScanSummary, status: VerificationStatus) -> str:
    """Format scan command output."""
    lines = [
        "Potential sensitive data",
        "",
        f"Emails:                  {summary.emails}",
        f"Phone numbers:           {summary.phone_numbers}",
        f"Spanish DNI/NIE:         {summary.spanish_dni_nie}",
        f"IP addresses:            {summary.ip_addresses}",
        f"IBAN:                    {summary.ibans}",
        f"Potential secrets:       {summary.potential_secrets}",
        "",
        f"Result: {status.value}",
    ]
    return "\n".join(lines)


def format_sanitization_report(report: SanitizationReport) -> str:
    """Format sanitization command output."""
    stats = report.stats
    verification = report.verification
    lines = [
        "Scrubsmith sanitization report",
        "",
        f"Lines processed:            {stats.lines_processed:>6}",
        f"Values transformed:           {stats.values_transformed:>6}",
        f"Secrets redacted:             {stats.secrets_redacted:>6}",
        f"PII pseudonymized:            {stats.pii_pseudonymized:>6}",
        "",
        "Verifier:",
        f"High-risk findings:           {verification.high_risk_findings:>6}",
        f"Uncertain findings:           {verification.uncertain_findings:>6}",
        "",
        f"Result: {verification.status.value}",
    ]
    return "\n".join(lines)


def write_json_report(report: SanitizationReport, path: Path) -> None:
    """Write machine-readable sanitization report."""
    payload = {
        "lines_processed": report.stats.lines_processed,
        "values_transformed": report.stats.values_transformed,
        "secrets_redacted": report.stats.secrets_redacted,
        "pii_pseudonymized": report.stats.pii_pseudonymized,
        "verifier": {
            "high_risk_findings": report.verification.high_risk_findings,
            "uncertain_findings": report.verification.uncertain_findings,
            "status": report.verification.status.value,
        },
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
