# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Scrubsmith, please report it responsibly.

**Do not** open a public GitHub issue for security-sensitive reports.

Instead, email the maintainers with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Important:** Do not include real production data, credentials, or personal information in your report. Use synthetic examples only.

## Scope

Security reports may include:

- Bypasses of sanitization or verification
- Sensitive data leakage in reports, logs, or exceptions
- Unsafe file handling
- Deterministic pseudonymization weaknesses that enable re-identification at scale

## Out of Scope

- General false positive/negative tuning (use regular issues)
- Legal compliance questions
- Feature requests

## Safe Harbor

We appreciate responsible disclosure and will work with reporters in good faith.

## Security Design Principles

Scrubsmith follows these principles:

- **Local-only processing** — no network calls, telemetry, or cloud dependencies in core functionality
- **No secret persistence** — original-to-pseudonym mappings exist only in memory for a single operation
- **Safe reporting** — reports contain metadata and counts, never matched sensitive values
- **Post-sanitization verification pass** — sanitized output is re-scanned by the verifier using the same built-in detector pipeline (alternative engines may be added later)
- **Conservative detection** — secrets are redacted, not faked

## Limitations

No automated tool can guarantee that arbitrary diagnostic data contains no sensitive information. Scrubsmith output must always be reviewed by a human before external sharing.

Pseudonymization is not necessarily anonymization. Pseudonymized data may still constitute personal data under applicable regulations.

Scrubsmith is not legal advice and does not certify regulatory compliance.
