# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-12

### Added

- Initial Phase 1 release: plain-text log sanitization
- Sensitive-data and secret detectors (email, IP, phone, IBAN, credit card, Spanish DNI/NIE)
- Session credential detection (SQL session queries, payloads, cookie pairs, UUID session IDs)
- Deterministic transformation strategies: redact, fake, hash
- Post-sanitization verification pass (re-scan with built-in detectors)
- `scrubsmith scan --scrubsmith-output` for verifying Scrubsmith-generated output in a separate process
- Streaming log processing
- CLI: `scrubsmith sanitize logs`, `scrubsmith scan`, `--version`
- YAML configuration with strict validation
- Scan report: credit-card counts and total findings; sanitize stats by strategy (PII pseudonymized, secrets redacted)
- Comprehensive unit tests

### Fixed

- Phone false positives in embedded alphanumeric tokens and structured-field ambiguity
- Credit-card false positives in filename-like tokens
- IPv4 misclassification of dotted software versions (e.g. browser user-agent strings)
- In-process verifier context mismatch causing intermittent verification FAIL after sanitize

[0.1.0]: https://github.com/scrubsmith/scrubsmith/releases/tag/v0.1.0
