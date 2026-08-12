# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-12

### Added

- Initial Phase 1 release: plain-text log sanitization
- Sensitive-data and secret detectors (email, IP, phone, IBAN, credit card, Spanish DNI/NIE)
- Deterministic transformation strategies: redact, fake, hash
- Post-sanitization verification pass (re-scan with built-in detectors)
- Streaming log processing
- CLI: `scrubsmith sanitize logs`, `scrubsmith scan`, `--version`
- YAML configuration with strict validation
- Comprehensive unit tests

[0.1.0]: https://github.com/scrubsmith/scrubsmith/releases/tag/v0.1.0
