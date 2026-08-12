# Scrubsmith

**Local-first sanitization for safe debugging and AI sharing.**

Scrubsmith helps developers transform production diagnostic data — logs, JSON, CSV, database extracts, and more — into **safe diagnostic datasets** that preserve useful structure and correlations for debugging, without unnecessarily exposing real identities, credentials, or confidential information.

## The problem

You have 200,000 lines of production logs that would help diagnose an incident, but those logs may contain customer emails, IPs, session tokens, identifiers, or other sensitive data.

Scrubsmith sanitizes the data locally, preserves useful diagnostic correlations, verifies the resulting output, and helps you review it before sharing.

## What Scrubsmith is NOT

- A GDPR compliance product or legal certification tool
- A generic regex redactor
- A cloud DLP product or AI proxy
- A replacement for Presidio or Greenmask

Scrubsmith focuses on the **developer workflow**: detect → transform → preserve correlations → verify → review → share.

## Key features (Phase 1)

- **Local-first** — all processing happens on your machine
- **Offline by default** — no cloud, no LLM, no telemetry, no external APIs
- **Deterministic pseudonymization** — the same identity maps consistently within one operation
- **Post-sanitization verification pass** — output is re-scanned after sanitization using the same built-in detectors (alternative engines may be added later)
- **Streaming** — `sanitize logs` and `scan` process large log files incrementally
- **Conservative detection** — distinguishes high-confidence secrets from uncertain matches

## Installation

Scrubsmith is **not yet published on PyPI**. Until the first release, install from a local checkout:

```bash
git clone https://github.com/scrubsmith/scrubsmith.git
cd scrubsmith
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

After the first PyPI release, installation will be:

```bash
pip install scrubsmith
```

Requires Python 3.12+.

## Quick start

Sanitize a log file:

```bash
scrubsmith sanitize logs application.log --output application.safe.log
```

Scan without modifying:

```bash
scrubsmith scan application.log
```

Dry-run (report only, no output file):

```bash
scrubsmith sanitize logs application.log --dry-run
```

Deterministic pseudonymization with a seed:

```bash
scrubsmith sanitize logs application.log --output application.safe.log --seed my-incident-seed
```

With configuration:

```bash
scrubsmith sanitize logs application.log --output application.safe.log --config scrubsmith.yml
```

See [examples/scrubsmith.yml](examples/scrubsmith.yml) for a sample configuration.

## Example

Original log:

```text
Authentication failed for john@example.com user_id=42
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

After Scrubsmith:

```text
Authentication failed for user-a81f@example.test user_id=42
Authorization: Bearer [REDACTED]
```

The same email always maps to the same pseudonym within one sanitization run.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | PASS — no high-confidence sensitive findings remain |
| `1` | REVIEW_REQUIRED — uncertain findings remain |
| `2` | FAIL — high-confidence secrets or sensitive values remain |
| `3` | ERROR — processing failure |

These codes are designed for CI integration.

## Configuration

```yaml
version: 1

detectors:
  email:
    enabled: true
    strategy: fake

  phone:
    enabled: true
    strategy: fake

  ip:
    enabled: true
    strategy: hash

  iban:
    enabled: true
    strategy: fake

  spanish_id:
    enabled: true
    strategy: fake

  credit_card:
    enabled: true
    strategy: redact

  secrets:
    enabled: true
    strategy: redact
```

Unknown configuration keys and invalid strategies are rejected.

### Transformation strategies

| Strategy | Use case | Example |
|----------|----------|---------|
| `redact` | Secrets and credentials | `password=[REDACTED]` |
| `fake` | Identity-like values | `user-a81f@example.test` |
| `hash` | Deterministic pseudonyms | `192.0.2.42` (RFC documentation range) |

## Architecture

```text
Detector → Finding → Transformer → Sanitized output → Verifier (post-sanitization pass)
                              ↑
                    TransformationContext
                    (shared across sources in future bundles)
```

Detectors identify sensitive spans. Transformers apply strategies using a shared in-memory context for deterministic correlation. The verifier runs a **post-sanitization verification pass**: it re-scans output with the same built-in detector pipeline and does not trust sanitizer assertions, but it is not a separate detection engine.

**Strict scan vs. generated-value-aware verification:** `scrubsmith scan` applies detectors strictly to raw input (including RFC documentation IP ranges). After sanitization, the verification pass may skip only replacement values actually generated during that operation via an in-memory allowlist — never entire IP ranges globally.

File processing is streaming end-to-end: segments are sanitized, verified incrementally, and discarded. Dry-run follows the same path without writing output.

### Deterministic pseudonymization

Pseudonyms are derived with HMAC-SHA256 from `(category, original value)` and an operation seed. This provides reproducible correlation within one run, not guaranteed anonymization. A low-entropy `--seed` is reproducible but may be vulnerable to dictionary guessing; the default ephemeral seed is cryptographically random.

### Overlap resolution

When detectors produce overlapping findings (e.g. a password assignment containing an email), security-sensitive categories take precedence and enclosing spans win, so secrets are fully redacted rather than partially pseudonymized.

## Important disclaimers

- **All processing is local.** No data leaves your machine through Scrubsmith core functionality.
- **No telemetry.** Scrubsmith does not phone home.
- **No LLM required.** Core sanitization does not use AI models.
- **Human review required.** Sanitized output must still be reviewed before sharing externally.
- **No guarantees.** No software can guarantee that arbitrary data contains no sensitive information.
- **Pseudonymization ≠ anonymization.** Pseudonymized data may still be personal data.
- **Not legal advice.** Scrubsmith does not certify GDPR or any regulatory compliance.

## Roadmap

### Phase 2
JSON, NDJSON, CSV, structured-field transformations

### Phase 3
MySQL/MariaDB, PostgreSQL, table/column transformations, foreign-key awareness

### Phase 4
Diagnostic bundles with shared pseudonymization across sources:

```bash
scrubsmith bundle incident.yml
```

### Phase 5
Optional integrations with established open-source detection engines

## Development

```bash
pytest
ruff check src tests
mypy
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.
