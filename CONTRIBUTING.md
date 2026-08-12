# Contributing to Scrubsmith

Thank you for your interest in contributing to Scrubsmith.

## Principles

- Keep the core **local-first**, **offline**, and **privacy-first**
- Do not add network calls, telemetry, or cloud dependencies to core sanitization
- Prefer conservative detection over aggressive destruction of debugging usefulness
- Write all code, comments, tests, and documentation in **English**
- Use synthetic test data only — never real PII or credentials

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Checks

```bash
pytest
ruff check src tests
ruff format --check src tests
mypy
```

## Pull Request Guidelines

1. Focus changes on a single concern
2. Add or update tests for behavior changes
3. Update documentation when user-facing behavior changes
4. Ensure CI checks pass locally before submitting

## Code Style

- Python 3.12+
- Ruff for linting and formatting
- Strict mypy typing
- Minimal dependencies

## Detector Contributions

New detectors should:

- Return structured `Finding` objects with appropriate confidence levels
- Avoid false positives on stack traces, UUIDs, timestamps, hashes, and version numbers
- Include validation where applicable (checksums, control characters)
- Be organized under `detectors/generic/` or `detectors/<country>/`

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
