"""Tests for CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from scrubsmith.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_scan_command(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("Clean log line\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(log)])
    assert result.exit_code == 0
    assert "Potential sensitive data" in result.stdout


def test_sanitize_dry_run(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("user@example.org login\n", encoding="utf-8")
    result = runner.invoke(app, ["sanitize", "logs", str(log), "--dry-run"])
    assert result.exit_code in (0, 1, 2)
    assert "Scrubsmith sanitization report" in result.stdout
    assert "example.org" not in result.stdout


def test_sanitize_with_output(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    out = tmp_path / "app.safe.log"
    log.write_text("user@company.org login\n", encoding="utf-8")
    runner.invoke(app, ["sanitize", "logs", str(log), "--output", str(out)])
    assert out.exists()
    assert "company.org" not in out.read_text(encoding="utf-8")


def test_same_input_output_rejected(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("data\n", encoding="utf-8")
    result = runner.invoke(app, ["sanitize", "logs", str(log), "--output", str(log)])
    assert result.exit_code == 3
    assert "same" in result.stderr.lower() or "same" in result.stdout.lower()
