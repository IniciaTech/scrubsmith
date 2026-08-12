"""Tests for streaming scan behavior."""

from pathlib import Path

from typer.testing import CliRunner

from scrubsmith.cli import app
from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.verifier import Verifier

runner = CliRunner()


def test_scan_file_streams_without_loading_entire_file(tmp_path: Path, monkeypatch) -> None:
    log = tmp_path / "large.log"
    line = "event user@company.org action=login\n"
    with log.open("w", encoding="utf-8") as handle:
        for _ in range(50_000):
            handle.write(line)

    read_text_called = False
    original_read_text = Path.read_text

    def tracking_read_text(self, *args, **kwargs):
        nonlocal read_text_called
        read_text_called = True
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", tracking_read_text)

    result = runner.invoke(app, ["scan", str(log)])
    assert result.exit_code in (0, 1, 2)
    assert not read_text_called


def test_verifier_scan_file_counts_findings(tmp_path: Path) -> None:
    log = tmp_path / "scan.log"
    log.write_text("clean line\nanother clean line\n", encoding="utf-8")
    verifier = Verifier(ScrubsmithConfig(version=1))
    summary = verifier.scan_file(log)
    assert summary.emails == 0


def test_scan_large_file_via_cli(tmp_path: Path) -> None:
    log = tmp_path / "large-scan.log"
    with log.open("w", encoding="utf-8") as handle:
        for _ in range(50_000):
            handle.write("status ok\n")
    result = runner.invoke(app, ["scan", str(log)])
    assert result.exit_code == 0
    assert "Potential sensitive data" in result.stdout
