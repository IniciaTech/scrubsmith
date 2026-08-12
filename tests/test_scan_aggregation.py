"""Tests for bounded scan aggregation."""

from pathlib import Path

from scrubsmith.config import ScrubsmithConfig
from scrubsmith.core.verifier import Verifier


def test_scan_file_returns_summary_not_findings_list(tmp_path: Path) -> None:
    log = tmp_path / "scan.log"
    log.write_text("user@company.org\n", encoding="utf-8")
    verifier = Verifier(ScrubsmithConfig(version=1))
    summary = verifier.scan_file(log)
    assert summary.emails == 1
    assert summary.total_findings == 1


def test_scan_aggregates_many_findings_without_retaining_list(tmp_path: Path, monkeypatch) -> None:
    log = tmp_path / "many.log"
    with log.open("w", encoding="utf-8") as handle:
        for i in range(20_000):
            handle.write(f"user{i}@company.org login\n")

    append_counts: list[int] = []

    original_scan_line = Verifier._scan_line

    def tracking_scan_line(self, line, accumulator, collected):
        if collected is not None:
            original_collected = collected

            def tracking_append(item):
                append_counts.append(len(original_collected))
                return list.append(original_collected, item)

            collected.append = tracking_append  # type: ignore[method-assign]
        return original_scan_line(self, line, accumulator, collected)

    monkeypatch.setattr(Verifier, "_scan_line", tracking_scan_line)

    summary = Verifier(ScrubsmithConfig(version=1)).scan_file(log)
    assert summary.emails == 20_000
    assert summary.total_findings == 20_000
    assert append_counts == []


def test_collect_findings_is_opt_in_for_in_memory_scan() -> None:
    verifier = Verifier(ScrubsmithConfig(version=1))
    findings, summary = verifier.scan("a@b.com\n", collect_findings=True)
    assert findings is not None
    assert len(findings) == 1
    assert summary.emails == 1

    findings_default, summary_default = verifier.scan("a@b.com\n")
    assert findings_default is None
    assert summary_default.emails == 1
