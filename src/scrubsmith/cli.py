"""Scrubsmith command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from scrubsmith import __version__
from scrubsmith.config import load_config
from scrubsmith.core.context import TransformationContext
from scrubsmith.core.models import ExitCode, VerificationStatus, verification_to_exit_code
from scrubsmith.core.verifier import Verifier
from scrubsmith.reporting import format_sanitization_report, format_scan_report, write_json_report
from scrubsmith.sources.logs import LogSanitizer, paths_are_same

app = typer.Typer(
    name="scrubsmith",
    help="Local-first sanitization for safe debugging and AI sharing.",
    no_args_is_help=True,
)


def _parse_seed(seed: str | None) -> bytes | None:
    if seed is None:
        return None
    try:
        return bytes.fromhex(seed)
    except ValueError:
        return seed.encode("utf-8")


def version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """Scrubsmith CLI entry point."""


sanitize_app = typer.Typer(help="Sanitize diagnostic data.")
app.add_typer(sanitize_app, name="sanitize")


@sanitize_app.command("logs")
def sanitize_logs(
    input: Annotated[Path, typer.Argument(help="Input log file path.", exists=True, readable=True)],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="YAML configuration file."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Process without writing output."),
    ] = False,
    seed: Annotated[
        str | None,
        typer.Option("--seed", help="Deterministic pseudonymization seed."),
    ] = None,
    report: Annotated[
        Path | None,
        typer.Option("--report", help="Write JSON sanitization report."),
    ] = None,
) -> None:
    """Sanitize a plain-text log file."""
    if not dry_run and output is None:
        typer.echo("Error: --output is required unless --dry-run is set.", err=True)
        raise typer.Exit(ExitCode.ERROR)

    if output is not None and paths_are_same(input, output):
        typer.echo("Error: Output path must not be the same as input path.", err=True)
        raise typer.Exit(ExitCode.ERROR)

    try:
        cfg = load_config(config)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    context = TransformationContext(seed=_parse_seed(seed))
    log_sanitizer = LogSanitizer(cfg, context=context)

    try:
        result = log_sanitizer.sanitize_file(
            input,
            output,
            dry_run=dry_run,
        )
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except OSError as exc:
        typer.echo(f"Error: Failed to process file: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(format_sanitization_report(result))

    if report is not None:
        write_json_report(result, report)

    raise typer.Exit(verification_to_exit_code(result.verification.status))


@app.command("scan")
def scan(
    input: Annotated[Path, typer.Argument(help="Input file path.", exists=True, readable=True)],
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="YAML configuration file."),
    ] = None,
) -> None:
    """Scan input for potential sensitive data without modifying it."""
    try:
        cfg = load_config(config)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    verifier = Verifier(cfg)
    try:
        summary, status = verifier.scan_file_with_status(input)
    except OSError as exc:
        typer.echo(f"Error: Failed to read file: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(format_scan_report(summary, status))

    if status == VerificationStatus.PASS:
        raise typer.Exit(ExitCode.SUCCESS)
    if status == VerificationStatus.REVIEW_REQUIRED:
        raise typer.Exit(ExitCode.REVIEW_REQUIRED)
    raise typer.Exit(ExitCode.FAIL)


if __name__ == "__main__":
    app()
