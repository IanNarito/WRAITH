"""Typer CLI: parses arguments into a ScanConfig."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from wraith import __version__
from wraith.config import (
    DEFAULT_CONCURRENCY,
    DEFAULT_RATE,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    ConfigError,
    OutputFormat,
    ScanConfig,
    normalize_target,
    parse_cookies,
    parse_headers,
    split_csv,
)
from wraith.models import Severity

app = typer.Typer(
    name="wraith",
    help="WRAITH - Web Reconnaissance, Assessment, Inspection & Threat Hunting.\n\n"
    "For authorized security testing only.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"wraith {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """WRAITH command group."""


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Base URL of the in-scope target.")],
    scope: Annotated[
        str | None,
        typer.Option(help="Comma-separated hosts/globs in scope. Defaults to the target host."),
    ] = None,
    confirm_authorized: Annotated[
        bool,
        typer.Option("--confirm-authorized", help="Affirm you have permission to test the target."),
    ] = False,
    rate: Annotated[float, typer.Option(min=0.1, help="Max requests per second.")] = DEFAULT_RATE,
    concurrency: Annotated[
        int, typer.Option(min=1, help="Max concurrent requests.")
    ] = DEFAULT_CONCURRENCY,
    checks: Annotated[
        str | None, typer.Option(help="Comma-separated checks to run (default: all default-on).")
    ] = None,
    exclude: Annotated[str | None, typer.Option(help="Comma-separated checks to skip.")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", case_sensitive=False, help="Report format.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[Path | None, typer.Option(help="Report destination file.")] = None,
    proxy: Annotated[
        str | None, typer.Option(help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp/ZAP).")
    ] = None,
    timeout: Annotated[
        float, typer.Option(min=0.1, help="Per-request timeout in seconds.")
    ] = DEFAULT_TIMEOUT,
    user_agent: Annotated[str, typer.Option(help="User-Agent header.")] = DEFAULT_USER_AGENT,
    header: Annotated[
        list[str] | None, typer.Option(help="Extra header 'Name: value' (repeatable).")
    ] = None,
    cookie: Annotated[
        list[str] | None, typer.Option(help="Cookie 'name=value' (repeatable).")
    ] = None,
    safe_mode: Annotated[
        bool,
        typer.Option(
            "--safe-mode/--aggressive",
            help="Safe mode (default) sends only non-mutating requests.",
        ),
    ] = True,
    fail_on: Annotated[
        Severity | None,
        typer.Option(case_sensitive=False, help="Exit 1 if any finding is at/above this severity."),
    ] = None,
    verbose: Annotated[
        int, typer.Option("--verbose", "-v", count=True, help="Increase verbosity (-v, -vv).")
    ] = 0,
) -> None:
    """Scan a target for web vulnerabilities."""
    try:
        normalized = normalize_target(target)
        scope_rules = split_csv(scope) or (urlparse(normalized).hostname or "",)
        config = ScanConfig(
            target=normalized,
            scope=scope_rules,
            confirm_authorized=confirm_authorized,
            rate=rate,
            concurrency=concurrency,
            checks=split_csv(checks),
            exclude=split_csv(exclude),
            output_format=output_format,
            output=output,
            proxy=proxy,
            timeout=timeout,
            user_agent=user_agent,
            headers=parse_headers(header or []),
            cookies=parse_cookies(cookie or []),
            safe_mode=safe_mode,
            fail_on=fail_on,
            verbosity=verbose,
        )
    except ConfigError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    # Step 1 stub: show the parsed config. The engine is wired in later steps.
    _print_config(config)


@app.command("list-checks")
def list_checks() -> None:
    """List available checks and whether each is on by default."""
    console.print("[yellow]No checks registered yet (plugin registry lands in step 5).[/]")


def _print_config(config: ScanConfig) -> None:
    table = Table(title="WRAITH scan config (stub)", show_header=False)
    table.add_column("key", style="cyan")
    table.add_column("value")
    for key, value in vars(config).items():
        table.add_row(key, repr(value))
    console.print(table)
