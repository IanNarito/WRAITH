"""Typer CLI: parses arguments into a ScanConfig."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

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
    build_config,
    load_config_file,
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
    ctx: typer.Context,
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
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config", exists=True, dir_okay=False, help="YAML file of defaults; CLI flags win."
        ),
    ] = None,
) -> None:
    """Scan a target for web vulnerabilities."""
    try:
        config = _config_from_cli(ctx, config_file)
    except ConfigError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    # Step 1 stub: show the parsed config. The engine is wired in later steps.
    _print_config(config)


@app.command("list-checks")
def list_checks() -> None:
    """List available checks and whether each is on by default."""
    console.print("[yellow]No checks registered yet (plugin registry lands in step 5).[/]")


def _config_from_cli(ctx: typer.Context, config_file: Path | None) -> ScanConfig:
    """Merge CLI params with an optional YAML file; explicitly passed flags take precedence."""
    values = dict(ctx.params)
    values.pop("config_file", None)
    if config_file is not None:
        for key, value in load_config_file(config_file).items():
            source = ctx.get_parameter_source(key)
            if source is None or source.name in ("DEFAULT", "DEFAULT_MAP"):
                values[key] = value
    return build_config(values)


def _print_config(config: ScanConfig) -> None:
    table = Table(title="WRAITH scan config (stub)", show_header=False)
    table.add_column("key", style="cyan")
    table.add_column("value")
    for key, value in vars(config).items():
        table.add_row(key, repr(value))
    console.print(table)
