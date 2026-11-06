"""Typer CLI: arguments -> ScanConfig -> authorization gate -> Engine -> report."""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from wraith import __version__
from wraith.audit import AuditLog, default_audit_path
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
from wraith.engine import Engine, ScanError, ScanResult
from wraith.models import Severity
from wraith.registry import PluginRegistry, RegistryError
from wraith.reporting import html_report, json_report, sarif_report, terminal

app = typer.Typer(
    name="wraith",
    help="WRAITH - Web Reconnaissance, Assessment, Inspection & Threat Hunting.\n\n"
    "For authorized security testing only.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(stderr=True)  # status, prompts, logs
out = Console()  # the report itself


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
    crawl_depth: Annotated[
        int,
        typer.Option(
            min=1, help="Same-origin crawl depth. 1 = links on the target page only (GET-only)."
        ),
    ] = 1,
    max_pages: Annotated[int, typer.Option(min=1, help="Maximum pages to crawl.")] = 30,
    cve: Annotated[
        bool,
        typer.Option(
            "--cve/--no-cve",
            help="Correlate detected versions against NVD. Contacts NVD (not the target).",
        ),
    ] = False,
    nvd_api_key: Annotated[
        str | None,
        typer.Option(envvar="NVD_API_KEY", help="NVD API key (raises the CVE lookup rate limit)."),
    ] = None,
    cve_cache: Annotated[
        Path | None,
        typer.Option(file_okay=False, help="Directory to cache NVD results. Default: no cache."),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config", exists=True, dir_okay=False, help="YAML file of defaults; CLI flags win."
        ),
    ] = None,
    audit_log: Annotated[
        Path | None,
        typer.Option(
            "--audit-log",
            dir_okay=False,
            help="Audit log file. Default: ./wraith-audit-<UTC timestamp>.log",
        ),
    ] = None,
) -> None:
    """Scan a target for web vulnerabilities."""
    try:
        config = _config_from_cli(ctx, config_file)
    except ConfigError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    _setup_logging(config.verbosity)
    audit_path = audit_log or default_audit_path(datetime.now(UTC))
    try:
        with AuditLog(audit_path) as audit:
            code = _run_scan(config, audit)
    except OSError as exc:  # _run_scan handles its own I/O errors; this is the log itself
        console.print(Text(f"error: cannot use audit log {audit_path}: {exc}", style="bold red"))
        raise typer.Exit(code=2) from exc
    console.print(Text(f"audit log: {audit_path}", style="dim"))
    raise typer.Exit(code=code)


def _run_scan(config: ScanConfig, audit: AuditLog) -> int:
    audit.record_config(config)
    affirmed, method = _authorization_gate(config)
    audit.record_authorization(config, affirmed=affirmed, method=method)
    if not affirmed:
        return 2

    try:
        with console.status("Scanning...", spinner="dots"):
            result = asyncio.run(Engine(config).run())
    except ScanError as exc:
        logging.getLogger("wraith.engine").error("scan error: %s", exc)
        console.print(Text("error: ", style="bold red") + Text(str(exc)))
        return 2
    except KeyboardInterrupt:
        logging.getLogger("wraith.engine").error("scan interrupted by user")
        console.print("[bold red]aborted[/]")
        return 2

    try:
        _write_report(config, result, str(audit.path))
    except OSError as exc:
        console.print(Text(f"error: cannot write report: {exc}", style="bold red"))
        return 2
    code = result.exit_code(config.fail_on)
    logging.getLogger("wraith.engine").info(
        "%d finding(s) %s; exit code %d",
        len(result.findings),
        json_report.severity_counts(result),
        code,
    )
    return code


def _write_report(config: ScanConfig, result: ScanResult, audit_path: str) -> None:
    fmt = config.output_format
    if fmt is OutputFormat.TERMINAL:
        if config.output is None:
            terminal.render(result, out, verbosity=config.verbosity)
            return
        with config.output.open("w", encoding="utf-8") as fh:
            file_console = Console(file=fh, width=120, no_color=True, force_terminal=False)
            terminal.render(result, file_console, verbosity=max(1, config.verbosity))
    else:
        if fmt is OutputFormat.JSON:
            text = json_report.render(result, audit_log=audit_path)
        elif fmt is OutputFormat.HTML:
            text = html_report.render(result, audit_log=audit_path)
        else:
            text = sarif_report.render(result)
        if config.output is None:
            sys.stdout.write(text)
            sys.stdout.flush()
        else:
            config.output.write_text(text, encoding="utf-8")

    counts = json_report.severity_counts(result)
    summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n) or "no findings"
    console.print(Text(f"{len(result.findings)} finding(s): {summary}"))
    if config.output is not None:
        console.print(Text(f"{fmt.value} report written to {config.output}", style="green"))


@app.command("list-checks")
def list_checks() -> None:
    """List available checks and whether each is on by default."""
    try:
        checks = PluginRegistry().checks
    except RegistryError as exc:
        console.print(Text("error: ", style="bold red") + Text(str(exc)))
        raise typer.Exit(code=2) from exc
    table = Table(header_style="bold")
    table.add_column("Check")
    table.add_column("Default")
    table.add_column("Max severity")
    table.add_column("Description")
    for name, cls in checks.items():
        default = "[green]on[/]" if cls.enabled_by_default else "[dim]off[/]"
        if cls.requires_aggressive:
            default += " [red](aggressive)[/]"
        table.add_row(name, default, cls.severity_hint.value, cls.description)
    out.print(table)


def _authorization_gate(config: ScanConfig) -> tuple[bool, str]:
    """Show the declared scope and require an explicit affirmation of permission."""
    mode = "safe (non-mutating requests only)" if config.safe_mode else "AGGRESSIVE"
    console.print(
        Panel(
            Text.assemble(
                ("Target: ", "bold"),
                config.target,
                "\n",
                ("Scope:  ", "bold"),
                ", ".join(config.scope),
                "\n",
                ("Mode:   ", "bold"),
                mode,
                "\n",
                ("Rate:   ", "bold"),
                f"{config.rate:g} req/s, concurrency {config.concurrency}",
            ),
            title="WRAITH - declared scope",
            border_style="red" if not config.safe_mode else "cyan",
        )
    )
    if config.confirm_authorized:
        return True, "--confirm-authorized flag"
    if not sys.stdin.isatty():
        console.print(
            "[bold red]error:[/] --confirm-authorized is required when not running interactively."
        )
        return False, "non-interactive run without --confirm-authorized"
    confirmed = typer.confirm(
        "Do you have explicit permission to test every host in this scope?", default=False
    )
    if not confirmed:
        console.print("Not authorized; nothing was sent.")
    return confirmed, "interactive prompt"


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING if verbosity <= 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    handler = RichHandler(console=console, show_path=False, show_time=verbosity >= 2)
    handler.setLevel(level)  # the audit log (if open) still receives DEBUG
    logging.basicConfig(level=logging.DEBUG, format="%(message)s", handlers=[handler], force=True)
    for noisy in ("httpx", "httpcore", "hpack", "h2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _config_from_cli(ctx: typer.Context, config_file: Path | None) -> ScanConfig:
    """Merge CLI params with an optional YAML file; explicitly passed flags take precedence."""
    values = dict(ctx.params)
    values.pop("config_file", None)
    values.pop("audit_log", None)
    if config_file is not None:
        for key, value in load_config_file(config_file).items():
            source = ctx.get_parameter_source(key)
            if source is None or source.name in ("DEFAULT", "DEFAULT_MAP"):
                values[key] = value
    return build_config(values)
