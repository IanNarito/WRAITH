"""Terminal reporter: findings grouped by severity, most severe first.

Target-controlled strings (URLs, header values) are always wrapped in ``Text`` so they are
never interpreted as rich markup.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from wraith.engine import ScanResult
from wraith.models import Severity

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(result: ScanResult, console: Console, *, verbosity: int = 0) -> None:
    console.print()
    console.rule(Text.assemble(("WRAITH", "bold"), " results for ", result.context.base_url))

    if result.findings:
        table = Table(header_style="bold", expand=False)
        table.add_column("#", justify="right", style="dim")
        table.add_column("Severity")
        table.add_column("Finding")
        table.add_column("URL", overflow="fold")
        table.add_column("Confidence", style="dim")
        for i, f in enumerate(result.findings, 1):
            table.add_row(
                str(i),
                Text(f.severity.upper(), style=SEVERITY_STYLE[f.severity]),
                Text(f.title),
                Text(f.url),
                Text(f.confidence.value),
            )
        console.print(table)

        for i, f in enumerate(result.findings, 1):
            console.print()
            console.print(
                Text.assemble(
                    (f"{i}. ", "dim"),
                    (f.title, "bold"),
                    "  ",
                    (f"[{f.severity.upper()}]", SEVERITY_STYLE[f.severity]),
                )
            )
            console.print(Text("   ") + Text(f.description))
            console.print(Text("   Fix: ", style="green") + Text(f.remediation))
            if verbosity >= 1:
                for ev in f.evidence:
                    body = ev.request + "\n\n" + ev.response_snippet
                    console.print(Panel(Text(body), title="evidence", border_style="dim"))
    else:
        console.print(Text("No findings.", style="bold green"))

    console.print()
    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1
    summary = Text("Summary: ")
    for severity in sorted(Severity, key=lambda s: -s.rank):
        summary.append(f"{severity.upper()} {counts[severity]}", style=SEVERITY_STYLE[severity])
        summary.append("  ")
    console.print(summary)

    for failure in result.failures:
        console.print(Text(f"check {failure.check} FAILED: {failure.error}", style="bold red"))

    ctx = result.context
    console.print(
        Text(
            f"{len(result.checks_run)} check(s) · {len(ctx.pages)} page(s) · "
            f"{len(ctx.forms)} form(s) · {result.requests_sent} request(s) · "
            f"{result.blocked_requests} blocked out-of-scope · "
            f"{len(ctx.off_scope_urls)} off-scope link(s) recorded · "
            f"{result.duration_s:.1f}s",
            style="dim",
        )
    )
