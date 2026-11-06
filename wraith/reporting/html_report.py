"""HTML reporter: one self-contained file (inline CSS, no external assets)."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from wraith import __version__
from wraith.engine import ScanResult
from wraith.reporting.json_report import finding_id, severity_counts


def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("wraith.reporting", "templates"),
        autoescape=select_autoescape(["html", "j2"], default=True),  # target data is untrusted
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(result: ScanResult, *, audit_log: str | None = None) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(
        result=result,
        ctx=result.context,
        config=result.config,
        counts=severity_counts(result),
        finding_id=finding_id,
        version=__version__,
        audit_log=audit_log,
    )
