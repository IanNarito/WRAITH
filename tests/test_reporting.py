import json
from datetime import UTC, datetime

from rich.console import Console

from tests.conftest import make_page
from wraith.config import ScanConfig
from wraith.context import ScanContext
from wraith.engine import ScanResult
from wraith.models import Confidence, Evidence, Finding, Severity
from wraith.reporting import html_report, json_report, sarif_report, terminal

XSS_URL = "https://app.test/<script>alert(1)</script>"


def make_result() -> ScanResult:
    page = make_page({}, url="https://app.test/")
    ctx = ScanContext(
        target="https://app.test/",
        base=page,
        pages=(page,),
        forms=(),
        robots_paths=("/admin",),
        sitemap_urls=(),
        script_srcs=(),
        tech_hints=(),
        off_scope_urls=("https://elsewhere.test/",),
        unsafe_urls=(),
    )
    findings = (
        Finding(
            check="exposed_files",
            title="Git repository exposed",
            url="https://app.test/.git/HEAD",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description="desc",
            remediation="remove it",
            evidence=(
                Evidence("GET /.git/HEAD HTTP/1.1", "HTTP/1.1 200 OK\n\nref: refs/", "ref: "),
            ),
            references=("https://example.test/ref",),
        ),
        Finding(
            check="security_headers",
            title="Missing [bold]markup[/bold] header",
            url=XSS_URL,  # target-controlled strings must be escaped everywhere
            severity=Severity.LOW,
            confidence=Confidence.PROBABLE,
            description="<img src=x onerror=alert(1)>",
            remediation="fix",
            evidence=(Evidence("GET / HTTP/1.1", "<b>raw</b>"),),
        ),
    )
    return ScanResult(
        config=ScanConfig(target="https://app.test/", scope=("app.test",)),
        context=ctx,
        findings=findings,
        failures=(),
        checks_run=("exposed_files", "security_headers"),
        requests_sent=12,
        blocked_requests=1,
        started_at=datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
        duration_s=1.5,
    )


def test_json_schema_and_stable_ids() -> None:
    data = json.loads(json_report.render(make_result(), audit_log="a.log"))
    assert data["schema_version"] == "1.0"
    assert data["summary"] == {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert data["scan"]["audit_log"] == "a.log"
    first = data["findings"][0]
    assert first["severity"] == "high" and first["evidence"][0]["matched"] == "ref: "
    again = json.loads(json_report.render(make_result()))
    assert [f["id"] for f in again["findings"]] == [f["id"] for f in data["findings"]]
    assert data["discovery"]["off_scope_urls"] == ["https://elsewhere.test/"]


def test_html_is_self_contained_escaped_and_collapsible() -> None:
    html = html_report.render(make_result())
    assert html.startswith("<!DOCTYPE html>")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html
    assert "<details>" in html and "Git repository exposed" in html
    assert "http://" not in html.split("<body>")[0].replace("http-equiv", "")  # no external assets
    assert html.index("Git repository exposed") < html.index("markup")  # severity-sorted


def test_sarif_structure() -> None:
    data = json.loads(sarif_report.render(make_result()))
    run = data["runs"][0]
    assert data["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "WRAITH"
    assert [r["level"] for r in run["results"]] == ["error", "note"]
    assert run["results"][0]["ruleId"] == "exposed_files/git-repository-exposed"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} == rule_ids


def test_terminal_does_not_interpret_target_markup() -> None:
    console = Console(record=True, width=200, no_color=True)
    terminal.render(make_result(), console, verbosity=1)
    text = console.export_text()
    assert "Missing [bold]markup[/bold] header" in text
    assert "ref: refs/" in text  # evidence shown at -v
