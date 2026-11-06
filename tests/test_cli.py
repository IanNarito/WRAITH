import json
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from typer.testing import CliRunner

from wraith.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _audit_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The default audit log goes to the working directory; keep tests from littering the repo.
    monkeypatch.chdir(tmp_path)


def serve_bare_page(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_data("<html>hi</html>", content_type="text/html")


def scan_args(httpserver: HTTPServer, *extra: str) -> list[str]:
    return ["scan", httpserver.url_for("/"), "--scope", "127.0.0.1", "--rate", "1000", *extra]


def test_scan_requires_authorization_when_not_interactive(httpserver: HTTPServer) -> None:
    serve_bare_page(httpserver)
    result = runner.invoke(app, scan_args(httpserver))
    assert result.exit_code == 2
    assert "--confirm-authorized is required" in result.output
    assert httpserver.log == []  # nothing was sent


def test_scan_exit_codes_follow_fail_on(httpserver: HTTPServer) -> None:
    serve_bare_page(httpserver)
    gated = runner.invoke(app, scan_args(httpserver, "--confirm-authorized", "--fail-on", "medium"))
    assert gated.exit_code == 1, gated.output
    assert "Missing Content-Security-Policy" in gated.output

    relaxed = runner.invoke(app, scan_args(httpserver, "--confirm-authorized", "--fail-on", "high"))
    assert relaxed.exit_code == 0, relaxed.output


def test_target_outside_scope_is_refused(httpserver: HTTPServer) -> None:
    serve_bare_page(httpserver)
    result = runner.invoke(
        app, ["scan", httpserver.url_for("/"), "--scope", "example.com", "--confirm-authorized"]
    )
    assert result.exit_code == 2
    assert "not covered by the declared scope" in result.output
    assert httpserver.log == []


def test_unknown_check_is_a_scan_error(httpserver: HTTPServer) -> None:
    result = runner.invoke(app, scan_args(httpserver, "--confirm-authorized", "--checks", "nope"))
    assert result.exit_code == 2
    assert "unknown check" in result.output


def test_list_checks() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "security_headers" in result.output


def test_audit_log_records_authorization_scope_and_requests(
    httpserver: HTTPServer, tmp_path: Path
) -> None:
    serve_bare_page(httpserver)
    log = tmp_path / "audit.log"
    result = runner.invoke(
        app,
        [
            *scan_args(httpserver, "--confirm-authorized", "--checks", "security_headers"),
            "--audit-log",
            str(log),
        ],
    )
    assert result.exit_code == 0, result.output
    text = log.read_text(encoding="utf-8")
    assert "AUTHORIZATION AFFIRMED" in text and "--confirm-authorized flag" in text
    assert "scope ALLOW " + httpserver.url_for("/") in text
    assert "GET " + httpserver.url_for("/") + " -> 200" in text
    assert "scan finished" in text
    assert text.splitlines()[0][:4].isdigit()  # every line is timestamped


def test_declined_authorization_is_audited(httpserver: HTTPServer, tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    result = runner.invoke(app, [*scan_args(httpserver), "--audit-log", str(log)])
    assert result.exit_code == 2
    assert "AUTHORIZATION NOT GIVEN" in log.read_text(encoding="utf-8")
    assert httpserver.log == []


def test_default_audit_log_location(httpserver: HTTPServer, tmp_path: Path) -> None:
    serve_bare_page(httpserver)
    runner.invoke(app, scan_args(httpserver, "--confirm-authorized", "--checks", "cookies"))
    assert len(list(tmp_path.glob("wraith-audit-*.log"))) == 1


@pytest.mark.parametrize("fmt", ["json", "html", "sarif", "terminal"])
def test_report_formats_written_to_file(httpserver: HTTPServer, tmp_path: Path, fmt: str) -> None:
    serve_bare_page(httpserver)
    out = tmp_path / f"report.{fmt}"
    result = runner.invoke(
        app,
        scan_args(httpserver, "--confirm-authorized", "--format", fmt, "--output", str(out)),
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "Missing Content-Security-Policy" in text
    if fmt in ("json", "sarif"):
        json.loads(text)


def test_json_to_stdout_is_pure_json(httpserver: HTTPServer) -> None:
    serve_bare_page(httpserver)
    result = runner.invoke(app, scan_args(httpserver, "--confirm-authorized", "--format", "json"))
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["schema_version"] == "1.0"


def test_aggressive_checks_refuse_safe_mode(httpserver: HTTPServer) -> None:
    serve_bare_page(httpserver)
    result = runner.invoke(app, scan_args(httpserver, "--confirm-authorized", "--checks", "sqli"))
    assert result.exit_code == 2
    assert "needs --aggressive" in result.output


def test_list_checks_marks_aggressive() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "sqli" in result.output and "xss_reflected" in result.output
    assert "aggressive" in result.output
