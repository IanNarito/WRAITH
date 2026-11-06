from pytest_httpserver import HTTPServer
from typer.testing import CliRunner

from wraith.cli import app

runner = CliRunner()


def serve_bare_page(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_data("<html>hi</html>", content_type="text/html")


def scan_args(httpserver: HTTPServer, *extra: str) -> list[str]:
    return ["scan", httpserver.url_for("/"), "--scope", "localhost", "--rate", "1000", *extra]


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
