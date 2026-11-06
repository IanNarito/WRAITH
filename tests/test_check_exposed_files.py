import re

from pytest_httpserver import HTTPServer

from tests.conftest import ConfigFactory
from wraith.checks.exposed_files import load_wordlist
from wraith.engine import Engine
from wraith.models import Severity


def test_wordlist_loads_and_signatures_compile() -> None:
    entries = load_wordlist()
    paths = {e.path for e in entries}
    assert {".git/HEAD", ".env", "backup.zip", ".DS_Store", "phpinfo.php"} <= paths


async def test_reports_only_signature_verified_files(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<html>home</html>", content_type="text/html")
    httpserver.expect_request("/.git/HEAD").respond_with_data("ref: refs/heads/main\n")
    httpserver.expect_request("/backup.zip").respond_with_data(
        b"PK\x03\x04\x14\x00" + b"\x00" * 50, content_type="application/zip"
    )
    httpserver.expect_request("/phpinfo.php").respond_with_data(
        "<html><head><title>PHP 8.2.1 - phpinfo()</title></head></html>",
        content_type="text/html",
    )
    # 200s that must NOT be reported: an HTML page at .env, the wrong content at .git/config,
    # and a redirect to a login page for the SQL dump.
    httpserver.expect_request("/.env").respond_with_data(
        "<!doctype html><html>DB_PASSWORD=x</html>", content_type="text/html"
    )
    httpserver.expect_request("/.git/config").respond_with_data("hello")
    httpserver.expect_request("/backup.sql").respond_with_data(
        "", status=302, headers={"Location": "/login"}
    )

    result = await Engine(make_config(checks=("exposed_files",))).run()

    found = {(f.url.rsplit("/", 1)[-1] or f.url, f.title, f.severity) for f in result.findings}
    assert found == {
        ("HEAD", "Git repository exposed", Severity.HIGH),
        ("backup.zip", "Backup archive exposed", Severity.HIGH),
        ("phpinfo.php", "phpinfo() page exposed", Severity.MEDIUM),
    }
    git = next(f for f in result.findings if f.url.endswith("/.git/HEAD"))
    assert git.evidence[0].matched == "ref: refs/"
    assert "ref: refs/heads/main" in git.evidence[0].response_snippet
    assert not any(req.path == "/login" for req, _ in httpserver.log)  # redirects not followed


async def test_catch_all_server_produces_no_findings(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    # Every path returns the same non-HTML body, which even matches the .git/HEAD signature.
    httpserver.expect_request(re.compile("^/.*")).respond_with_data("ref: refs/heads/main\n")
    result = await Engine(make_config(checks=("exposed_files",))).run()
    assert result.findings == ()
