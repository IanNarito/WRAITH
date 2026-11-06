import re

from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.checks.content_discovery import load_paths
from wraith.checks.param_mining import load_param_names
from wraith.engine import Engine
from wraith.models import Severity

HTML = {"content_type": "text/html"}


def test_wordlists_load() -> None:
    assert "admin" in load_paths()
    assert "debug" in load_param_names()


async def test_content_discovery_finds_unlinked_paths(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<html>home</html>", **HTML)
    httpserver.expect_request("/admin").respond_with_data("<html>admin panel</html>", **HTML)
    httpserver.expect_request("/dashboard").respond_with_data("", status=401)
    # Everything else is a real 404 (pytest-httpserver default for unmatched).

    result = await Engine(make_config(checks=("content_discovery",), safe_mode=False)).run()
    found = {f.title: f.severity for f in result.findings if f.check == "content_discovery"}
    assert "Discovered path /admin" in found
    assert found["Discovered path /admin"] is Severity.LOW  # "admin" is sensitive
    assert "Discovered path /dashboard" in found  # 401 = exists but protected


async def test_content_discovery_handles_catch_all_200(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    # Server returns the same 200 page for every path -> nothing should be reported.
    httpserver.expect_request(re.compile("^/.*")).respond_with_data(
        "<html>same page everywhere</html>", **HTML
    )
    result = await Engine(make_config(checks=("content_discovery",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "content_discovery"] == []


async def test_param_mining_finds_reflected_hidden_param(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    def home(request: Request) -> Response:
        # Reflects only the "debug" parameter's value; others are ignored.
        debug = request.args.get("debug", "")
        return Response(f"<html><body>debug={debug}</body></html>", **HTML)

    httpserver.expect_request("/").respond_with_handler(home)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)

    result = await Engine(make_config(checks=("param_mining",), safe_mode=False)).run()
    mined = [f for f in result.findings if f.check == "param_mining"]
    assert len(mined) == 1
    assert mined[0].title == "Hidden parameter 'debug' is reflected"


async def test_param_mining_quiet_when_nothing_reflected(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<html>static page</html>", **HTML)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)
    result = await Engine(make_config(checks=("param_mining",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "param_mining"] == []
