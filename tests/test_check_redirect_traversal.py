from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.engine import Engine
from wraith.models import Confidence, Severity

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def serve_redirect(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/go?next=/home'>go</a> <a href='/safe?next=/home'>safe</a>",
        content_type="text/html",
    )

    def go(request: Request) -> Response:  # reflects next into Location unchecked
        return Response("", status=302, headers={"Location": request.args.get("next", "/")})

    def safe(request: Request) -> Response:  # ignores next, always same-site
        return Response("", status=302, headers={"Location": "/dashboard"})

    httpserver.expect_request("/go").respond_with_handler(go)
    httpserver.expect_request("/safe").respond_with_handler(safe)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


async def test_open_redirect_detected_and_safe_endpoint_clean(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve_redirect(httpserver)
    result = await Engine(make_config(checks=("open_redirect",), safe_mode=False)).run()
    assert result.failures == ()
    red = [f for f in result.findings if f.check == "open_redirect"]
    assert len(red) == 1
    assert red[0].title == "Open redirect in parameter 'next'"
    assert red[0].url.endswith("/go")
    assert red[0].confidence is Confidence.CONFIRMED


def serve_lfi(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/download?file=notes.txt'>d</a>", content_type="text/html"
    )

    def download(request: Request) -> Response:
        name = request.args.get("file", "")
        normalized = name.replace("%2f", "/").replace("\\", "/")
        if "etc/passwd" in normalized:
            return Response(PASSWD, content_type="text/plain")
        return Response("Contents of notes file", content_type="text/plain")

    httpserver.expect_request("/download").respond_with_handler(download)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


async def test_path_traversal_detected(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    serve_lfi(httpserver)
    result = await Engine(make_config(checks=("path_traversal",), safe_mode=False)).run()
    lfi = [f for f in result.findings if f.check == "path_traversal"]
    assert len(lfi) == 1
    assert lfi[0].title == "Path traversal / LFI in parameter 'file'"
    assert lfi[0].severity is Severity.HIGH
    assert "root:" in (lfi[0].evidence[0].matched or "")


async def test_no_traversal_when_sanitized(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/download?file=notes.txt'>d</a>", content_type="text/html"
    )
    # Always returns the same page; the traversal signature never appears.
    httpserver.expect_request("/download").respond_with_data(
        "<html>safe content</html>", content_type="text/html"
    )
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)
    result = await Engine(make_config(checks=("path_traversal",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "path_traversal"] == []
