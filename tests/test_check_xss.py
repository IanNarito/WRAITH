import html as html_lib

from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.engine import Engine
from wraith.models import Confidence, Severity


def serve(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/search?q=hello'>s</a> <a href='/safe?q=hello'>safe</a>",
        content_type="text/html",
    )

    def reflect(request: Request) -> Response:
        q = request.args.get("q", "")
        return Response(f"<html><body>Results for {q}</body></html>", content_type="text/html")

    def escaped(request: Request) -> Response:
        q = html_lib.escape(request.args.get("q", ""))
        return Response(f"<html><body>Results for {q}</body></html>", content_type="text/html")

    httpserver.expect_request("/search").respond_with_handler(reflect)
    httpserver.expect_request("/safe").respond_with_handler(escaped)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


async def test_detects_reflected_xss_and_skips_escaped(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve(httpserver)
    result = await Engine(make_config(checks=("xss_reflected",), safe_mode=False)).run()

    assert result.failures == ()
    xss = [f for f in result.findings if f.check == "xss_reflected"]
    assert len(xss) == 1
    assert xss[0].title == "Reflected XSS in parameter 'q'"
    assert xss[0].severity is Severity.HIGH
    assert xss[0].confidence is Confidence.PROBABLE
    assert xss[0].url.endswith("/search")
    assert "wrz" in (xss[0].evidence[0].matched or "")


async def test_no_injection_points_no_findings(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<html>no params here</html>", content_type="text/html"
    )
    result = await Engine(make_config(checks=("xss_reflected",), safe_mode=False)).run()
    assert result.findings == ()
