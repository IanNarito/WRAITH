import time

import pytest
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.checks import sqli
from wraith.engine import Engine
from wraith.models import Confidence, Severity


def serve_time_based(httpserver: HTTPServer, delay: int) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/item?id=1'>i</a>", content_type="text/html"
    )

    def item(request: Request) -> Response:
        value = request.args.get("id", "")
        # Simulate a backend that sleeps for SLEEP(N)/pg_sleep(N) with N>0; no error output.
        for token in (f"SLEEP({delay})", f"pg_sleep({delay})", f"0:0:{delay}"):
            if token in value:
                time.sleep(delay)
                break
        return Response("<html>Item</html>", content_type="text/html")

    httpserver.expect_request("/item").respond_with_handler(item)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


async def test_time_based_blind_sqli(
    httpserver: HTTPServer, make_config: ConfigFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sqli, "TIME_DELAY", 1)  # keep the test fast (1s sleep, not 5s)
    serve_time_based(httpserver, delay=1)
    result = await Engine(make_config(checks=("sqli",), safe_mode=False)).run()

    found = [f for f in result.findings if f.check == "sqli"]
    assert len(found) == 1
    assert found[0].title == "SQL injection (time-based blind) in parameter 'id'"
    assert found[0].severity is Severity.HIGH
    assert found[0].confidence is Confidence.PROBABLE


async def test_slow_but_clean_endpoint_is_not_flagged(
    httpserver: HTTPServer, make_config: ConfigFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sqli, "TIME_DELAY", 1)
    httpserver.expect_request("/").respond_with_data(
        "<a href='/item?id=1'>i</a>", content_type="text/html"
    )

    def slow(request: Request) -> Response:  # always slow, regardless of payload
        time.sleep(1)
        return Response("<html>Item</html>", content_type="text/html")

    httpserver.expect_request("/item").respond_with_handler(slow)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)
    result = await Engine(make_config(checks=("sqli",), safe_mode=False)).run()
    # The zero-delay control is also slow, so time-based must NOT fire.
    assert [f for f in result.findings if f.check == "sqli"] == []


def serve_stored(httpserver: HTTPServer, *, escape: bool) -> None:
    import html as html_lib

    store: list[str] = []
    httpserver.expect_request("/").respond_with_data(
        "<form action='/comment' method='post'><input name='text'></form>",
        content_type="text/html",
    )

    def comment(request: Request) -> Response:
        store.append(request.form.get("text", ""))
        return Response("<html>saved</html>", content_type="text/html")

    def show(request: Request) -> Response:
        items = [html_lib.escape(s) if escape else s for s in store]
        return Response(
            "<html><body>" + "".join(items) + "</body></html>", content_type="text/html"
        )

    httpserver.expect_request("/comment", method="POST").respond_with_handler(comment)
    httpserver.expect_request("/comments").respond_with_handler(show)
    httpserver.expect_request("/robots.txt").respond_with_data(
        f"Allow: {httpserver.url_for('/comments')}\n", content_type="text/plain"
    )
    httpserver.expect_request("/sitemap.xml").respond_with_data(
        f"<urlset><url><loc>{httpserver.url_for('/comments')}</loc></url></urlset>",
        content_type="application/xml",
    )


async def test_stored_xss_detected(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    serve_stored(httpserver, escape=False)
    result = await Engine(make_config(checks=("xss_stored",), safe_mode=False)).run()
    stored = [f for f in result.findings if f.check == "xss_stored"]
    assert len(stored) == 1
    assert stored[0].severity is Severity.HIGH
    assert stored[0].url.endswith("/comments")
    assert "wsx" in (stored[0].evidence[0].matched or "")


async def test_stored_xss_not_flagged_when_escaped(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve_stored(httpserver, escape=True)
    result = await Engine(make_config(checks=("xss_stored",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "xss_stored"] == []
