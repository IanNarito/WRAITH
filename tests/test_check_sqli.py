from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.checks.sqli import first_sql_error, load_error_signatures
from wraith.engine import Engine
from wraith.models import Confidence, Severity

MYSQL_ERROR = (
    "<html><body>You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version near ''' at line 1</body></html>"
)


def test_signatures_load_and_match() -> None:
    assert load_error_signatures()
    assert first_sql_error(MYSQL_ERROR) is not None
    assert first_sql_error("<html>all good</html>") is None


def serve_error_based(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/item?id=1'>item</a>", content_type="text/html"
    )

    def item(request: Request) -> Response:
        value = request.args.get("id", "")
        if "'" in value or '"' in value:  # unbalanced quote breaks the (simulated) query
            return Response(MYSQL_ERROR, status=500, content_type="text/html")
        return Response("<html><body>Item 1: widget</body></html>", content_type="text/html")

    httpserver.expect_request("/item").respond_with_handler(item)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


def serve_boolean_based(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/view?id=1'>view</a>", content_type="text/html"
    )

    def view(request: Request) -> Response:
        value = request.args.get("id", "")
        # True (or plain) -> full record; false condition -> empty result page.
        false = "1'='2" in value or "1=2" in value
        body = "<html>empty</html>" if false else "<html>" + "full record " * 50 + "</html>"
        return Response(body, content_type="text/html")

    httpserver.expect_request("/view").respond_with_handler(view)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


async def test_error_based_sqli(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    serve_error_based(httpserver)
    result = await Engine(make_config(checks=("sqli",), safe_mode=False)).run()

    assert result.failures == ()
    sqli = [f for f in result.findings if f.check == "sqli"]
    assert len(sqli) == 1
    assert sqli[0].title == "SQL injection (error-based) in parameter 'id'"
    assert sqli[0].severity is Severity.CRITICAL
    assert sqli[0].confidence is Confidence.PROBABLE


async def test_boolean_based_sqli(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    serve_boolean_based(httpserver)
    result = await Engine(make_config(checks=("sqli",), safe_mode=False)).run()

    sqli = [f for f in result.findings if f.check == "sqli"]
    assert len(sqli) == 1
    assert sqli[0].title == "SQL injection (boolean-based) in parameter 'id'"
    assert sqli[0].severity is Severity.HIGH


async def test_no_sqli_on_clean_endpoint(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<a href='/view?id=1'>view</a>", content_type="text/html"
    )
    # Always returns the same stable page regardless of input.
    httpserver.expect_request("/view").respond_with_data(
        "<html><body>static content</body></html>", content_type="text/html"
    )
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)
    result = await Engine(make_config(checks=("sqli",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "sqli"] == []
