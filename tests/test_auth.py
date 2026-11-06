import pytest
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.engine import Engine, ScanError


def serve_app(httpserver: HTTPServer) -> None:
    def login(request: Request) -> Response:
        if request.form.get("username") == "admin" and request.form.get("password") == "secret":
            resp = Response("<html>welcome admin</html>", content_type="text/html")
            resp.set_cookie("sid", "valid-session")
            return resp
        return Response("<html>invalid credentials</html>", status=401, content_type="text/html")

    def home(request: Request) -> Response:
        if request.cookies.get("sid") == "valid-session":
            return Response(
                "<html><body>Authenticated dashboard</body></html>", content_type="text/html"
            )
        return Response("<html><body>Please log in</body></html>", content_type="text/html")

    httpserver.expect_request("/login", method="POST").respond_with_handler(login)
    httpserver.expect_request("/").respond_with_handler(home)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


async def test_form_login_authenticates_the_scan(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve_app(httpserver)
    config = make_config(
        checks=("security_headers",),
        login_url=httpserver.url_for("/login"),
        login_data={"username": "admin", "password": "secret"},
        login_check="welcome",
    )
    result = await Engine(config).run()
    assert "Authenticated dashboard" in result.context.base.body  # scanned as the logged-in user


async def test_failed_login_raises_scan_error(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve_app(httpserver)
    config = make_config(
        login_url=httpserver.url_for("/login"),
        login_data={"username": "admin", "password": "wrong"},
        login_check="welcome",
    )
    with pytest.raises(ScanError, match="login appears to have failed"):
        await Engine(config).run()


async def test_login_url_out_of_scope_is_refused(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve_app(httpserver)
    config = make_config(login_url="https://other.example/login", login_data={"u": "a"})
    with pytest.raises(ScanError, match="outside the declared scope"):
        await Engine(config).run()
