from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.engine import Engine
from wraith.models import Confidence, Severity

HTML = {"content_type": "text/html"}


def _robots(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


# --- LDAP injection -----------------------------------------------------------------------------


async def test_ldap_injection_error_based(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/dir?user=bob'>d</a>", **HTML)

    def directory(request: Request) -> Response:
        user = request.args.get("user", "")
        if any(c in user for c in "()*\\"):  # unbalanced filter -> server-side LDAP error
            return Response(
                "javax.naming.directory.InvalidSearchFilterException: Bad search filter",
                status=500,
                content_type="text/plain",
            )
        return Response(f"<html>Found user {user}</html>", content_type="text/html")

    httpserver.expect_request("/dir").respond_with_handler(directory)
    _robots(httpserver)

    result = await Engine(make_config(checks=("ldap_injection",), safe_mode=False)).run()
    ldap = [f for f in result.findings if f.check == "ldap_injection"]
    assert len(ldap) == 1
    assert ldap[0].title == "LDAP injection in parameter 'user'"
    assert ldap[0].severity is Severity.HIGH
    assert ldap[0].confidence is Confidence.PROBABLE


async def test_ldap_injection_no_error_is_clean(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/dir?user=bob'>d</a>", **HTML)
    httpserver.expect_request("/dir").respond_with_data("<html>ok</html>", **HTML)
    _robots(httpserver)
    result = await Engine(make_config(checks=("ldap_injection",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "ldap_injection"] == []


# --- CSRF (passive) -----------------------------------------------------------------------------


async def test_csrf_unprotected_post_form_flagged(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<form method='post' action='/transfer'>"
        "<input name='amount'><input name='to'><button>go</button></form>",
        **HTML,
    )
    _robots(httpserver)
    result = await Engine(make_config(checks=("csrf",))).run()
    csrf = [f for f in result.findings if f.check == "csrf"]
    assert len(csrf) == 1
    assert csrf[0].title == "Form without anti-CSRF token"
    assert csrf[0].url.endswith("/transfer")
    assert csrf[0].severity is Severity.MEDIUM


async def test_csrf_token_field_is_clean(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<form method='post' action='/transfer'>"
        "<input name='amount'><input type='hidden' name='csrf_token' value='abc'>"
        "<button>go</button></form>",
        **HTML,
    )
    _robots(httpserver)
    result = await Engine(make_config(checks=("csrf",))).run()
    assert [f for f in result.findings if f.check == "csrf"] == []


async def test_csrf_get_form_ignored(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<form method='get' action='/search'><input name='q'><button>go</button></form>", **HTML
    )
    _robots(httpserver)
    result = await Engine(make_config(checks=("csrf",))).run()
    assert [f for f in result.findings if f.check == "csrf"] == []


# --- IDOR (opt-in) ------------------------------------------------------------------------------

_NAMES = {4: "Alice Ant", 5: "Bobby Bee", 6: "Carol Cat"}  # equal-length distinct records


async def test_idor_enumerable_reference_flagged(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/item?id=5'>i</a>", **HTML)

    def item(request: Request) -> Response:
        raw = request.args.get("id", "")
        if not raw.isdigit():
            return Response("bad", status=400)
        v = int(raw)
        if v in _NAMES:
            body = f"<html><body>Record {v}: {_NAMES[v]} is an active member here.</body></html>"
            return Response(body, content_type="text/html")
        return Response("<html>Record not found</html>", status=404, content_type="text/html")

    httpserver.expect_request("/item").respond_with_handler(item)
    _robots(httpserver)

    result = await Engine(make_config(checks=("idor",), safe_mode=False)).run()
    idor = [f for f in result.findings if f.check == "idor"]
    assert len(idor) == 1
    assert idor[0].title == "Enumerable object reference in parameter 'id'"
    assert idor[0].confidence is Confidence.PROBABLE


async def test_idor_static_page_is_clean(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/item?id=5'>i</a>", **HTML)
    # Ignores the id entirely -> control is not distinct from baseline, so no finding.
    httpserver.expect_request("/item").respond_with_data(
        "<html><body>Same static page regardless of id value here.</body></html>", **HTML
    )
    _robots(httpserver)
    result = await Engine(make_config(checks=("idor",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "idor"] == []
