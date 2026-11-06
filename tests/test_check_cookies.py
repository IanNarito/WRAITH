from pytest_httpserver import HTTPServer

from tests.conftest import ConfigFactory, make_page
from wraith.checks.cookies import evaluate, parse_set_cookie
from wraith.engine import Engine
from wraith.models import Confidence, Severity


def results(*set_cookies: str, url: str = "https://app.test/") -> set[tuple[str, Severity]]:
    page = make_page({}, url=url, extra=tuple(("Set-Cookie", c) for c in set_cookies))
    return {(f.title, f.severity) for f in evaluate([page])}


def test_session_cookie_missing_everything() -> None:
    assert results("PHPSESSID=abc123; Path=/") == {
        ("Session cookie 'PHPSESSID' missing Secure flag", Severity.MEDIUM),
        ("Session cookie 'PHPSESSID' missing HttpOnly flag", Severity.LOW),
        ("Session cookie 'PHPSESSID' missing SameSite attribute", Severity.INFO),
    }


def test_hardened_session_cookie_is_clean() -> None:
    assert results("session=abc; Path=/; Secure; HttpOnly; SameSite=Lax") == set()


def test_samesite_none_is_flagged() -> None:
    assert results("auth_token=abc; Secure; HttpOnly; SameSite=None") == {
        ("Session cookie 'auth_token' set with SameSite=None", Severity.LOW)
    }


def test_secure_not_expected_over_plain_http() -> None:
    titles = {t for t, _ in results("sid=abc; HttpOnly; SameSite=Lax", url="http://app.test/")}
    assert titles == set()


def test_non_session_and_csrf_cookies_are_ignored() -> None:
    assert results("theme=dark; Max-Age=999999", "csrftoken=abc123; Path=/") == set()


def test_deletion_cookies_are_ignored() -> None:
    assert results("PHPSESSID=deleted; Max-Age=0", "sessionid=; Max-Age=0") == set()


def test_unknown_name_with_random_value_is_probable() -> None:
    page = make_page(
        {}, extra=(("Set-Cookie", "x9=f3a8c1d27b6e4a90b1c2d3e4f5a6b7c8; Secure; HttpOnly"),)
    )
    findings = evaluate([page])
    assert [f.title for f in findings] == ["Likely session cookie 'x9' missing SameSite attribute"]
    assert findings[0].confidence is Confidence.PROBABLE


def test_parse_set_cookie() -> None:
    cookie = parse_set_cookie("a=b=c; Path=/; SameSite=Strict; secure")
    assert cookie is not None
    assert (cookie.name, cookie.value, cookie.samesite, cookie.secure) == (
        "a",
        "b=c",
        "strict",
        True,
    )
    assert parse_set_cookie("garbage") is None


async def test_engine_reports_each_cookie_once_across_pages(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    cookie = {"Set-Cookie": "JSESSIONID=abc; Path=/; HttpOnly"}
    httpserver.expect_request("/").respond_with_data(
        "<a href='/a'>a</a>", content_type="text/html", headers=cookie
    )
    httpserver.expect_request("/a").respond_with_data(
        "<html>a</html>", content_type="text/html", headers=cookie
    )
    result = await Engine(make_config(checks=("cookies",))).run()
    # Set on two pages, reported once. Plain HTTP target, so Secure is not expected.
    assert [f.title for f in result.findings] == [
        "Session cookie 'JSESSIONID' missing SameSite attribute"
    ]
