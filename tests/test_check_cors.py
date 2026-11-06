from collections.abc import Callable

from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.engine import Engine
from wraith.models import Severity

Policy = Callable[[str], dict[str, str]]


def serve(httpserver: HTTPServer, policy: Policy) -> None:
    def handler(request: Request) -> Response:
        headers = policy(request.headers.get("Origin", ""))
        return Response("<html>api</html>", content_type="text/html", headers=headers)

    httpserver.expect_request("/").respond_with_handler(handler)


async def run(make_config: ConfigFactory) -> list[tuple[str, Severity]]:
    result = await Engine(make_config(checks=("cors",))).run()
    assert result.failures == ()
    return [(f.title, f.severity) for f in result.findings]


async def test_reflecting_any_origin_with_credentials_is_high(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve(
        httpserver,
        lambda origin: {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        },
    )
    # Reported once: the prefix/suffix/null variants are implied by full reflection.
    assert await run(make_config) == [
        ("CORS reflects arbitrary origin with credentials", Severity.HIGH)
    ]


async def test_reflection_without_credentials_is_low(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve(httpserver, lambda origin: {"Access-Control-Allow-Origin": origin})
    assert await run(make_config) == [("CORS reflects arbitrary origin", Severity.LOW)]


async def test_naive_suffix_allowlist_and_null_origin(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    def policy(origin: str) -> dict[str, str]:
        if origin.endswith("127.0.0.1") or origin == "null":
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        return {}

    serve(httpserver, policy)
    assert sorted(await run(make_config)) == [
        ("CORS origin check bypass (suffix match) with credentials", Severity.HIGH),
        ("CORS trusts the 'null' origin with credentials", Severity.HIGH),
    ]


async def test_exact_allowlist_is_clean(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    serve(
        httpserver,
        lambda origin: (
            {"Access-Control-Allow-Origin": origin}
            if origin == "https://app.trusted.example"
            else {"Access-Control-Allow-Origin": "https://app.trusted.example"}
        ),
    )
    assert await run(make_config) == []


async def test_wildcard_with_credentials_is_flagged_low(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    serve(
        httpserver,
        lambda origin: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert await run(make_config) == [
        ("CORS wildcard origin combined with credentials", Severity.LOW)
    ]
