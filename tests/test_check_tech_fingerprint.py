from pytest_httpserver import HTTPServer

from tests.conftest import ConfigFactory
from wraith.checks.tech_fingerprint import load_signatures
from wraith.engine import Engine
from wraith.models import Confidence

PAGE = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/themes/x/style.css">
<script src="/wp-includes/js/jquery/jquery-3.5.1.min.js"></script>
</head><body>hi</body></html>"""


def test_signatures_load() -> None:
    names = {s.name for s in load_signatures()}
    assert {"nginx", "PHP", "WordPress", "jQuery"} <= names


async def test_detects_stack_and_versions(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        PAGE,
        content_type="text/html",
        headers={
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3",
            "Set-Cookie": "PHPSESSID=abc; Path=/",
        },
    )
    result = await Engine(make_config(checks=("tech_fingerprint",))).run()
    titles = [f.title for f in result.findings]

    assert "Technology stack detected" in titles
    assert {
        "nginx 1.18.0 version disclosed",
        "PHP 7.4.3 version disclosed",
        "WordPress 6.4.2 version disclosed",
        "jQuery 3.5.1 version disclosed",
    } <= set(titles)

    stack = next(f for f in result.findings if f.title == "Technology stack detected")
    assert stack.confidence is Confidence.INFORMATIONAL
    nginx = next(f for f in result.findings if f.title.startswith("nginx"))
    assert nginx.evidence[0].matched == "nginx/1.18.0"
    assert "server_tokens off" in nginx.remediation


async def test_no_signals_no_findings(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    httpserver.expect_request("/").respond_with_data("<html>plain</html>", content_type="text/html")
    result = await Engine(make_config(checks=("tech_fingerprint",))).run()
    assert [f.title for f in result.findings if "version" in f.title] == []
