import re

from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.engine import Engine
from wraith.models import Confidence, Severity

HTML = {"content_type": "text/html"}


def _robots(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)


# --- Command injection --------------------------------------------------------------------------


async def test_command_injection_echo_detected(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/ping?host=127.0.0.1'>p</a>", **HTML)

    def ping(request: Request) -> Response:
        host = request.args.get("host", "")
        # Simulate a vulnerable shell call: run `ping <host>` and echo-marker executes.
        out = f"PING {host.split(';')[0]}\n"
        m = re.search(r";echo (\S+)", host) or re.search(r"\$\(echo (\S+)\)", host)
        if m:  # the shell executed the injected echo and printed the token alone
            out += m.group(1) + "\n"
        return Response(out, content_type="text/plain")

    httpserver.expect_request("/ping").respond_with_handler(ping)
    _robots(httpserver)

    result = await Engine(make_config(checks=("command_injection",), safe_mode=False)).run()
    ci = [f for f in result.findings if f.check == "command_injection"]
    assert len(ci) == 1
    assert ci[0].title == "OS command injection (echo marker) in parameter 'host'"
    assert ci[0].severity is Severity.CRITICAL
    assert ci[0].confidence is Confidence.CONFIRMED


async def test_command_injection_plain_reflection_is_clean(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/ping?host=127.0.0.1'>p</a>", **HTML)

    # Reflects the raw input verbatim (so "echo <token>" is present) -> not execution.
    def ping(request: Request) -> Response:
        echoed = f"You asked to ping {request.args.get('host', '')}"
        return Response(echoed, content_type="text/plain")

    httpserver.expect_request("/ping").respond_with_handler(ping)
    _robots(httpserver)
    result = await Engine(make_config(checks=("command_injection",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "command_injection"] == []


# --- SSTI ---------------------------------------------------------------------------------------


async def test_ssti_detected_via_arithmetic(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/hi?name=bob'>h</a>", **HTML)

    def hi(request: Request) -> Response:
        name = request.args.get("name", "")
        # Simulate a template engine that evaluates {{ a*b }} / ${ a*b } expressions.
        m = re.search(r"\{\{(\d+)\*(\d+)\}\}", name) or re.search(r"\$\{(\d+)\*(\d+)\}", name)
        if m:
            name = str(int(m.group(1)) * int(m.group(2)))
        return Response(f"<html>Hello {name}</html>", content_type="text/html")

    httpserver.expect_request("/hi").respond_with_handler(hi)
    _robots(httpserver)

    result = await Engine(make_config(checks=("ssti",), safe_mode=False)).run()
    ssti = [f for f in result.findings if f.check == "ssti"]
    assert len(ssti) == 1
    assert ssti[0].title == "Server-side template injection in parameter 'name'"
    assert ssti[0].severity is Severity.HIGH
    assert ssti[0].confidence is Confidence.CONFIRMED


async def test_ssti_plain_reflection_is_clean(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/hi?name=bob'>h</a>", **HTML)

    # Echoes the expression unevaluated -> the literal "a*b" is present, so no finding.
    def hi(request: Request) -> Response:
        echoed = f"<html>Hello {request.args.get('name', '')}</html>"
        return Response(echoed, content_type="text/html")

    httpserver.expect_request("/hi").respond_with_handler(hi)
    _robots(httpserver)
    result = await Engine(make_config(checks=("ssti",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "ssti"] == []
