from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from tests.conftest import ConfigFactory
from wraith.engine import Engine
from wraith.models import Confidence, Severity

HTML = {"content_type": "text/html"}


# --- CRLF injection -----------------------------------------------------------------------------


async def test_crlf_injection_detected(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/set?lang=en'>s</a>", **HTML)

    def set_lang(request: Request) -> Response:
        lang = request.args.get("lang", "")
        headers = {}
        # Vulnerable: reflects the value into a header after splitting on CRLF.
        if "\r\n" in lang or "\n" in lang:
            for line in lang.replace("\r\n", "\n").split("\n")[1:]:
                if ":" in line:
                    name, _, val = line.partition(":")
                    headers[name.strip()] = val.strip()
        return Response("ok", headers=headers, content_type="text/html")

    httpserver.expect_request("/set").respond_with_handler(set_lang)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)

    result = await Engine(make_config(checks=("crlf_injection",), safe_mode=False)).run()
    crlf = [f for f in result.findings if f.check == "crlf_injection"]
    assert len(crlf) == 1
    assert crlf[0].confidence is Confidence.CONFIRMED
    assert crlf[0].title == "CRLF header injection in parameter 'lang'"


# --- Host header injection ----------------------------------------------------------------------


async def test_host_header_injection_detected(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    def home(request: Request) -> Response:
        host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
        return Response(f"<html><a href='https://{host}/reset'>reset</a></html>", **HTML)

    httpserver.expect_request("/").respond_with_handler(home)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)

    result = await Engine(make_config(checks=("host_header_injection",), safe_mode=False)).run()
    hh = [f for f in result.findings if f.check == "host_header_injection"]
    assert len(hh) == 1
    assert hh[0].severity is Severity.MEDIUM
    assert "wraith-evil.example" in hh[0].evidence[0].response_snippet


async def test_host_header_not_reflected_is_clean(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<html><a href='https://fixed.example/'>x</a></html>", **HTML
    )
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)
    result = await Engine(make_config(checks=("host_header_injection",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "host_header_injection"] == []


# --- SSRF ---------------------------------------------------------------------------------------


async def test_ssrf_detected_via_fetch_error(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/fetch?url=home'>f</a>", **HTML)

    def fetch(request: Request) -> Response:
        url = request.args.get("url", "")
        if url.startswith("http"):  # simulate a server trying to fetch and failing
            return Response(
                f"Failed to connect to {url.split('//')[1].split('/')[0]}: "
                "Name or service not known",
                content_type="text/plain",
            )
        return Response("no url", content_type="text/plain")

    httpserver.expect_request("/fetch").respond_with_handler(fetch)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)

    result = await Engine(make_config(checks=("ssrf",), safe_mode=False)).run()
    ssrf = [f for f in result.findings if f.check == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0].title == "Possible SSRF in parameter 'url'"
    assert ssrf[0].confidence is Confidence.PROBABLE


async def test_ssrf_plain_reflection_is_not_flagged(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/fetch?url=home'>f</a>", **HTML)

    # Reflects the url but shows no fetch error -> not SSRF evidence.
    def fetch(request: Request) -> Response:
        return Response(f"You asked for {request.args.get('url', '')}", content_type="text/plain")

    httpserver.expect_request("/fetch").respond_with_handler(fetch)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)
    result = await Engine(make_config(checks=("ssrf",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "ssrf"] == []


# --- XXE ----------------------------------------------------------------------------------------


async def test_xxe_internal_entity_expansion_detected(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    import re
    from xml.sax.saxutils import unescape  # noqa: F401 (document intent)

    httpserver.expect_request("/").respond_with_data("<a href='/api?x=1'>a</a>", **HTML)

    def api(request: Request) -> Response:
        body = request.get_data(as_text=True)
        # Simulate an XML parser that resolves the internal entity.
        m = re.search(r'<!ENTITY wr "([^"]*)">', body)
        if m and "&wr;" in body:
            return Response(body.replace("&wr;", m.group(1)), content_type="application/xml")
        return Response("ok", content_type="text/plain")

    httpserver.expect_request("/api").respond_with_handler(api)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)

    result = await Engine(make_config(checks=("xxe",), safe_mode=False)).run()
    xxe = [f for f in result.findings if f.check == "xxe"]
    assert len(xxe) == 1
    assert xxe[0].title == "XML entity expansion (possible XXE)"


async def test_xxe_not_flagged_when_body_only_reflected(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<a href='/api?x=1'>a</a>", **HTML)

    # Echoes the raw body (so "&wr;" is present and the marker is not) -> no entity processing.
    def api(request: Request) -> Response:
        return Response(request.get_data(as_text=True), content_type="application/xml")

    httpserver.expect_request("/api").respond_with_handler(api)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)
    result = await Engine(make_config(checks=("xxe",), safe_mode=False)).run()
    assert [f for f in result.findings if f.check == "xxe"] == []
