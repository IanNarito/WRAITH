from urllib.parse import urlsplit

import pytest
from pytest_httpserver import HTTPServer

from tests.conftest import ConfigFactory
from wraith.discovery import DiscoveryError, discover, parse_sitemap
from wraith.http_client import HTTPClient
from wraith.scope import ScopeManager

HOME = """<!doctype html>
<html><head>
  <meta name="generator" content="WordPress 6.4.2">
  <script src="/static/app.js"></script>
</head><body>
  <a href="/about">About</a>
  <a href="/about#team">About (fragment)</a>
  <a href="/logout">Log out</a>
  <a href="/items/delete?id=3">Delete</a>
  <a href="https://evil.example/x">Elsewhere</a>
  <a href="/img/logo.png">Logo</a>
  <a href="mailto:a@b.c">Mail</a>
  <a href="javascript:void(0)">JS</a>
  <form action="/login" method="post">
    <input name="user"><input type="password" name="pass"><input type="submit" value="Go">
  </form>
</body></html>"""


def serve_site(httpserver: HTTPServer) -> None:
    html = {"content_type": "text/html"}
    httpserver.expect_request("/").respond_with_data(
        HOME, headers={"Server": "nginx/1.18.0", "Set-Cookie": "PHPSESSID=abc; Path=/"}, **html
    )
    httpserver.expect_request("/robots.txt").respond_with_data(
        "User-agent: *\nDisallow: /admin  # secret\nAllow: /public\n"
        f"Sitemap: {httpserver.url_for('/sitemap.xml')}\n",
        content_type="text/plain",
    )
    httpserver.expect_request("/sitemap.xml").respond_with_data(
        f"<?xml version='1.0'?><urlset><url><loc>{httpserver.url_for('/from-sitemap')}</loc>"
        "</url><url><loc>https://other.example/page</loc></url></urlset>",
        content_type="application/xml",
    )
    httpserver.expect_request("/about").respond_with_data(
        "<html><body><form><input name='q'></form></body></html>", **html
    )
    httpserver.expect_request("/from-sitemap").respond_with_data("<html>ok</html>", **html)


async def test_discovery_builds_context(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    serve_site(httpserver)
    config = make_config()
    scope = ScopeManager(config.scope)
    async with HTTPClient(config, scope) as http:
        ctx = await discover(config.target, http, scope)

    page_paths = sorted(urlsplit(p.url).path for p in ctx.pages)
    assert page_paths == ["/", "/about", "/from-sitemap"]
    assert ctx.robots_paths == ("/admin", "/public")
    assert ctx.sitemap_urls == (httpserver.url_for("/from-sitemap"), "https://other.example/page")
    assert "https://evil.example/x" in ctx.off_scope_urls
    assert "https://other.example/page" in ctx.off_scope_urls
    assert {_path_query(u) for u in ctx.unsafe_urls} == {
        "/logout",
        "/items/delete?id=3",
    }

    login = next(f for f in ctx.forms if f.action.endswith("/login"))
    assert login.method == "POST"
    assert login.parameters == ("user", "pass")
    search = next(f for f in ctx.forms if f.page_url.endswith("/about"))
    assert search.method == "GET" and search.parameters == ("q",)

    hints = {(h.source, h.value) for h in ctx.tech_hints}
    assert ("header:server", "nginx/1.18.0") in hints
    assert ("meta:generator", "WordPress 6.4.2") in hints
    assert ("cookie", "PHPSESSID") in hints
    assert ctx.script_srcs == (httpserver.url_for("/static/app.js"),)

    # Unsafe, static, and off-scope URLs were never requested.
    requested = {req.path for req, _ in httpserver.log}
    assert requested == {"/", "/robots.txt", "/sitemap.xml", "/about", "/from-sitemap"}


async def test_base_redirect_off_scope_is_an_error(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "", status=301, headers={"Location": "https://www.elsewhere.example/"}
    )
    config = make_config()
    scope = ScopeManager(config.scope)
    async with HTTPClient(config, scope) as http:
        with pytest.raises(DiscoveryError, match="out of scope"):
            await discover(config.target, http, scope)


async def test_soft_404_robots_is_ignored(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<html></html>", content_type="text/html")
    httpserver.expect_request("/robots.txt").respond_with_data(
        "<!doctype html><html>Disallow: /nope</html>", content_type="text/html"
    )
    config = make_config()
    scope = ScopeManager(config.scope)
    async with HTTPClient(config, scope) as http:
        ctx = await discover(config.target, http, scope)
    assert ctx.robots_paths == ()


def test_parse_sitemap_index_and_entities() -> None:
    is_index, locs = parse_sitemap(
        "<sitemapindex><sitemap><loc>https://a.test/s1.xml?a=1&amp;b=2</loc></sitemap>"
        "</sitemapindex>"
    )
    assert is_index
    assert locs == ["https://a.test/s1.xml?a=1&b=2"]
    assert parse_sitemap("<html>not a sitemap</html>") == (False, [])


def _path_query(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


async def test_crawl_depth_bfs(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    html = {"content_type": "text/html"}
    httpserver.expect_request("/").respond_with_data("<a href='/a'>a</a>", **html)
    httpserver.expect_request("/a").respond_with_data("<a href='/b'>b</a>", **html)
    httpserver.expect_request("/b").respond_with_data("<a href='/c'>c</a>", **html)
    httpserver.expect_request("/c").respond_with_data("<html>leaf</html>", **html)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)

    config = make_config()
    scope = ScopeManager(config.scope)

    async with HTTPClient(config, scope) as http:
        depth1 = await discover(config.target, http, scope, max_depth=1)
    assert sorted(urlsplit(p.url).path for p in depth1.pages) == ["/", "/a"]

    async with HTTPClient(config, scope) as http:
        depth3 = await discover(config.target, http, scope, max_depth=3)
    assert sorted(urlsplit(p.url).path for p in depth3.pages) == ["/", "/a", "/b", "/c"]


async def test_crawl_respects_max_pages(httpserver: HTTPServer, make_config: ConfigFactory) -> None:
    html = {"content_type": "text/html"}
    links = "".join(f"<a href='/p{i}'>{i}</a>" for i in range(10))
    httpserver.expect_request("/").respond_with_data(links, **html)
    for i in range(10):
        httpserver.expect_request(f"/p{i}").respond_with_data("<html>leaf</html>", **html)
    httpserver.expect_request("/robots.txt").respond_with_data("", content_type="text/plain")
    httpserver.expect_request("/sitemap.xml").respond_with_data("", status=404)

    config = make_config()
    scope = ScopeManager(config.scope)
    async with HTTPClient(config, scope) as http:
        ctx = await discover(config.target, http, scope, max_pages=3, max_depth=2)
    assert len(ctx.pages) == 4  # base + 3 crawled
