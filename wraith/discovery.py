"""Lightweight discovery: base page, robots.txt, sitemap.xml, same-origin links one level deep,
forms, and technology hints. Builds the ScanContext every check shares.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx
import yaml
from bs4 import BeautifulSoup

from wraith import data
from wraith.context import Form, FormField, Page, ScanContext, TechHint
from wraith.http_client import REDIRECT_STATUSES, HTTPClient, HTTPClientError, Response
from wraith.scope import DEFAULT_PORTS, ScopeManager

logger = logging.getLogger("wraith.discovery")

DEFAULT_MAX_PAGES = 30
MAX_SITEMAP_DOCS = 5
_LOC_RE = re.compile(r"<(?:\w+:)?loc>\s*(.*?)\s*</(?:\w+:)?loc>", re.IGNORECASE | re.DOTALL)
_IGNORED_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "about:", "blob:")


class DiscoveryError(Exception):
    """The target could not be used as a scan base."""


@dataclass(frozen=True)
class DiscoveryRules:
    skip_extensions: frozenset[str]
    unsafe_patterns: tuple[re.Pattern[str], ...]
    tech_hint_headers: tuple[str, ...]

    def is_unsafe(self, url: str) -> bool:
        parts = urlsplit(url)
        target = parts.path + ("?" + parts.query if parts.query else "")
        return any(p.search(target) for p in self.unsafe_patterns)

    def is_static(self, url: str) -> bool:
        path = urlsplit(url).path.lower()
        return any(path.endswith(ext) for ext in self.skip_extensions)


@lru_cache(maxsize=1)
def load_rules() -> DiscoveryRules:
    raw = yaml.safe_load(data.read_text("discovery.yaml"))
    return DiscoveryRules(
        skip_extensions=frozenset(str(e).lower() for e in raw["skip_extensions"]),
        unsafe_patterns=tuple(re.compile(p, re.IGNORECASE) for p in raw["unsafe_link_patterns"]),
        tech_hint_headers=tuple(str(h).lower() for h in raw["tech_hint_headers"]),
    )


@dataclass
class ParsedHtml:
    links: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    generator: str | None = None


async def discover(
    target: str,
    http: HTTPClient,
    scope: ScopeManager,
    *,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_depth: int = 1,
) -> ScanContext:
    rules = load_rules()
    try:
        base_response = await http.get(target)
    except HTTPClientError as exc:
        raise DiscoveryError(f"could not fetch target {target}: {exc}") from exc
    location = base_response.headers.get("location")
    if base_response.status_code in REDIRECT_STATUSES and location:
        raise DiscoveryError(
            f"target redirects to {urljoin(str(base_response.url), location)}, which is out of "
            "scope; add that host to --scope if you are authorized, or scan it directly"
        )
    base = to_page(base_response)
    origin = _origin(base.url)
    off_scope: set[str] = set()
    unsafe: set[str] = set()

    robots_paths, robots_sitemaps = await _fetch_robots(http, base.url)
    sitemap_urls = await _fetch_sitemaps(http, scope, base.url, robots_sitemaps, off_scope)
    base_html = parse_html(base.url, base.body) if base.is_html else ParsedHtml()

    def crawlable(url: str) -> bool:
        """Classify a link: record off-scope/unsafe ones, return True if it should be fetched."""
        if not scope.is_in_scope(url):
            off_scope.add(url)
            return False
        if _origin(url) != origin or rules.is_static(url):
            return False
        if rules.is_unsafe(url):
            unsafe.add(url)
            return False
        return True

    # Same-origin breadth-first crawl. The base page is depth 0; its links are depth 1, etc.
    # Every hop is still a GET through the scope-checked, rate-limited client.
    seen: set[str] = {base.url}
    fetched_pages: list[Page] = []
    level: list[str] = _new_links([*base_html.links, *sitemap_urls], seen, crawlable)
    depth = 1
    while level and len(fetched_pages) < max_pages:
        batch = level[: max_pages - len(fetched_pages)]
        results = await asyncio.gather(*(_fetch_page(http, u) for u in batch))
        next_level: list[str] = []
        for page in results:
            if page is None:
                continue
            fetched_pages.append(page)
            if depth < max_depth:
                next_level += _new_links(_parse_if_html(page).links, seen, crawlable)
        level = next_level
        depth += 1
    if level:
        logger.info(
            "discovery: page budget %d reached; %d link(s) not crawled", max_pages, len(level)
        )
    pages = [base, *fetched_pages]

    forms: dict[tuple[str, str, tuple[str, ...]], Form] = {}
    scripts: dict[str, None] = {}
    hints: dict[TechHint, None] = {}
    for page in pages:
        parsed = base_html if page is base else _parse_if_html(page)
        for form in parsed.forms:
            forms.setdefault((form.action, form.method, form.parameters), form)
        scripts.update(dict.fromkeys(parsed.scripts))
        if parsed.generator:
            hints[TechHint("meta:generator", parsed.generator)] = None
    for name in rules.tech_hint_headers:
        for value in base.header_values(name):
            hints[TechHint(f"header:{name}", value)] = None
    for cookie in base.header_values("set-cookie"):
        cookie_name = cookie.split("=", 1)[0].strip()
        if cookie_name:
            hints[TechHint("cookie", cookie_name)] = None

    logger.info(
        "discovery: %d pages, %d forms, %d robots paths, %d sitemap URLs, %d off-scope links",
        len(pages),
        len(forms),
        len(robots_paths),
        len(sitemap_urls),
        len(off_scope),
    )
    return ScanContext(
        target=target,
        base=base,
        pages=tuple(pages),
        forms=tuple(forms.values()),
        robots_paths=robots_paths,
        sitemap_urls=sitemap_urls,
        script_srcs=tuple(scripts),
        tech_hints=tuple(hints),
        off_scope_urls=tuple(sorted(off_scope)),
        unsafe_urls=tuple(sorted(unsafe)),
    )


def _new_links(links: list[str], seen: set[str], crawlable: Callable[[str], bool]) -> list[str]:
    """First-seen links that should be crawled; updates ``seen`` with everything considered."""
    out: list[str] = []
    for url in links:
        if url in seen:
            continue
        seen.add(url)
        if crawlable(url):
            out.append(url)
    return out


def to_page(response: Response) -> Page:
    return Page(
        url=str(response.url),
        status=response.status_code,
        headers=response.exchange.response_headers,
        body=response.text,
        exchange=response.exchange,
    )


async def _fetch_page(http: HTTPClient, url: str) -> Page | None:
    try:
        response = await http.get(url)
    except HTTPClientError as exc:
        logger.debug("discovery: skipping %s: %s", url, exc)
        return None
    if response.status_code >= 400 or response.status_code in REDIRECT_STATUSES:
        return None
    return to_page(response)


async def _fetch_robots(http: HTTPClient, base_url: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        response = await http.get(urljoin(base_url, "/robots.txt"))
    except HTTPClientError:
        return (), ()
    if response.status_code != 200 or _looks_like_html(response.text):
        return (), ()
    paths: dict[str, None] = {}
    sitemaps: dict[str, None] = {}
    for line in response.text.splitlines():
        key, sep, value = line.split("#", 1)[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if not sep or not value:
            continue
        if key in ("allow", "disallow"):
            paths[value] = None
        elif key == "sitemap":
            sitemaps[value] = None
    return tuple(paths), tuple(sitemaps)


async def _fetch_sitemaps(
    http: HTTPClient,
    scope: ScopeManager,
    base_url: str,
    declared: tuple[str, ...],
    off_scope: set[str],
) -> tuple[str, ...]:
    queue = list(
        dict.fromkeys(
            [*(urljoin(base_url, s) for s in declared), urljoin(base_url, "/sitemap.xml")]
        )
    )
    seen: set[str] = set()
    found: dict[str, None] = {}
    fetched = 0
    while queue and fetched < MAX_SITEMAP_DOCS:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        if not scope.is_in_scope(url):
            off_scope.add(url)
            continue
        fetched += 1
        try:
            response = await http.get(url)
        except HTTPClientError:
            continue
        if response.status_code != 200:
            continue
        is_index, locs = parse_sitemap(response.text)
        if is_index:
            queue.extend(locs)
        else:
            found.update(dict.fromkeys(locs))
    return tuple(found)


def parse_sitemap(text: str) -> tuple[bool, list[str]]:
    """Return (is_sitemap_index, loc URLs). Regex-based: no XML parser, no entity expansion."""
    lowered = text[:4096].lower()
    if "<urlset" not in lowered and "<sitemapindex" not in lowered:
        return False, []
    locs = [html.unescape(m) for m in _LOC_RE.findall(text) if m]
    return "<sitemapindex" in lowered, locs


def parse_html(page_url: str, body: str) -> ParsedHtml:
    soup: Any = BeautifulSoup(body, "lxml")
    parsed = ParsedHtml()
    link_base = page_url
    base_tag = soup.find("base", href=True)
    if base_tag is not None:
        link_base = urljoin(page_url, _attr(base_tag, "href") or "")

    for tag in soup.find_all(["a", "area", "iframe", "frame"]):
        href = _attr(tag, "href") or _attr(tag, "src")
        if href and (url := normalize_link(link_base, href)):
            parsed.links.append(url)

    for form in soup.find_all("form"):
        action = normalize_link(link_base, _attr(form, "action") or "") or page_url
        fields: list[FormField] = []
        for element in form.find_all(["input", "select", "textarea", "button"]):
            name = _attr(element, "name")
            if not name:
                continue
            if element.name == "input":
                kind = (_attr(element, "type") or "text").lower()
                fields.append(FormField(name, kind, _attr(element, "value") or ""))
            else:
                fields.append(FormField(name, element.name, _attr(element, "value") or ""))
        method = (_attr(form, "method") or "GET").upper()
        parsed.forms.append(Form(page_url, action, method, tuple(fields)))

    for script in soup.find_all("script", src=True):
        if url := normalize_link(link_base, _attr(script, "src") or ""):
            parsed.scripts.append(url)

    generator = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.IGNORECASE)})
    if generator is not None:
        parsed.generator = _attr(generator, "content")
    return parsed


def normalize_link(base: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith("#") or href.lower().startswith(_IGNORED_SCHEMES):
        return None
    absolute, _fragment = urldefrag(urljoin(base, href))
    if urlsplit(absolute).scheme.lower() not in DEFAULT_PORTS:
        return None
    return absolute


def _parse_if_html(page: Page) -> ParsedHtml:
    return parse_html(page.url, page.body) if page.is_html else ParsedHtml()


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL:
        return None
    scheme = parsed.scheme.lower()
    return scheme, parsed.host.lower(), parsed.port or DEFAULT_PORTS.get(scheme, 0)


def _looks_like_html(text: str) -> bool:
    return text.lstrip()[:100].lower().startswith(("<!doctype", "<html"))


def _attr(tag: Any, name: str) -> str | None:
    value = tag.get(name)
    if value is None:
        return None
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value)
