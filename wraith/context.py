"""ScanContext: shared recon state built by discovery. Read-only to checks."""

from __future__ import annotations

from dataclasses import dataclass

from wraith.http_client import Exchange

HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})


@dataclass(frozen=True)
class FormField:
    name: str
    type: str
    value: str = ""


@dataclass(frozen=True)
class Form:
    page_url: str
    action: str
    method: str
    fields: tuple[FormField, ...]

    @property
    def parameters(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields)


@dataclass(frozen=True)
class Page:
    url: str  # final URL after in-scope redirects
    status: int
    headers: tuple[tuple[str, str], ...]
    body: str
    exchange: Exchange

    def header(self, name: str) -> str | None:
        """First value of a header (case-insensitive), or None."""
        values = self.header_values(name)
        return values[0] if values else None

    def header_values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";", 1)[0].strip().lower()

    @property
    def is_html(self) -> bool:
        if self.content_type:
            return self.content_type in HTML_TYPES
        head = self.body.lstrip()[:200].lower()
        return head.startswith(("<!doctype html", "<html"))

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")


@dataclass(frozen=True)
class TechHint:
    source: str  # e.g. "header:server", "meta:generator", "cookie"
    value: str


@dataclass(frozen=True)
class ScanContext:
    target: str  # as given by the user
    base: Page  # the target's response, after in-scope redirects
    pages: tuple[Page, ...]  # all fetched pages, base first
    forms: tuple[Form, ...]
    robots_paths: tuple[str, ...]  # Allow/Disallow entries from robots.txt
    sitemap_urls: tuple[str, ...]
    script_srcs: tuple[str, ...]
    tech_hints: tuple[TechHint, ...]
    off_scope_urls: tuple[str, ...]  # discovered but out of scope: recorded, never requested
    unsafe_urls: tuple[str, ...]  # in scope but look state-changing (logout, delete): not requested

    @property
    def base_url(self) -> str:
        return self.base.url
