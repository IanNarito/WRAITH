"""Shared substrate for the aggressive injection checks (XSS, SQLi).

Enumerates injection points - a single parameter of a GET query or a form - from the recon
context, and sends a request with one parameter replaced by a probe value. All requests go
through the scope-checked, rate-limited, safe-mode-gated HTTPClient; sending a form body is a
mutating request, so these checks run only under --aggressive.

Nothing here is destructive: it substitutes marker/boundary values into existing parameters to
observe how the application reflects or errors on them. It does not attempt to extract data or
change server state beyond the single request a normal form submission would make.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from wraith.context import ScanContext
from wraith.http_client import HTTPClient, Response

# Form field types whose value is free-ish text worth fuzzing (others are value-constrained).
_TEXTUAL_FIELD_TYPES = frozenset(
    {"text", "search", "url", "email", "tel", "textarea", "hidden", "", "number", "password"}
)
MAX_POINTS = 60  # bound the request budget per check across the whole scan

# Parameter names that commonly carry a URL or path (used to focus redirect/SSRF/LFI probing).
URL_PARAM_HINTS = frozenset(
    {
        "url",
        "uri",
        "link",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "returnurl",
        "return_url",
        "returnto",
        "return_to",
        "next",
        "goto",
        "go",
        "dest",
        "destination",
        "continue",
        "target",
        "to",
        "out",
        "view",
        "page",
        "r",
        "u",
        "callback",
        "image",
        "img",
        "file",
        "path",
        "src",
        "source",
        "load",
        "data",
        "domain",
        "host",
        "site",
        "feed",
    }
)


def looks_like_url_or_path(value: str) -> bool:
    v = value.strip().lower()
    return (
        v.startswith(("http://", "https://", "//", "/", "www.", "ftp://"))
        or "://" in v
        or v.endswith((".php", ".html", ".jsp", ".asp", ".aspx", ".txt", ".xml", ".json"))
    )


def is_urlish_point(point: InjectionPoint) -> bool:
    """A point worth URL/path probing: its name hints at a URL, or its value looks like one."""
    return point.param.lower() in URL_PARAM_HINTS or looks_like_url_or_path(point.baseline())


@dataclass(frozen=True)
class InjectionPoint:
    method: str  # GET or POST
    action: str  # URL the request is sent to (no query for the tested params)
    param: str  # the parameter being fuzzed
    params: dict[str, str] = field(default_factory=dict)  # all params with baseline values
    source: str = "query"  # "query" or "form"
    found_on: str = ""  # page where this point was discovered

    def identity(self) -> tuple[str, str, str, tuple[str, ...]]:
        return (self.method, self.action, self.param, tuple(sorted(self.params)))

    def baseline(self) -> str:
        return self.params.get(self.param, "")


def points_from_context(ctx: ScanContext, *, include_forms: bool = True) -> list[InjectionPoint]:
    """Every fuzzable (parameter) injection point found during recon, de-duplicated."""
    points: dict[tuple[str, str, str, tuple[str, ...]], InjectionPoint] = {}

    def add(point: InjectionPoint) -> None:
        points.setdefault(point.identity(), point)

    query_urls = {p.url for p in ctx.pages} | set(ctx.param_urls)
    for url in query_urls:
        split = urlsplit(url)
        if not split.query:
            continue
        params = dict(parse_qsl(split.query, keep_blank_values=True))
        action = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        for name in params:
            add(InjectionPoint("GET", action, name, dict(params), "query", url))

    if include_forms:
        for form in ctx.forms:
            params = {
                f.name: f.value
                for f in form.fields
                if f.type.lower() in _TEXTUAL_FIELD_TYPES and f.name
            }
            for name in params:
                add(
                    InjectionPoint(
                        form.method.upper(), form.action, name, dict(params), "form", form.page_url
                    )
                )

    return list(points.values())


async def send_probe(
    http: HTTPClient, point: InjectionPoint, value: str, *, follow_redirects: bool = True
) -> Response:
    """Send ``point`` with its ``param`` set to ``value``; other params keep baseline values."""
    params = {**point.params, point.param: value}
    if point.method == "GET":
        split = urlsplit(point.action)
        url = urlunsplit((split.scheme, split.netloc, split.path, urlencode(params), ""))
        return await http.get(url, follow_redirects=follow_redirects)
    return await http.request("POST", point.action, data=params, follow_redirects=follow_redirects)
