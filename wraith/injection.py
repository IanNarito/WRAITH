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

    for page in ctx.pages:
        split = urlsplit(page.url)
        if not split.query:
            continue
        params = dict(parse_qsl(split.query, keep_blank_values=True))
        action = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        for name in params:
            add(InjectionPoint("GET", action, name, dict(params), "query", page.url))

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


async def send_probe(http: HTTPClient, point: InjectionPoint, value: str) -> Response:
    """Send ``point`` with its ``param`` set to ``value``; other params keep baseline values."""
    params = {**point.params, point.param: value}
    if point.method == "GET":
        split = urlsplit(point.action)
        url = urlunsplit((split.scheme, split.netloc, split.path, urlencode(params), ""))
        return await http.get(url)
    return await http.request("POST", point.action, data=params)
