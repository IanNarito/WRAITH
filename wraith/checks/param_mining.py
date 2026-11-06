"""Parameter mining (aggressive): discover hidden/unlinked request parameters.

For a bounded set of endpoints, sends a GET with many candidate parameter names - each set to a
unique marker - and reports the names whose marker is reflected in the response. Reflected
unknown parameters reveal hidden functionality and additional attack surface for the injection
checks. GET-only and non-mutating; many names are tested per request to keep volume low.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from functools import lru_cache
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from wraith import data
from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.models import Confidence, Finding, Severity

logger = logging.getLogger("wraith.checks.param_mining")
MAX_ENDPOINTS = 10
CHUNK = 25  # candidate names per request


@lru_cache(maxsize=1)
def load_param_names() -> tuple[str, ...]:
    names = []
    for line in data.read_text("param_names.txt").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return tuple(dict.fromkeys(names))


class ParamMiningCheck(BaseCheck):
    name = "param_mining"
    severity_hint = Severity.INFO
    description = "Discover hidden reflected request parameters (attack-surface mapping)"
    enabled_by_default = False  # opt in with --checks param_mining
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        endpoints = _endpoints(ctx)
        names = load_param_names()
        for action, existing in endpoints[:MAX_ENDPOINTS]:
            reflected = await _mine(http, action, existing, names)
            for name, response in reflected.items():
                yield _finding(action, name, response)


def _endpoints(ctx: ScanContext) -> list[tuple[str, dict[str, str]]]:
    """(action, existing-params) for the base, parameterized URLs, and crawled pages."""
    seen: dict[str, dict[str, str]] = {}
    for url in [ctx.base_url, *ctx.param_urls, *(p.url for p in ctx.pages if p.is_html)]:
        split = urlsplit(url)
        action = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        seen.setdefault(action, dict(parse_qsl(split.query, keep_blank_values=True)))
    return list(seen.items())


async def _mine(
    http: HTTPClient, action: str, existing: dict[str, str], names: tuple[str, ...]
) -> dict[str, Response]:
    token = secrets.token_hex(4)
    found: dict[str, Response] = {}
    candidates = [n for n in names if n not in existing]
    for start in range(0, len(candidates), CHUNK):
        chunk = candidates[start : start + CHUNK]
        # Fixed width + trailing sentinel so no marker is a substring of another.
        markers = {name: f"wrp{token}{i:04d}z" for i, name in enumerate(chunk, start)}
        params = {**existing, **markers}
        url = urlunsplit((*urlsplit(action)[:3], urlencode(params), ""))
        try:
            response = await http.get(url)
        except HTTPClientError:
            continue
        body = response.text
        for name, marker in markers.items():
            if marker in body:
                found[name] = response
    return found


def _finding(action: str, name: str, response: Response) -> Finding:
    return Finding(
        check=ParamMiningCheck.name,
        title=f"Hidden parameter {name!r} is reflected",
        url=action,
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        description=(
            f"The endpoint reflects the value of an unlinked request parameter {name!r} that is "
            "not used by any discovered link or form. Hidden parameters expand the attack surface "
            "and are worth testing for injection (XSS, SQLi) and access-control issues."
        ),
        remediation=(
            "Remove unused parameter handling, and ensure every accepted parameter is validated "
            "and output-encoded like any other input."
        ),
        evidence=(response.exchange.to_evidence(name),),
    )
