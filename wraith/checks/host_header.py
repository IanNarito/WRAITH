"""Host header injection detection (aggressive).

Sends the base request with an attacker-style host in the Host and X-Forwarded-Host headers
and checks whether that marker host is reflected into the response body (e.g. absolute links,
password-reset URLs) or into a redirect Location. Apps that build absolute URLs from the Host
header are vulnerable to cache poisoning and password-reset poisoning. Single GET per page,
non-destructive.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.models import Confidence, Finding, Severity

MARKER_HOST = "wraith-evil.example"
MAX_PAGES = 5
REFERENCES = (
    "https://portswigger.net/web-security/host-header",
    "https://cwe.mitre.org/data/definitions/644.html",
)


class HostHeaderCheck(BaseCheck):
    name = "host_header_injection"
    severity_hint = Severity.MEDIUM
    description = "Reflected Host / X-Forwarded-Host header used to build URLs"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        urls = list(dict.fromkeys(p.url for p in ctx.pages if p.is_html))[:MAX_PAGES]
        for url in urls:
            finding = await _probe(http, url)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, url: str) -> Finding | None:
    # Two independent vectors: a spoofed absolute Host, and X-Forwarded-Host (honored by many
    # frameworks/proxies even when Host is validated).
    for header in ("X-Forwarded-Host", "Host"):
        try:
            response = await http.get(url, headers={header: MARKER_HOST}, follow_redirects=False)
        except HTTPClientError:
            continue
        where = _reflected(response)
        if where is not None:
            return _finding(url, header, where, response)
    return None


def _reflected(response: Response) -> str | None:
    location = response.headers.get("location", "")
    if MARKER_HOST in location:
        return f"Location header ({location})"
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type in ("text/html", "application/xhtml+xml", "") and MARKER_HOST in response.text:
        return "response body (e.g. an absolute link built from the host)"
    return None


def _finding(url: str, header: str, where: str, response: Response) -> Finding:
    return Finding(
        check=HostHeaderCheck.name,
        title=f"Host header injection via {header}",
        url=url,
        severity=Severity.MEDIUM,
        confidence=Confidence.PROBABLE,
        description=(
            f"Setting {header}: {MARKER_HOST} caused that attacker-controlled host to appear in "
            f"the {where}. If the application builds absolute URLs (links, password-reset links, "
            "resource loads) from the request host, an attacker can poison them - for example to "
            "steal password-reset tokens or poison a shared cache."
        ),
        remediation=(
            "Do not build absolute URLs from the incoming Host/X-Forwarded-Host header. Use a "
            "configured canonical domain, validate Host against an allowlist at the edge, and "
            "ignore X-Forwarded-* headers unless they come from a trusted proxy."
        ),
        evidence=(response.exchange.to_evidence(MARKER_HOST),),
        references=REFERENCES,
    )
