"""CORS misconfiguration check: origin reflection and unsafe origin trust."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.models import Confidence, Finding, Severity

MAX_URLS = 5
PROBE_DOMAIN = "wraith-cors-probe.example"  # reserved TLD: can never be a real origin
REFERENCES = (
    "https://portswigger.net/web-security/cors",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
)


@dataclass(frozen=True)
class Probe:
    kind: str
    origin: str
    title: str
    trusted: str  # what the server is shown to trust


def probes_for(host: str) -> list[Probe]:
    return [
        Probe(
            "arbitrary", f"https://{PROBE_DOMAIN}", "CORS reflects arbitrary origin", "any origin"
        ),
        Probe("null", "null", "CORS trusts the 'null' origin", "the 'null' origin"),
        Probe(
            "prefix",
            f"https://{host}.{PROBE_DOMAIN}",
            "CORS origin check bypass (prefix match)",
            f"any origin that merely starts with {host}",
        ),
        Probe(
            "suffix",
            f"https://wraithprobe{host}",
            "CORS origin check bypass (suffix match)",
            f"any origin that merely ends with {host}",
        ),
    ]


class CorsCheck(BaseCheck):
    name = "cors"
    severity_hint = Severity.HIGH
    description = "Access-Control-Allow-Origin reflecting untrusted origins"

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        urls = list(dict.fromkeys([ctx.base_url, *(p.url for p in ctx.pages)]))[:MAX_URLS]
        for url in urls:
            async for finding in self._probe_url(url, http):
                yield finding

    async def _probe_url(self, url: str, http: HTTPClient) -> AsyncIterator[Finding]:
        host = httpx.URL(url).host
        for probe in probes_for(host):
            try:
                response = await http.get(
                    url, headers={"Origin": probe.origin}, follow_redirects=False
                )
            except HTTPClientError:
                continue
            acao = (response.headers.get("access-control-allow-origin") or "").strip()
            credentials = (
                response.headers.get("access-control-allow-credentials", "").strip().lower()
                == "true"
            )
            if acao == probe.origin:
                yield _reflection_finding(url, probe, response, credentials)
                if probe.kind == "arbitrary":
                    return  # every other probe is a special case of this one
            elif acao == "*" and credentials and probe.kind == "arbitrary":
                yield _wildcard_finding(url, response)


def _reflection_finding(url: str, probe: Probe, response: Response, credentials: bool) -> Finding:
    if credentials:
        severity = Severity.HIGH
        impact = (
            "Because Access-Control-Allow-Credentials is true, a malicious site can make "
            "authenticated requests as a logged-in victim and read the responses, stealing "
            "their data or anti-CSRF tokens."
        )
        title = f"{probe.title} with credentials"
    else:
        severity = Severity.LOW
        impact = (
            "Credentials are not allowed, so only data readable without the victim's cookies is "
            "exposed; impact is higher if the endpoint relies on network position (intranet) "
            "or IP allowlists."
        )
        title = probe.title
    return Finding(
        check=CorsCheck.name,
        title=title,
        url=url,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        description=(
            f"A request with Origin: {probe.origin} was answered with "
            f"Access-Control-Allow-Origin: {probe.origin}, so the server trusts {probe.trusted}. "
            + impact
        ),
        remediation=(
            "Validate the Origin header against an exact allowlist of trusted origins (full "
            "scheme + host + port match), never reflect it blindly, never trust 'null', and "
            "only send Access-Control-Allow-Credentials: true for allowlisted origins."
        ),
        evidence=(response.exchange.to_evidence(probe.origin, include_body=False),),
        references=REFERENCES,
    )


def _wildcard_finding(url: str, response: Response) -> Finding:
    return Finding(
        check=CorsCheck.name,
        title="CORS wildcard origin combined with credentials",
        url=url,
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        description=(
            "The response sends Access-Control-Allow-Origin: * together with "
            "Access-Control-Allow-Credentials: true. Browsers refuse this combination, so it is "
            "not directly exploitable, but it shows credentialed cross-origin access is "
            "intended and other code paths may reflect origins instead."
        ),
        remediation=(
            "Decide whether cross-origin credentialed access is needed. If not, drop "
            "Access-Control-Allow-Credentials; if so, use an exact origin allowlist."
        ),
        evidence=(response.exchange.to_evidence("*", include_body=False),),
        references=REFERENCES,
    )
