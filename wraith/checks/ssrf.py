"""Server-side request forgery (SSRF) detection (aggressive, conservative).

Full SSRF confirmation normally needs an out-of-band collaborator server, which WRAITH does not
run. To stay safe and keep false positives low, this check uses an in-band signal only: it sets
a URL-like parameter to an UNRESOLVABLE marker host (``*.invalid``, reserved by RFC 6761 so it
can never route anywhere) and reports only when the response shows a server-side fetch *error*
that names the marker host and did not appear in the baseline. That proves the server tried to
make the request without it ever reaching a real third party.

Plain reflection of the value (without a fetch error) is NOT reported here - that is the XSS
checks' domain, not evidence of SSRF. Findings are PROBABLE; confirm with a collaborator.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import (
    MAX_POINTS,
    InjectionPoint,
    is_urlish_point,
    points_from_context,
    send_probe,
)
from wraith.models import Confidence, Finding, Severity

MARKER_HOST = "wraith-ssrf-probe.invalid"
PAYLOADS = (f"http://{MARKER_HOST}/", f"https://{MARKER_HOST}/")
# Signatures of a server-side HTTP client failing to reach the marker host.
_FETCH_ERROR = re.compile(
    r"(failed to (?:connect|open)|could not resolve|name or service not known|getaddrinfo|"
    r"nodename nor servname|no such host|connection (?:refused|timed out)|curl error|"
    r"unknownhost|name resolution|temporary failure in name resolution|"
    r"errno (?:-?\d+)|socket|urlopen error|httpconnection)",
    re.IGNORECASE,
)
REFERENCES = (
    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    "https://cwe.mitre.org/data/definitions/918.html",
)


class SsrfCheck(BaseCheck):
    name = "ssrf"
    severity_hint = Severity.HIGH
    description = "Server-side request forgery in URL-like parameters (in-band, conservative)"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        points = [p for p in points_from_context(ctx) if is_urlish_point(p)]
        for point in points[:MAX_POINTS]:
            finding = await _probe(http, point)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    try:
        baseline = await send_probe(http, point, point.baseline() or "test")
    except HTTPClientError:
        return None
    baseline_has_error = bool(_FETCH_ERROR.search(baseline.text))

    for payload in PAYLOADS:
        try:
            response = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        if MARKER_HOST not in response.text:
            continue
        error = _FETCH_ERROR.search(response.text)
        # Require a fetch-error referencing our host that the baseline did not already show.
        if error is not None and not baseline_has_error:
            return _finding(point, payload, error.group(0), response)
    return None


def _finding(point: InjectionPoint, payload: str, matched: str, response: Response) -> Finding:
    return Finding(
        check=SsrfCheck.name,
        title=f"Possible SSRF in parameter {point.param!r}",
        url=point.action,
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description=(
            f"Setting the {point.source} parameter {point.param!r} ({point.method}) to "
            f"{payload} made the server attempt an outbound request to the unresolvable host "
            f"{MARKER_HOST!r}, revealed by a fetch error in the response ({matched!r}) that the "
            "baseline did not contain. The server fetches URLs from this parameter, so an "
            "attacker could target internal services or cloud metadata endpoints. Confirm the "
            "reachable impact with an out-of-band collaborator before exploiting."
        ),
        remediation=(
            "Do not fetch user-supplied URLs directly. Allowlist permitted hosts/schemes, resolve "
            "and validate the address (block private, loopback, link-local, and metadata ranges), "
            "disable unneeded protocols, and do not follow redirects into blocked ranges."
        ),
        evidence=(response.exchange.to_evidence(matched),),
        references=REFERENCES,
    )
