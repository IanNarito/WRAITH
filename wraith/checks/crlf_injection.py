"""CRLF / HTTP response header injection detection (aggressive).

Injects a CR-LF sequence followed by a harmless marker header into a parameter and checks
whether the server emits that marker as a real response header. If it does, the parameter is
written into the response headers unsanitized (HTTP response splitting / header injection).
The injected header is inert (a custom ``X-Wraith`` marker); nothing else is changed.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import MAX_POINTS, InjectionPoint, points_from_context, send_probe
from wraith.models import Confidence, Finding, Severity

MARKER_HEADER = "x-wraith-crlf"
REFERENCES = (
    "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
    "https://cwe.mitre.org/data/definitions/113.html",
)


class CrlfInjectionCheck(BaseCheck):
    name = "crlf_injection"
    severity_hint = Severity.MEDIUM
    description = "CRLF injection into HTTP response headers (response splitting)"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for point in points_from_context(ctx)[:MAX_POINTS]:
            finding = await _probe(http, point)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    token = secrets.token_hex(4)
    base = point.baseline()
    # CR-LF variants; send_probe percent-encodes these, and a vulnerable server decodes and
    # re-emits them as header bytes.
    payloads = (
        f"{base}\r\n{MARKER_HEADER}: {token}",
        f"{base}\r\n\r\n{MARKER_HEADER}: {token}",
        f"{base}\n{MARKER_HEADER}: {token}",
    )
    for payload in payloads:
        try:
            response = await send_probe(http, point, payload, follow_redirects=False)
        except HTTPClientError:
            continue
        if response.headers.get(MARKER_HEADER) == token:
            return _finding(point, payload, token, response)
    return None


def _finding(point: InjectionPoint, payload: str, token: str, response: Response) -> Finding:
    return Finding(
        check=CrlfInjectionCheck.name,
        title=f"CRLF header injection in parameter {point.param!r}",
        url=point.action,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) is written into the "
            f"HTTP response headers without stripping CR/LF: an injected value produced the "
            f"response header {MARKER_HEADER}: {token}. This allows HTTP response splitting - "
            "setting arbitrary headers or cookies, and in some stacks poisoning caches or "
            "injecting a response body."
        ),
        remediation=(
            "Strip or reject CR (\\r) and LF (\\n) in any value placed into a response header, "
            "and prefer framework APIs that encode header values. Do not build headers by string "
            "concatenation of user input."
        ),
        evidence=(response.exchange.to_evidence(f"{MARKER_HEADER}: {token}", include_body=False),),
        references=REFERENCES,
    )
