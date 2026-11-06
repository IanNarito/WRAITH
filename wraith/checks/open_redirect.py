"""Open redirect detection (aggressive).

For parameters that carry a URL, inject a marker destination on a reserved domain
(``wraith-redirect.example``, which cannot route anywhere real) and check whether the server
redirects to it via a Location header, a meta refresh, or a JavaScript location assignment.
The redirect is never followed, so nothing is actually navigated to. Non-destructive.
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

MARKER_HOST = "wraith-redirect.example"
PAYLOADS = (f"https://{MARKER_HOST}/", f"//{MARKER_HOST}/")
_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)""", re.IGNORECASE
)
_JS_LOCATION = re.compile(
    r"""(?:location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\()\s*["']([^"']+)""",
    re.IGNORECASE,
)
REFERENCES = (
    "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
    "https://cwe.mitre.org/data/definitions/601.html",
)


class OpenRedirectCheck(BaseCheck):
    name = "open_redirect"
    severity_hint = Severity.MEDIUM
    description = "Unvalidated redirects to attacker-controlled URLs"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        points = [p for p in points_from_context(ctx) if is_urlish_point(p)]
        for point in points[:MAX_POINTS]:
            finding = await _probe(http, point)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    for payload in PAYLOADS:
        try:
            response = await send_probe(http, point, payload, follow_redirects=False)
        except HTTPClientError:
            continue
        vector = _redirects_to_marker(response)
        if vector is not None:
            where, dest = vector
            return _finding(point, payload, where, dest, response)
    return None


def _redirects_to_marker(response: Response) -> tuple[str, str] | None:
    location = response.headers.get("location", "")
    if response.status_code in (301, 302, 303, 307, 308) and _points_at_marker(location):
        return "Location header", location
    if 200 <= response.status_code < 300:
        for label, pattern in (("meta refresh", _META_REFRESH), ("JavaScript", _JS_LOCATION)):
            for dest in pattern.findall(response.text):
                if _points_at_marker(dest):
                    return label, dest
    return None


def _points_at_marker(value: str) -> bool:
    v = value.strip().lower()
    if v.startswith(("http://", "https://")):
        return v.split("://", 1)[1].split("/", 1)[0] == MARKER_HOST
    if v.startswith("//"):
        return v[2:].split("/", 1)[0] == MARKER_HOST
    return False


def _finding(
    point: InjectionPoint, payload: str, where: str, dest: str, response: Response
) -> Finding:
    return Finding(
        check=OpenRedirectCheck.name,
        title=f"Open redirect in parameter {point.param!r}",
        url=point.action,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) controls the redirect "
            f"destination: a request with {point.param}={payload} redirected to the external host "
            f"{MARKER_HOST!r} via the {where} ({dest}). Attackers can use this to send victims to "
            "phishing or malware pages under the trust of this domain, and to help bypass some "
            "OAuth/SSO protections."
        ),
        remediation=(
            "Do not put user input directly into a redirect target. Redirect only to an allowlist "
            "of known paths/hosts, or map an opaque identifier to a server-side URL. If external "
            "redirects are required, show an interstitial confirmation page."
        ),
        evidence=(response.exchange.to_evidence(dest, include_body=False),),
        references=REFERENCES,
    )
