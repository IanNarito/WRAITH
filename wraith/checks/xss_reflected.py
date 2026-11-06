"""Reflected XSS detection (aggressive).

Method, per injection point:
  1. Send a unique random marker and check whether it is reflected in an HTML response.
  2. If it is, send the marker wrapped in a harmless, non-executing custom tag with a boundary
     (``">`` and ``'>``). If the angle brackets come back unencoded around the marker, the input
     is reflected into HTML markup without output encoding - i.e. reflected XSS is possible.

The probe never injects a working script (no <script>, no event handler that runs): observing
that ``<`` and ``>`` survive unencoded is enough to demonstrate the flaw, and keeps the test
non-executing. Findings are PROBABLE: reflection into markup is shown, execution is not.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import HTML_TYPES, ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import MAX_POINTS, InjectionPoint, points_from_context, send_probe
from wraith.models import Confidence, Finding, Severity

logger = logging.getLogger("wraith.checks.xss")
REFERENCES = (
    "https://owasp.org/www-community/attacks/xss/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
)


class ReflectedXssCheck(BaseCheck):
    name = "xss_reflected"
    severity_hint = Severity.HIGH
    description = "Reflected cross-site scripting in query and form parameters"
    enabled_by_default = True
    requires_aggressive = True  # substitutes payloads into parameters; POSTs forms

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for point in points_from_context(ctx)[:MAX_POINTS]:
            finding = await _probe_point(http, point)
            if finding is not None:
                yield finding


async def _probe_point(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    token = secrets.token_hex(4)
    marker = f"wrx{token}"
    try:
        reflected = await send_probe(http, point, marker)
    except HTTPClientError:
        return None
    if not _is_html(reflected) or marker not in reflected.text:
        return None

    tag = f"wrz{token}"
    payload = f'{marker}"><{tag}>'
    try:
        response = await send_probe(http, point, payload)
    except HTTPClientError:
        return None
    needle = f"<{tag}>"
    if not _is_html(response) or needle not in response.text:
        return None

    return Finding(
        check=ReflectedXssCheck.name,
        title=f"Reflected XSS in parameter {point.param!r}",
        url=point.action,
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) is reflected into the "
            f"HTML response without output encoding: the injected marker {needle} came back with "
            "its angle brackets intact, so an attacker-controlled value is parsed as HTML. A "
            "crafted value could inject script that runs in a victim's browser. The probe used a "
            "harmless non-executing tag; confirm manually with a scripting payload in context."
        ),
        remediation=(
            "Contextually output-encode all user input when placing it in HTML (HTML-entity "
            "encode <, >, &, \", '), prefer safe templating/auto-escaping, and add a strict "
            "Content-Security-Policy as defense in depth."
        ),
        evidence=(response.exchange.to_evidence(needle),),
        references=REFERENCES,
    )


def _is_html(response: Response) -> bool:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    return content_type in HTML_TYPES or content_type == ""
