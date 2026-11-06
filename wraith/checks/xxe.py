"""XML external entity (XXE) detection (aggressive, conservative and safe).

Sends an XML document whose DOCTYPE defines an INTERNAL entity expanding to a marker, and
reports if the marker's expanded value comes back in the response. That proves the endpoint
parses XML and resolves entities - the precondition for XXE - WITHOUT using an external entity,
so it never reads a file, makes the server fetch a URL, or triggers entity-expansion DoS.

Because only internal expansion is proven (not external-entity resolution), findings are MEDIUM
/ PROBABLE: confirm exploitability (file read, SSRF) manually.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.models import Confidence, Finding, Severity

MAX_ENDPOINTS = 15
REFERENCES = (
    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
)


class XxeCheck(BaseCheck):
    name = "xxe"
    severity_hint = Severity.MEDIUM
    description = "XML entity processing (possible XXE) on XML-accepting endpoints"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        # Endpoints plausibly backed by an XML parser: form actions and parameterized URLs.
        endpoints = list(
            dict.fromkeys([f.action for f in ctx.forms] + list(ctx.param_urls) + [ctx.base_url])
        )
        for url in endpoints[:MAX_ENDPOINTS]:
            finding = await _probe(http, url)
            if finding is not None:
                yield finding


def _payload(marker: str) -> str:
    # Internal entity only - no SYSTEM/PUBLIC external entity, no nested expansion.
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE wraith [<!ENTITY wr "{marker}">]>\n'
        "<wraith>&wr;</wraith>"
    )


async def _probe(http: HTTPClient, url: str) -> Finding | None:
    token = secrets.token_hex(5)
    marker = f"wraithxxe{token}"
    body = _payload(marker)
    try:
        response = await http.request(
            "POST", url, headers={"Content-Type": "application/xml"}, content=body
        )
    except HTTPClientError:
        return None
    # The expanded value (marker) present, while the literal entity "&wr;" is NOT echoed back,
    # means the parser resolved the entity rather than reflecting our raw body.
    if marker in response.text and "&wr;" not in response.text:
        return _finding(url, marker, response)
    return None


def _finding(url: str, marker: str, response: Response) -> Finding:
    return Finding(
        check=XxeCheck.name,
        title="XML entity expansion (possible XXE)",
        url=url,
        severity=Severity.MEDIUM,
        confidence=Confidence.PROBABLE,
        description=(
            f"The endpoint parsed a posted XML document and expanded an internal entity (the "
            f"marker {marker!r} was returned from an entity reference). This shows the XML parser "
            "resolves entities with a DOCTYPE allowed - the precondition for XML external entity "
            "(XXE) attacks, which can read local files or make server-side requests. Only internal "
            "expansion was tested here; confirm external-entity resolution manually."
        ),
        remediation=(
            "Disable DOCTYPE processing and external entities in the XML parser (e.g. set "
            "FEATURE_SECURE_PROCESSING, disallow-doctype-decl, or the language's equivalent). "
            "Prefer a parser configuration that rejects DTDs entirely."
        ),
        evidence=(response.exchange.to_evidence(marker),),
        references=REFERENCES,
    )
