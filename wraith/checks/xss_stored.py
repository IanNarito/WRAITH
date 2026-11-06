"""Stored (persistent) XSS detection (aggressive).

For each discovered form, submit a unique, non-executing marker into its text fields, then
re-fetch the form's page and a bounded set of other pages and look for the marker reflected
into HTML with its angle brackets unencoded. If it persists and is rendered as markup, stored
XSS is possible.

This check WRITES to the target: it submits a form once per form, which is a normal, benign
submission carrying a harmless marker (no working script, no bulk/repeat submissions). It runs
only under --aggressive. Findings are PROBABLE - persistence into markup is shown, execution is
not. The submitted marker may remain visible in the application; note this on real engagements.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import Form, ScanContext
from wraith.http_client import HTTPClient, HTTPClientError
from wraith.injection import _TEXTUAL_FIELD_TYPES
from wraith.models import Confidence, Finding, Severity

logger = logging.getLogger("wraith.checks.xss_stored")
MAX_FORMS = 20
MAX_REFETCH = 15
REFERENCES = (
    "https://owasp.org/www-community/attacks/xss/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
)


class StoredXssCheck(BaseCheck):
    name = "xss_stored"
    severity_hint = Severity.HIGH
    description = "Stored cross-site scripting via form submissions"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        forms = [f for f in ctx.forms if _text_fields(f)][:MAX_FORMS]
        if not forms:
            return
        # Pages to inspect for persistence: the forms' own pages first, then other fetched pages.
        inspect_urls = list(
            dict.fromkeys([*(f.page_url for f in forms), *(p.url for p in ctx.pages)])
        )

        for form in forms:
            token = secrets.token_hex(4)
            needle = f"<wsx{token}>"
            payload = f'wrs{token}"><wsx{token}>'
            data = {name: payload for name in _text_fields(form)}
            try:
                await http.request(form.method.upper(), form.action, data=data)
            except HTTPClientError:
                continue

            finding = await _find_persisted(http, inspect_urls[:MAX_REFETCH], form, needle)
            if finding is not None:
                yield finding


async def _find_persisted(
    http: HTTPClient, urls: list[str], form: Form, needle: str
) -> Finding | None:
    for url in urls:
        try:
            response = await http.get(url)
        except HTTPClientError:
            continue
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type and content_type not in ("text/html", "application/xhtml+xml"):
            continue
        if needle in response.text:
            return Finding(
                check=StoredXssCheck.name,
                title=f"Stored XSS via form at {form.action}",
                url=url,
                severity=Severity.HIGH,
                confidence=Confidence.PROBABLE,
                description=(
                    f"A value submitted to the form at {form.action} ({form.method}) was stored "
                    f"and later rendered on {url} with its angle brackets unencoded (marker "
                    f"{needle}). Stored input that becomes HTML lets an attacker persist script "
                    "that runs for every user who views the page. The probe used a harmless "
                    "non-executing tag; confirm manually with a scripting payload."
                ),
                remediation=(
                    "Output-encode stored data for the HTML context when rendering it, validate "
                    "input on the way in, and apply a strict Content-Security-Policy. Encoding at "
                    "output time (not only input) is essential, since the same data may render in "
                    "several contexts."
                ),
                evidence=(response.exchange.to_evidence(needle),),
                references=REFERENCES,
            )
    return None


def _text_fields(form: Form) -> list[str]:
    return [f.name for f in form.fields if f.type.lower() in _TEXTUAL_FIELD_TYPES and f.name]
