"""Server-side template injection (SSTI) detection (aggressive, non-destructive).

Injects a small arithmetic expression wrapped in the delimiters of the common template engines
(Jinja2/Twig ``{{ }}``, Java EL/Spring ``${ }``, Ruby/JSF ``#{ }``, ERB/EJS ``<%= %>``,
Thymeleaf ``*{ }``, Razor ``@( )``) and reports only when the *product* is rendered back while
the literal expression is NOT. That differential proves the server evaluated the expression
(plain reflection would echo the delimiters and the ``a*b`` text verbatim), with near-zero false
positives. The probe only multiplies two random numbers; it never calls template built-ins,
reads objects, or executes code, so it is safe. SSTI commonly escalates to RCE - confirm the
engine and impact manually.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import MAX_POINTS, InjectionPoint, points_from_context, send_probe
from wraith.models import Confidence, Finding, Severity

REFERENCES = (
    "https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
    "https://portswigger.net/web-security/server-side-template-injection",
    "https://cwe.mitre.org/data/definitions/1336.html",
)

# Delimiter templates, keyed by the engine family they signal. {e} is the ``a*b`` expression.
_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("Jinja2/Twig/Nunjucks", "{{{{{e}}}}}"),  # -> {{a*b}}
    ("Java EL / Spring / Mako", "${{{e}}}"),  # -> ${a*b}
    ("Ruby ERB / JSF / Freemarker", "#{{{e}}}"),  # -> #{a*b}
    ("Smarty / double", "${{{{{e}}}}}"),  # -> ${{a*b}}
    ("ERB / EJS", "<%= {e} %>"),
    ("Thymeleaf", "*{{{e}}}"),  # -> *{a*b}
    ("Razor", "@({e})"),
)


class SstiCheck(BaseCheck):
    name = "ssti"
    severity_hint = Severity.HIGH
    description = "Server-side template injection in query and form parameters"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for point in points_from_context(ctx)[:MAX_POINTS]:
            finding = await _probe(http, point)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    # Two random 3-digit factors give an uncommon 5-6 digit product unlikely to occur by chance.
    a = secrets.randbelow(900) + 100
    b = secrets.randbelow(900) + 100
    expr = f"{a}*{b}"
    product = str(a * b)
    base_value = point.baseline()
    try:
        baseline = await send_probe(http, point, base_value or "1")
    except HTTPClientError:
        return None
    if product in baseline.text:  # the number already appears; the differential would be unreliable
        return None
    for engine, template in _TEMPLATES:
        payload = (base_value or "") + template.format(e=expr)
        try:
            response = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        # Evaluated: the product is present and the literal "a*b" expression is gone.
        if product in response.text and expr not in response.text:
            return _finding(point, engine, expr, product, response)
    return None


def _finding(
    point: InjectionPoint, engine: str, expr: str, product: str, response: Response
) -> Finding:
    return Finding(
        check=SstiCheck.name,
        title=f"Server-side template injection in parameter {point.param!r}",
        url=point.action,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) is rendered by a "
            f"server-side template engine: the expression {expr!r} was evaluated to {product!r} in "
            f"the response (delimiters consistent with {engine}), while the literal expression was "
            "not reflected. Template injection typically escalates to reading server-side data and "
            "remote code execution via engine built-ins. Confirm the exact engine and its sandbox."
        ),
        remediation=(
            "Never concatenate user input into a template. Pass user data only as template "
            "variables/parameters, render with a sandboxed/logic-less engine where possible, and "
            "avoid engine features that expose object or OS access to templates."
        ),
        evidence=(response.exchange.to_evidence(product),),
        references=REFERENCES,
    )
