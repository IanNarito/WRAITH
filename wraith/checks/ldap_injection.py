"""LDAP injection detection (aggressive, conservative).

Error-based only: sends values that break LDAP filter syntax (an unbalanced parenthesis, a lone
wildcard, a null byte) and reports when the response newly shows an LDAP error signature
(``data/ldap_errors.txt``) that the baseline did not contain. That proves the parameter is
concatenated into an LDAP filter. The probes only unbalance the filter; they do not attempt an
authentication bypass or data extraction, so they change no state. Findings are PROBABLE - a
successful filter injection may be exploitable for authentication bypass or data disclosure;
confirm manually.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from functools import lru_cache

from wraith import data
from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import MAX_POINTS, InjectionPoint, points_from_context, send_probe
from wraith.models import Confidence, Finding, Severity

REFERENCES = (
    "https://owasp.org/www-community/attacks/LDAP_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/90.html",
)
# Values that break LDAP filter syntax without forming a valid bypass filter.
_PROBES = (")", "(", "*)(", "*))%00", ")(cn=*", "*|(", r"\\")


@dataclass(frozen=True)
class LdapErrorSignature:
    pattern: re.Pattern[str]


@lru_cache(maxsize=1)
def load_error_signatures() -> tuple[LdapErrorSignature, ...]:
    out: list[LdapErrorSignature] = []
    for line in data.read_text("ldap_errors.txt").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        out.append(LdapErrorSignature(re.compile(line.strip(), re.IGNORECASE)))
    return tuple(out)


def first_ldap_error(text: str) -> re.Match[str] | None:
    for sig in load_error_signatures():
        match = sig.pattern.search(text)
        if match is not None:
            return match
    return None


class LdapInjectionCheck(BaseCheck):
    name = "ldap_injection"
    severity_hint = Severity.HIGH
    description = "LDAP injection in query and form parameters (error-based)"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for point in points_from_context(ctx)[:MAX_POINTS]:
            finding = await _probe(http, point)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    base_value = point.baseline()
    try:
        baseline = await send_probe(http, point, base_value or "a")
    except HTTPClientError:
        return None
    if first_ldap_error(baseline.text) is not None:
        return None  # the page already shows LDAP errors; the differential would be unreliable
    for probe in _PROBES:
        payload = f"{base_value}{probe}" if base_value else probe
        try:
            response = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        match = first_ldap_error(response.text)
        if match is not None:
            return _finding(point, payload, match.group(0), response)
    return None


def _finding(point: InjectionPoint, payload: str, matched: str, response: Response) -> Finding:
    return Finding(
        check=LdapInjectionCheck.name,
        title=f"LDAP injection in parameter {point.param!r}",
        url=point.action,
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) is built into an LDAP "
            f"filter without escaping: the payload {payload!r} triggered an LDAP error "
            f"({matched!r}) that the baseline response did not contain. Attackers can tamper with "
            "the filter to bypass authentication or read directory entries they should not see."
        ),
        remediation=(
            "Escape all user input used in LDAP filters and DNs per RFC 4515 (or use the LDAP "
            "library's parameterized filter API), validate against a strict allowlist, and bind "
            "with least-privilege directory accounts."
        ),
        evidence=(response.exchange.to_evidence(matched),),
        references=REFERENCES,
    )
