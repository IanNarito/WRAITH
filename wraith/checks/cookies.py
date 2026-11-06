"""Cookie security flags on session cookies: Secure, HttpOnly, SameSite."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from functools import lru_cache

from wraith import data
from wraith.checks.base import BaseCheck
from wraith.context import Page, ScanContext
from wraith.http_client import HTTPClient
from wraith.models import Confidence, Finding, Severity

_RANDOM_VALUE = re.compile(r"^[A-Za-z0-9+/=_.%-]{16,}$")
REFERENCES = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
    "https://owasp.org/www-community/controls/SecureCookieAttribute",
)


@dataclass(frozen=True)
class SetCookie:
    raw: str
    name: str
    value: str
    attributes: dict[str, str] = field(default_factory=dict)  # lowercase name -> value

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attributes

    @property
    def samesite(self) -> str | None:
        value = self.attributes.get("samesite")
        return value.strip().lower() if value is not None else None

    @property
    def persistent(self) -> bool:
        return "expires" in self.attributes or "max-age" in self.attributes


def parse_set_cookie(raw: str) -> SetCookie | None:
    first, *rest = raw.split(";")
    name, sep, value = first.partition("=")
    if not sep or not name.strip():
        return None
    attributes: dict[str, str] = {}
    for part in rest:
        key, _, val = part.partition("=")
        if key.strip():
            attributes[key.strip().lower()] = val.strip()
    return SetCookie(raw=raw, name=name.strip(), value=value.strip(), attributes=attributes)


@lru_cache(maxsize=1)
def _patterns() -> tuple[tuple[re.Pattern[str], ...], tuple[re.Pattern[str], ...]]:
    include: list[re.Pattern[str]] = []
    exclude: list[re.Pattern[str]] = []
    for line in data.read_text("session_cookies.txt").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            exclude.append(re.compile(line[1:], re.IGNORECASE))
        else:
            include.append(re.compile(line, re.IGNORECASE))
    return tuple(include), tuple(exclude)


def session_confidence(cookie: SetCookie) -> Confidence | None:
    """CONFIRMED if the name is a known session name, PROBABLE if it merely looks like one."""
    include, exclude = _patterns()
    if any(p.search(cookie.name) for p in exclude):
        return None
    if any(p.search(cookie.name) for p in include):
        return Confidence.CONFIRMED
    if not cookie.persistent and _RANDOM_VALUE.match(cookie.value):
        return Confidence.PROBABLE
    return None


class CookiesCheck(BaseCheck):
    name = "cookies"
    severity_hint = Severity.MEDIUM
    description = "Session cookies missing Secure, HttpOnly, or SameSite"

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for finding in evaluate(ctx.pages):
            yield finding


def evaluate(pages: tuple[Page, ...] | list[Page]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for page in pages:
        for raw in page.header_values("set-cookie"):
            cookie = parse_set_cookie(raw)
            if cookie is None or cookie.name in seen:
                continue
            confidence = session_confidence(cookie)
            if confidence is None or _is_deletion(cookie):
                continue
            seen.add(cookie.name)
            findings.extend(_issues(page, cookie, confidence))
    return findings


def _issues(page: Page, cookie: SetCookie, confidence: Confidence) -> list[Finding]:
    out: list[Finding] = []
    label = "Session cookie" if confidence is Confidence.CONFIRMED else "Likely session cookie"

    def add(title: str, severity: Severity, description: str, remediation: str) -> None:
        out.append(
            Finding(
                check=CookiesCheck.name,
                title=f"{label} {cookie.name!r} {title}",
                url=page.url,
                severity=severity,
                confidence=confidence,
                description=description,
                remediation=remediation,
                evidence=(page.exchange.to_evidence(cookie.raw, include_body=False),),
                references=REFERENCES,
            )
        )

    if page.is_https and not cookie.secure:
        add(
            "missing Secure flag",
            Severity.MEDIUM,
            "The cookie is set over HTTPS without the Secure attribute, so the browser will "
            "also send it over plain HTTP, where a network attacker can capture it and hijack "
            "the session.",
            "Add the Secure attribute (or use the __Host- name prefix, which requires it).",
        )
    if not cookie.httponly:
        add(
            "missing HttpOnly flag",
            Severity.LOW,
            "The cookie lacks HttpOnly, so any script running in the page (including injected "
            "script from an XSS bug) can read it and steal the session.",
            "Add the HttpOnly attribute unless client-side script genuinely needs the value.",
        )
    samesite = cookie.samesite
    if samesite == "none":
        add(
            "set with SameSite=None",
            Severity.LOW,
            "SameSite=None tells the browser to send the cookie on cross-site requests, which "
            "removes the browser's built-in protection against cross-site request forgery.",
            "Use SameSite=Lax (or Strict) unless cross-site use is required, and keep strong "
            "CSRF tokens either way.",
        )
    elif samesite is None:
        add(
            "missing SameSite attribute",
            Severity.INFO,
            "No SameSite attribute is set. Most modern browsers then default to Lax, but some "
            "older browsers send the cookie on all cross-site requests.",
            "Set SameSite=Lax or SameSite=Strict explicitly.",
        )
    return out


def _is_deletion(cookie: SetCookie) -> bool:
    """A Set-Cookie that clears the cookie carries no session to protect."""
    if cookie.attributes.get("max-age", "").strip() in ("0", "-1"):
        return True
    return cookie.value in ("", '""', "deleted")
