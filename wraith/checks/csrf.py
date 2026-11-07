"""Cross-site request forgery (CSRF) exposure on state-changing forms (passive).

Inspects the forms found during discovery - it sends no probes of its own, so it is safe and
runs without ``--aggressive``. A POST form (a state-changing request) is flagged when it carries
no recognizable anti-CSRF token field (``data/csrf_tokens.txt``) and no hidden field whose value
looks like a high-entropy token. Because token validation can also happen via a header or an
Origin check that passive inspection cannot see, findings are MEDIUM / PROBABLE: confirm by
replaying the form from a foreign origin without the token.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from functools import lru_cache

from wraith import data
from wraith.checks.base import BaseCheck
from wraith.context import Form, Page, ScanContext
from wraith.http_client import HTTPClient
from wraith.models import Confidence, Finding, Severity

REFERENCES = (
    "https://owasp.org/www-community/attacks/csrf",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/352.html",
)
_RANDOM_TOKEN = re.compile(r"^[A-Za-z0-9+/=_.-]{16,}$")


@lru_cache(maxsize=1)
def _token_patterns() -> tuple[re.Pattern[str], ...]:
    out: list[re.Pattern[str]] = []
    for line in data.read_text("csrf_tokens.txt").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        out.append(re.compile(line.strip(), re.IGNORECASE))
    return tuple(out)


def _looks_like_token_name(name: str) -> bool:
    return any(p.search(name) for p in _token_patterns())


def has_csrf_defense(form: Form) -> bool:
    """True if the form carries a field that plausibly is an anti-CSRF token."""
    for field in form.fields:
        if _looks_like_token_name(field.name):
            return True
        # A hidden field holding a long, random-looking value is very likely a token.
        if field.type.lower() == "hidden" and _RANDOM_TOKEN.match(field.value.strip()):
            return True
    return False


def _has_meaningful_fields(form: Form) -> bool:
    """A form worth protecting has at least one non-submit, non-hidden input to submit."""
    return any(f.type.lower() not in ("submit", "button", "image", "reset") for f in form.fields)


class CsrfCheck(BaseCheck):
    name = "csrf"
    severity_hint = Severity.MEDIUM
    description = "State-changing forms without an anti-CSRF token"

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        pages = {page.url: page for page in ctx.pages}
        seen: set[tuple[str, str]] = set()
        for form in ctx.forms:
            if form.method.upper() != "POST" or not _has_meaningful_fields(form):
                continue
            if has_csrf_defense(form):
                continue
            key = (form.page_url, form.action)
            if key in seen:
                continue
            seen.add(key)
            page = pages.get(form.page_url) or ctx.base
            yield _finding(form, page)


def _finding(form: Form, page: Page) -> Finding:
    fields = ", ".join(repr(f.name) for f in form.fields if f.name) or "(none)"
    return Finding(
        check=CsrfCheck.name,
        title="Form without anti-CSRF token",
        url=form.action,
        severity=Severity.MEDIUM,
        confidence=Confidence.PROBABLE,
        description=(
            f"The POST form on {form.page_url} submitting to {form.action} (fields: {fields}) has "
            "no hidden anti-CSRF token field and no field whose name matches a known token "
            "pattern. If the server relies only on the session cookie to authorize this request, "
            "an attacker page can forge it on a logged-in victim's behalf. Validation via a custom "
            "header or Origin check cannot be seen here - confirm by replaying the form cross-site."
        ),
        remediation=(
            "Protect every state-changing request with a per-session (or per-request) anti-CSRF "
            "token that the server validates, and/or verify the Origin/Referer header. Set session "
            "cookies with SameSite=Lax or Strict as defense in depth."
        ),
        evidence=(page.exchange.to_evidence(form.action, include_body=False),),
        references=REFERENCES,
    )
