"""Security header analysis of the base response."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from bs4 import BeautifulSoup

from wraith.checks.base import BaseCheck
from wraith.context import Page, ScanContext
from wraith.http_client import HTTPClient
from wraith.models import Confidence, Finding, Severity

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
_MAX_AGE_RE = re.compile(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)
_HASH_OR_NONCE = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
_BROAD_SOURCES = ("*", "http:", "https:", "data:")
_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


class SecurityHeadersCheck(BaseCheck):
    name = "security_headers"
    severity_hint = Severity.MEDIUM
    description = "Missing or weak HTTP security headers on the base response"

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for finding in evaluate(ctx.base):
            yield finding


def evaluate(page: Page) -> list[Finding]:
    """Pure analysis of one response; no requests needed."""
    findings: list[Finding] = []
    # An error page may not carry the headers the real application sets.
    confidence = Confidence.CONFIRMED if page.status < 400 else Confidence.PROBABLE

    def add(
        title: str,
        severity: Severity,
        description: str,
        remediation: str,
        *,
        matched: str | None = None,
        header: str,
        include_body: bool = False,
    ) -> None:
        findings.append(
            Finding(
                check=SecurityHeadersCheck.name,
                title=title,
                url=page.url,
                severity=severity,
                confidence=confidence,
                description=description,
                remediation=remediation,
                evidence=(page.exchange.to_evidence(matched, include_body=include_body),),
                references=(MDN + header, OWASP_HEADERS),
            )
        )

    header_policies = _policies(page.header_values("content-security-policy"))

    # Content-Security-Policy (only meaningful for documents)
    if page.is_html:
        meta_policies = _policies(_meta_csp(page.body))
        policies = header_policies or meta_policies
        if not policies:
            report_only = page.header("content-security-policy-report-only")
            note = (
                " A Content-Security-Policy-Report-Only header is present, but it only reports "
                "violations and blocks nothing."
                if report_only
                else ""
            )
            add(
                "Missing Content-Security-Policy",
                Severity.MEDIUM,
                "The page sets no Content-Security-Policy, so the browser applies no restriction "
                "on where scripts may load from or whether inline script may run. CSP is a key "
                "defense-in-depth control against cross-site scripting." + note,
                "Send a Content-Security-Policy header. Start from a strict policy such as "
                "\"default-src 'self'; script-src 'self'; object-src 'none'; "
                "frame-ancestors 'self'\" and use nonces or hashes for required inline scripts.",
                matched=report_only,
                header="Content-Security-Policy",
            )
        else:
            weaknesses = [csp_weaknesses(p) for p in policies]
            # Multiple policies are all enforced; one strong policy is enough.
            if all(weaknesses):
                source = "header" if header_policies else "<meta> tag"
                add(
                    "Weak Content-Security-Policy",
                    Severity.LOW,
                    f"The Content-Security-Policy ({source}) does not meaningfully restrict "
                    "script execution: " + "; ".join(weaknesses[0]) + ".",
                    "Remove 'unsafe-inline' and 'unsafe-eval' from script sources, replace "
                    "wildcard or scheme-only sources with explicit origins, and use nonces, "
                    "hashes, or 'strict-dynamic' for inline scripts.",
                    matched=policies[0],
                    header="Content-Security-Policy",
                    include_body=not header_policies,
                )

    # Strict-Transport-Security (ignored by browsers over plain HTTP)
    if page.is_https:
        hsts = page.header("strict-transport-security")
        if hsts is None:
            add(
                "Missing Strict-Transport-Security",
                Severity.MEDIUM,
                "The HTTPS response sets no Strict-Transport-Security header, so browsers will "
                "still try plain HTTP on later visits and users can be downgraded or have "
                "cookies intercepted by a network attacker.",
                'Send "Strict-Transport-Security: max-age=31536000; includeSubDomains" on all '
                "HTTPS responses (add preload once every subdomain supports HTTPS).",
                header="Strict-Transport-Security",
            )
        else:
            match = _MAX_AGE_RE.search(hsts)
            if match is None:
                add(
                    "Invalid Strict-Transport-Security",
                    Severity.LOW,
                    "The Strict-Transport-Security header has no valid max-age directive, so "
                    "browsers ignore it.",
                    'Use "Strict-Transport-Security: max-age=31536000; includeSubDomains".',
                    matched=hsts,
                    header="Strict-Transport-Security",
                )
            elif int(match.group(1)) < HSTS_MIN_MAX_AGE:
                max_age = int(match.group(1))
                effect = (
                    "max-age=0 tells browsers to forget the policy, disabling HSTS"
                    if max_age == 0
                    else f"max-age={max_age} ({max_age // 86400} days) is below the "
                    "recommended minimum of 180 days"
                )
                add(
                    "Weak Strict-Transport-Security",
                    Severity.LOW,
                    f"The Strict-Transport-Security policy is too short-lived: {effect}.",
                    "Set max-age to at least 15552000 (180 days); 31536000 (1 year) is typical.",
                    matched=hsts,
                    header="Strict-Transport-Security",
                )

    # Clickjacking: X-Frame-Options or CSP frame-ancestors (header only; ignored in <meta>)
    if page.is_html and not any("frame-ancestors" in parse_csp(p) for p in header_policies):
        xfo = page.header("x-frame-options")
        if xfo is None:
            add(
                "Missing clickjacking protection",
                Severity.MEDIUM,
                "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive "
                "is set, so any site can embed this page in a frame and trick users into "
                "clicking on it (clickjacking).",
                "Send \"Content-Security-Policy: frame-ancestors 'self'\" (preferred) and/or "
                '"X-Frame-Options: DENY" or "SAMEORIGIN".',
                header="X-Frame-Options",
            )
        elif xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
            add(
                "Invalid X-Frame-Options",
                Severity.LOW,
                f"X-Frame-Options is set to {xfo!r}. Only DENY and SAMEORIGIN are honored by "
                "modern browsers (ALLOW-FROM is ignored), so the page can still be framed.",
                'Use "X-Frame-Options: DENY" or "SAMEORIGIN", or CSP frame-ancestors.',
                matched=xfo,
                header="X-Frame-Options",
            )

    # X-Content-Type-Options
    xcto = page.header("x-content-type-options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        add(
            "Missing X-Content-Type-Options" if xcto is None else "Invalid X-Content-Type-Options",
            Severity.LOW,
            "X-Content-Type-Options: nosniff is not set, so browsers may MIME-sniff responses "
            "and render user-controlled content as HTML or script.",
            'Send "X-Content-Type-Options: nosniff" on all responses.',
            matched=xcto,
            header="X-Content-Type-Options",
        )

    # Referrer-Policy
    referrer = page.header("referrer-policy")
    if referrer is None:
        if page.is_html:
            add(
                "Missing Referrer-Policy",
                Severity.INFO,
                "No Referrer-Policy is set. Modern browsers default to "
                "strict-origin-when-cross-origin, but older ones send full URLs (including any "
                "tokens in query strings) to third parties.",
                'Send "Referrer-Policy: strict-origin-when-cross-origin" or stricter.',
                header="Referrer-Policy",
            )
    else:
        tokens = [t.strip().lower() for t in referrer.split(",")]
        known = [t for t in tokens if t in _REFERRER_POLICIES]
        effective = known[-1] if known else None  # browsers use the last value they understand
        if effective in ("unsafe-url", "no-referrer-when-downgrade"):
            add(
                "Weak Referrer-Policy",
                Severity.LOW,
                f"Referrer-Policy {effective!r} sends the full URL, including path and query "
                "string, to other origins.",
                'Use "Referrer-Policy: strict-origin-when-cross-origin" or stricter.',
                matched=referrer,
                header="Referrer-Policy",
            )

    # Permissions-Policy
    if (
        page.is_html
        and page.header("permissions-policy") is None
        and page.header("feature-policy") is None
    ):
        add(
            "Missing Permissions-Policy",
            Severity.INFO,
            "No Permissions-Policy is set, so the page and any frames it embeds can request "
            "powerful browser features (camera, microphone, geolocation) without restriction.",
            "Send a Permissions-Policy that disables unused features, e.g. "
            '"Permissions-Policy: camera=(), microphone=(), geolocation=()".',
            header="Permissions-Policy",
        )

    return findings


def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            # Per spec, the first occurrence of a directive wins.
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def csp_weaknesses(policy: str) -> list[str]:
    directives = parse_csp(policy)
    script = directives.get("script-src", directives.get("default-src"))
    if script is None:
        return ["no script-src or default-src directive, so scripts may load from anywhere"]
    issues: list[str] = []
    has_nonce_or_hash = any(t.startswith(_HASH_OR_NONCE) for t in script)
    if "'unsafe-inline'" in script and not has_nonce_or_hash:
        issues.append("script sources allow 'unsafe-inline'")
    if "'unsafe-eval'" in script:
        issues.append("script sources allow 'unsafe-eval'")
    if "'strict-dynamic'" not in script:
        broad = [t for t in script if t in _BROAD_SOURCES]
        if broad:
            issues.append(f"script sources include overly broad source(s) {' '.join(broad)}")
    return issues


def _policies(values: list[str]) -> list[str]:
    """Split header values into individual policies (comma-separated = multiple policies)."""
    return [p.strip() for v in values for p in v.split(",") if p.strip()]


def _meta_csp(body: str) -> list[str]:
    if "content-security-policy" not in body.lower():
        return []
    soup = BeautifulSoup(body, "lxml")
    values: list[str] = []
    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv", "")).strip().lower() == "content-security-policy":
            content = meta.get("content")
            if content:
                values.append(str(content))
    return values
