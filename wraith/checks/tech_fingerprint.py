"""Technology fingerprinting from headers, cookies, generator tags, scripts, and bodies."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import yaml

from wraith import data
from wraith.checks.base import BaseCheck
from wraith.context import Page, ScanContext
from wraith.cve import CveCorrelator, CveMatch
from wraith.http_client import HTTPClient
from wraith.models import Confidence, Evidence, Finding, Severity

MAX_CVES_PER_PRODUCT = 15

DEFAULT_HIDE_VERSION = (
    "Configure the component not to advertise its version in headers, meta tags, or file names."
)


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    headers: tuple[tuple[str, re.Pattern[str]], ...]
    cookies: re.Pattern[str] | None
    generator: re.Pattern[str] | None
    scripts: re.Pattern[str] | None
    body: re.Pattern[str] | None
    hide_version: str
    cpe: str | None  # NVD CPE base (cpe:2.3:a:vendor:product) for precise CVE correlation


@dataclass(frozen=True)
class Detection:
    name: str
    category: str
    version: str | None
    source: str
    evidence: Evidence
    hide_version: str
    cpe: str | None


def _compile(value: Any) -> re.Pattern[str] | None:
    return re.compile(str(value), re.IGNORECASE) if value else None


@lru_cache(maxsize=1)
def load_signatures() -> tuple[Signature, ...]:
    raw = yaml.safe_load(data.read_text("tech_signatures.yaml"))
    signatures: list[Signature] = []
    for item in raw["technologies"]:
        headers = tuple(
            (str(name).lower(), re.compile(str(rx), re.IGNORECASE))
            for name, rx in (item.get("headers") or {}).items()
        )
        signatures.append(
            Signature(
                name=item["name"],
                category=item.get("category", "Technology"),
                headers=headers,
                cookies=_compile(item.get("cookies")),
                generator=_compile(item.get("generator")),
                scripts=_compile(item.get("scripts")),
                body=_compile(item.get("body")),
                hide_version=item.get("hide_version", DEFAULT_HIDE_VERSION),
                cpe=item.get("cpe"),
            )
        )
    return tuple(signatures)


def _version(match: re.Match[str]) -> str | None:
    return next((g for g in match.groups() if g), None)


def detect(ctx: ScanContext) -> list[Detection]:
    base = ctx.base
    cookie_names = [h.value for h in ctx.tech_hints if h.source == "cookie"]
    generators = [h.value for h in ctx.tech_hints if h.source == "meta:generator"]
    html_pages = [p for p in ctx.pages if p.is_html]
    detections: dict[str, Detection] = {}

    def record(sig: Signature, match: re.Match[str], source: str, evidence: Evidence) -> None:
        found = Detection(
            sig.name, sig.category, _version(match), source, evidence, sig.hide_version, sig.cpe
        )
        current = detections.get(sig.name)
        if current is None or (current.version is None and found.version is not None):
            detections[sig.name] = found

    for sig in load_signatures():
        for header, pattern in sig.headers:
            for value in base.header_values(header):
                if m := pattern.search(value):
                    record(
                        sig,
                        m,
                        f"{header} header",
                        base.exchange.to_evidence(value, include_body=False),
                    )
        if sig.cookies:
            for name in cookie_names:
                if m := sig.cookies.search(name):
                    record(
                        sig, m, "cookie name", base.exchange.to_evidence(name, include_body=False)
                    )
        if sig.generator:
            for value in generators:
                if m := sig.generator.search(value):
                    page = _page_containing(html_pages, value) or base
                    record(sig, m, "generator meta tag", page.exchange.to_evidence(value))
        if sig.scripts:
            for src in ctx.script_srcs:
                if m := sig.scripts.search(urlsplit(src).path):
                    filename = urlsplit(src).path.rsplit("/", 1)[-1]
                    page = _page_containing(html_pages, filename) or base
                    record(sig, m, "script URL", page.exchange.to_evidence(filename))
        if sig.body:
            for page in html_pages:
                if m := sig.body.search(page.body):
                    record(sig, m, "page content", page.exchange.to_evidence(m.group(0)))
                    break
    return sorted(detections.values(), key=lambda d: (d.category, d.name))


def _page_containing(pages: list[Page], needle: str) -> Page | None:
    return next((p for p in pages if needle in p.body), None)


class TechFingerprintCheck(BaseCheck):
    name = "tech_fingerprint"
    severity_hint = Severity.INFO
    description = "Detect server, framework, CMS, and JS libraries; note exposed versions"

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        detections = detect(ctx)
        if not detections:
            return
        stack = "; ".join(
            f"{d.name}{' ' + d.version if d.version else ''} ({d.category}, via {d.source})"
            for d in detections
        )
        yield Finding(
            check=self.name,
            title="Technology stack detected",
            url=ctx.base_url,
            severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL,
            description=f"Identified: {stack}.",
            remediation="No action required; use this to focus manual testing.",
            evidence=tuple(d.evidence for d in detections),
        )
        for d in detections:
            if d.version is None:
                continue
            yield _version_finding(self.name, ctx.base_url, d)
            if ctx.cve is not None:
                async for finding in _cve_findings(self.name, ctx.base_url, d, ctx.cve):
                    yield finding


def _version_finding(check: str, url: str, d: Detection) -> Finding:
    return Finding(
        check=check,
        title=f"{d.name} {d.version} version disclosed",
        url=url,
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        description=(
            f"The {d.source} reveals {d.name} version {d.version}. Cross-check this version "
            "against CVE databases (e.g. NVD, the vendor's security advisories) for known "
            "vulnerabilities. Version disclosure also helps attackers pick exploits."
        ),
        remediation=f"Patch {d.name} to a supported release. {d.hide_version}",
        evidence=(d.evidence,),
        references=(
            f"https://nvd.nist.gov/vuln/search/results?query={d.name.replace(' ', '+')}"
            f"+{d.version}",
        ),
    )


async def _cve_findings(
    check: str, url: str, d: Detection, correlator: CveCorrelator
) -> AsyncIterator[Finding]:
    assert d.version is not None
    try:
        matches = await correlator.correlate(d.name, d.version, d.cpe)
    except Exception as exc:  # correlation is best-effort; never sink the check
        logging.getLogger("wraith.cve").warning("CVE correlation for %s failed: %s", d.name, exc)
        return
    if not matches:
        return
    top = matches[:MAX_CVES_PER_PRODUCT]
    highest = top[0].cvss_severity
    yield Finding(
        check=check,
        title=f"{d.name} {d.version} has {len(matches)} known CVE(s)",
        url=url,
        severity=highest,
        confidence=Confidence.PROBABLE,
        description=(
            f"NVD lists {len(matches)} CVE(s) affecting {d.name} {d.version} "
            f"(highest {_label(top[0])}). These are version-based matches: confirm each applies "
            f"to this build and configuration before acting. Top: {_summarize(top)}."
        ),
        remediation=(
            f"Review the listed CVEs, prioritize by CVSS and exploitability, and upgrade "
            f"{d.name} to a patched release."
        ),
        evidence=(d.evidence,),
        references=tuple(m.url for m in top),
        cvss=top[0].cvss_score,
    )


def _label(m: CveMatch) -> str:
    score = f"CVSS {m.cvss_score}" if m.cvss_score is not None else "unscored"
    return f"{m.cve_id} ({score})"


def _summarize(matches: list[CveMatch]) -> str:
    return ", ".join(_label(m) for m in matches[:5])
