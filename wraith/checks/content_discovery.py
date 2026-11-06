"""Content discovery (aggressive): probe a small wordlist of common non-linked paths.

GET-only and non-mutating. To avoid false positives on servers that return 200 for everything
(soft 404s), it first calibrates against two random non-existent paths and reports a path only
when its response differs from that "not found" fingerprint. A request budget plus the global
rate limiter bound the volume so this never floods the target.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urljoin

from wraith import data
from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.models import Confidence, Finding, Severity

logger = logging.getLogger("wraith.checks.content_discovery")
REQUEST_BUDGET = 300
MAX_FINDINGS = 60
LENGTH_TOLERANCE = 0.10
_SENSITIVE = ("admin", "backup", "config", "api", "phpmyadmin", "adminer", ".git", "debug", "setup")
REFERENCES = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
)


@lru_cache(maxsize=1)
def load_paths() -> tuple[str, ...]:
    paths = []
    for line in data.read_text("content_paths.txt").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            paths.append(line.lstrip("/"))
    return tuple(dict.fromkeys(paths))


@dataclass(frozen=True)
class NotFoundFingerprint:
    always_200: bool
    length: int


class ContentDiscoveryCheck(BaseCheck):
    name = "content_discovery"
    severity_hint = Severity.LOW
    description = "Brute-force common unlinked paths (directories, admin panels, API endpoints)"
    enabled_by_default = False  # high request volume; opt in with --checks content_discovery
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        base = ctx.base_url
        fingerprint = await _calibrate(http, base)
        if fingerprint is None:
            return
        budget = REQUEST_BUDGET
        emitted = 0
        for path in load_paths():
            if budget <= 0 or emitted >= MAX_FINDINGS:
                break
            budget -= 1
            url = urljoin(base, path)
            try:
                response = await http.get(url, follow_redirects=False)
            except HTTPClientError:
                continue
            finding = _classify(path, url, response, fingerprint)
            if finding is not None:
                emitted += 1
                yield finding


async def _calibrate(http: HTTPClient, base: str) -> NotFoundFingerprint | None:
    lengths: list[int] = []
    statuses: list[int] = []
    for _ in range(2):
        url = urljoin(base, f"wraith-{secrets.token_hex(10)}")
        try:
            response = await http.get(url, follow_redirects=False)
        except HTTPClientError:
            return None
        lengths.append(len(response.text))
        statuses.append(response.status_code)
    always_200 = all(s == 200 for s in statuses)
    return NotFoundFingerprint(always_200=always_200, length=max(lengths))


def _classify(path: str, url: str, response: Response, fp: NotFoundFingerprint) -> Finding | None:
    status = response.status_code
    if status in (404, 410):
        return None
    if status in (401, 403):
        return _finding(path, url, response, f"exists but is protected (HTTP {status})")
    if status in (301, 302, 307, 308):
        location = response.headers.get("location", "")
        return _finding(path, url, response, f"redirects (HTTP {status} -> {location})")
    if 200 <= status < 300:
        if fp.always_200 and abs(len(response.text) - fp.length) <= LENGTH_TOLERANCE * max(
            fp.length, 1
        ):
            return None  # indistinguishable from the catch-all "not found" page
        return _finding(path, url, response, f"accessible (HTTP {status})")
    return None


def _finding(path: str, url: str, response: Response, state: str) -> Finding:
    sensitive = any(s in path.lower() for s in _SENSITIVE)
    return Finding(
        check=ContentDiscoveryCheck.name,
        title=f"Discovered path /{path}",
        url=url,
        severity=Severity.LOW if sensitive else Severity.INFO,
        confidence=Confidence.CONFIRMED,
        description=(
            f"The path /{path} is not linked from the crawled pages but {state}. Unlinked "
            "endpoints often expose admin interfaces, APIs, backups, or debug tooling that get "
            "less security attention. Review whether it should be publicly reachable."
        ),
        remediation=(
            "Remove or restrict access to endpoints that should not be public (authentication, "
            "network ACLs), and do not rely on an endpoint being unlinked for its security."
        ),
        evidence=(response.exchange.to_evidence(include_body=False),),
        references=REFERENCES,
    )
