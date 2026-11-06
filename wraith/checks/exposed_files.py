"""Exposed / sensitive file check, verified by content signature (not just a 200)."""

from __future__ import annotations

import re
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urljoin, urlsplit

from wraith import data
from wraith.checks.base import BaseCheck
from wraith.context import HTML_TYPES, ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.models import Confidence, Finding, Severity

PROBE_MAX_BYTES = 64 * 1024  # signatures sit near the start; don't download whole archives
REFERENCES = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
)


@dataclass(frozen=True)
class ExposedPath:
    path: str
    severity: Severity
    allow_html: bool
    title: str
    signature: re.Pattern[bytes]


class WordlistError(ValueError):
    pass


@lru_cache(maxsize=1)
def load_wordlist() -> tuple[ExposedPath, ...]:
    entries: list[ExposedPath] = []
    for lineno, line in enumerate(data.read_text("exposed_paths.txt").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" | ", 4)]
        if len(parts) != 5:
            raise WordlistError(f"exposed_paths.txt:{lineno}: expected 5 fields, got {len(parts)}")
        path, severity, flags, title, signature = parts
        try:
            entries.append(
                ExposedPath(
                    path=path.lstrip("/"),
                    severity=Severity(severity.lower()),
                    allow_html="html" in flags.split(","),
                    title=title,
                    signature=re.compile(signature.encode("utf-8")),
                )
            )
        except (ValueError, re.error) as exc:
            raise WordlistError(f"exposed_paths.txt:{lineno}: {exc}") from exc
    return tuple(entries)


class ExposedFilesCheck(BaseCheck):
    name = "exposed_files"
    severity_hint = Severity.CRITICAL
    description = "Publicly reachable sensitive files (.git, .env, backups, dumps, phpinfo...)"

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for base in _probe_bases(ctx.base_url):
            baseline = await self._baseline(base, http)
            for entry in load_wordlist():
                url = urljoin(base, entry.path)
                try:
                    response = await http.get(
                        url, follow_redirects=False, max_bytes=PROBE_MAX_BYTES
                    )
                except HTTPClientError:
                    continue
                if (match := _verify(entry, response, baseline)) is not None:
                    yield _finding(entry, url, response, match)

    async def _baseline(self, base: str, http: HTTPClient) -> bytes | None:
        """Body served for a path that cannot exist, to rule out catch-all responses."""
        url = urljoin(base, f"wraith-{secrets.token_hex(8)}.txt")
        try:
            response = await http.get(url, follow_redirects=False, max_bytes=PROBE_MAX_BYTES)
        except HTTPClientError:
            return None
        return response.content if response.status_code == 200 else None


def _probe_bases(base_url: str) -> list[str]:
    """The site root, plus the target's directory when it isn't the root."""
    parts = urlsplit(base_url)
    root = f"{parts.scheme}://{parts.netloc}/"
    directory = urljoin(base_url, ".")
    return [root] if directory == root else [root, directory]


def _verify(entry: ExposedPath, response: Response, baseline: bytes | None) -> str | None:
    """Return the matched indicator if the response really is the sensitive file."""
    if response.status_code != 200 or not response.content:
        return None
    if baseline is not None and response.content == baseline:
        return None
    if not entry.allow_html and _is_html(response):
        return None
    match = entry.signature.search(response.content)
    if match is None:
        return None
    return match.group(0).decode("utf-8", "replace")


def _is_html(response: Response) -> bool:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    head = response.content.lstrip()[:100].lower()
    return content_type in HTML_TYPES or head.startswith((b"<!doctype html", b"<html"))


def _finding(entry: ExposedPath, url: str, response: Response, matched: str) -> Finding:
    return Finding(
        check=ExposedFilesCheck.name,
        title=entry.title,
        url=url,
        severity=entry.severity,
        confidence=Confidence.CONFIRMED,
        description=(
            f"/{entry.path} is publicly accessible and its content matches the signature of "
            f"this file type (matched {matched[:80]!r}), so it is the real file and not a "
            "custom error page. Files like this can disclose source code, credentials, or "
            "internal configuration."
        ),
        remediation=(
            "Remove the file from the web root and block access to it (and similar files) in "
            "the web server configuration. Assume any credentials or keys it contained are "
            "compromised and rotate them."
        ),
        evidence=(response.exchange.to_evidence(matched),),
        references=REFERENCES,
    )
