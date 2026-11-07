"""OS command injection detection (aggressive, non-destructive).

Two techniques, per injection point:

* Echo-marker (in-band): append a shell command that echoes a unique random token via a shell
  metacharacter (``;`` ``|`` ``&`` ``$(...)`` backticks, newline). If the token comes back WITHOUT
  the literal ``echo <token>`` text, the shell ran the command (reflection would echo the whole
  payload, metacharacters and all). This differential makes the finding CONFIRMED with near-zero
  false positives, and it only ever runs ``echo`` - it reads nothing and changes no state.
* Time-based blind (fallback): only when nothing is echoed back, ask the OS to sleep and confirm
  with a fast zero-delay control request, exactly like the SQLi time technique. Tightly budgeted.

The probes run a single harmless ``echo``/``sleep``; they do not read files, spawn shells beyond
one command, or alter the target. Blind findings are PROBABLE; confirm manually.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator

from wraith.checks.base import BaseCheck
from wraith.context import ScanContext
from wraith.http_client import HTTPClient, HTTPClientError, Response
from wraith.injection import MAX_POINTS, InjectionPoint, points_from_context, send_probe
from wraith.models import Confidence, Finding, Severity

logger = logging.getLogger("wraith.checks.command_injection")
REFERENCES = (
    "https://owasp.org/www-community/attacks/Command_Injection",
    "https://cwe.mitre.org/data/definitions/78.html",
)

# Shell separators wrapped around ``echo <token>``. {t} is the unique token.
_ECHO_TEMPLATES = (
    ";echo {t}",
    "|echo {t}",
    "||echo {t}",
    "&echo {t}",
    "&&echo {t}",
    "$(echo {t})",
    "`echo {t}`",
    "\n echo {t}",
    "; echo {t} #",
    "' ;echo {t}; '",
    '" ;echo {t}; "',
)

# Time-based blind: sleep a few seconds, confirmed by a fast zero-delay control. {d} is seconds.
_SLEEP_TEMPLATES = (
    ";sleep {d}",
    "|sleep {d}",
    "$(sleep {d})",
    "`sleep {d}`",
    "& ping -n {dp1} 127.0.0.1",  # Windows: ping N times ~= (N-1) seconds
    "& ping -c {d} 127.0.0.1 &",
    "\n sleep {d}",
)
TIME_DELAY = 5  # seconds the injected command sleeps
TIME_RATIO = 0.6
TIME_BUDGET = 6  # at most this many points get the (slow) time test per scan


class CommandInjectionCheck(BaseCheck):
    name = "command_injection"
    severity_hint = Severity.CRITICAL
    description = "OS command injection in query and form parameters"
    enabled_by_default = True
    requires_aggressive = True

    async def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        time_budget = [TIME_BUDGET]
        for point in points_from_context(ctx)[:MAX_POINTS]:
            finding = await _probe_point(http, point, time_budget)
            if finding is not None:
                yield finding


async def _probe_point(
    http: HTTPClient, point: InjectionPoint, time_budget: list[int]
) -> Finding | None:
    base_value = point.baseline()
    try:
        baseline = await send_probe(http, point, base_value or "1")
    except HTTPClientError:
        return None

    echo_finding = await _echo_based(http, point, baseline)
    if echo_finding is not None:
        return echo_finding
    if time_budget[0] > 0:
        time_budget[0] -= 1
        return await _time_based(http, point, baseline)
    return None


async def _echo_based(
    http: HTTPClient, point: InjectionPoint, baseline: Response
) -> Finding | None:
    base_value = point.baseline()
    token = f"wraithci{secrets.token_hex(5)}"
    if token in baseline.text:  # astronomically unlikely, but keep the differential honest
        return None
    for template in _ECHO_TEMPLATES:
        suffix = template.format(t=token)
        payload = f"{base_value}{suffix}" if base_value else suffix
        try:
            response = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        # Executed: the token is printed alone. Reflected: the whole "echo <token>" is echoed back.
        if token in response.text and f"echo {token}" not in response.text:
            return _finding(
                point,
                "echo marker",
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"Appending {suffix!r} made the server run a shell command: the unique token "
                f"{token!r} was returned without the literal 'echo' text, so the metacharacter "
                "broke out of the intended command and the shell executed the injected one.",
                response,
                token,
            )
    return None


async def _time_based(
    http: HTTPClient, point: InjectionPoint, baseline: Response
) -> Finding | None:
    base_value = point.baseline()
    delay = TIME_DELAY
    base_ms = baseline.exchange.elapsed_ms
    threshold_ms = base_ms + delay * 1000 * TIME_RATIO
    for template in _SLEEP_TEMPLATES:
        suffix = template.format(d=delay, dp1=delay + 1)
        payload = f"{base_value}{suffix}" if base_value else suffix
        try:
            delayed = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        if delayed.exchange.elapsed_ms < threshold_ms:
            continue
        # Confirm: the same command with a zero delay must return quickly; otherwise the endpoint
        # is simply slow and this is not a timing signal.
        control_suffix = template.format(d=0, dp1=1)
        control_payload = f"{base_value}{control_suffix}" if base_value else control_suffix
        try:
            control = await send_probe(http, point, control_payload)
        except HTTPClientError:
            continue
        if control.exchange.elapsed_ms >= threshold_ms:
            continue
        return _finding(
            point,
            "time-based blind",
            Severity.HIGH,
            Confidence.PROBABLE,
            f"A payload asking the OS to sleep for {delay}s delayed the response "
            f"({delayed.exchange.elapsed_ms:.0f} ms vs {base_ms:.0f} ms baseline) while the same "
            f"command with no delay returned quickly ({control.exchange.elapsed_ms:.0f} ms). The "
            "injected command is executed by the operating system even though no output is shown.",
            delayed,
            None,
        )
    return None


def _finding(
    point: InjectionPoint,
    technique: str,
    severity: Severity,
    confidence: Confidence,
    detail: str,
    response: Response,
    matched: str | None,
) -> Finding:
    return Finding(
        check=CommandInjectionCheck.name,
        title=f"OS command injection ({technique}) in parameter {point.param!r}",
        url=point.action,
        severity=severity,
        confidence=confidence,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) is passed to a system "
            "shell without sanitization. "
            + detail
            + " This gives an attacker arbitrary command execution on the server; treat the host "
            "as fully compromisable and confirm the scope of access manually."
        ),
        remediation=(
            "Never pass user input to a shell. Call programs directly with an argument array (no "
            "shell interpretation), use the language's exec APIs that take an argv list, validate "
            "input against a strict allowlist, and drop the privileges of the executing process."
        ),
        evidence=(response.exchange.to_evidence(matched),),
        references=REFERENCES,
    )
