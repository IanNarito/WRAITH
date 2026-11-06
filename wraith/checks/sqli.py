"""SQL injection detection (aggressive), using non-destructive techniques.

Two techniques, per injection point:

* Error-based: send a value that breaks a string literal (a single quote) and look for a
  database error signature that is NOT present in the baseline response. The differential keeps
  the false-positive rate low.
* Boolean-based: compare a value carrying an always-true condition against an always-false one.
  If the true variant matches the baseline while the false variant differs markedly, the
  condition is being evaluated by a database. Conditions are strict to avoid false positives.

The probes only break and rebalance quotes and append simple boolean conditions. They do not
extract data, stack queries, or use time delays, so they do not change state or load the server
beyond a normal request. Findings are PROBABLE and should be confirmed manually.
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger("wraith.checks.sqli")
REFERENCES = (
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
)
# Boolean-based: lengths of the true-condition and baseline responses must agree within this
# fraction, and the false-condition response must differ by at least this much, to report.
_LEN_TOLERANCE = 0.02
_LEN_DIFFERENCE = 0.30

# Time-based blind: the slowest, most load-sensitive technique, so it is tightly bounded. It
# runs only after error- and boolean-based find nothing, on at most TIME_BUDGET points per scan,
# with a single sleeping request confirmed by one fast control request (to rule out an endpoint
# that is simply slow). A delayed response must exceed baseline + TIME_DELAY * TIME_RATIO seconds.
TIME_DELAY = 5  # seconds the injected payload asks the database to sleep
TIME_RATIO = 0.6
TIME_BUDGET = 8


@dataclass(frozen=True)
class SqlErrorSignature:
    dbms: str
    pattern: re.Pattern[str]


@lru_cache(maxsize=1)
def load_error_signatures() -> tuple[SqlErrorSignature, ...]:
    out: list[SqlErrorSignature] = []
    for line in data.read_text("sql_errors.txt").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        dbms, _, pattern = line.partition(" | ")
        out.append(SqlErrorSignature(dbms.strip(), re.compile(pattern.strip(), re.IGNORECASE)))
    return tuple(out)


def first_sql_error(text: str) -> SqlErrorSignature | None:
    return next((sig for sig in load_error_signatures() if sig.pattern.search(text)), None)


class SqliCheck(BaseCheck):
    name = "sqli"
    severity_hint = Severity.CRITICAL
    description = "SQL injection in query and form parameters (error- and boolean-based)"
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
    baseline_error = first_sql_error(baseline.text)

    error_finding = await _error_based(http, point, baseline, baseline_error)
    if error_finding is not None:
        return error_finding
    if baseline_error is not None:
        return None  # app shows SQL errors regardless; boolean/time tests would be unreliable

    boolean_finding = await _boolean_based(http, point, baseline)
    if boolean_finding is not None:
        return boolean_finding
    if time_budget[0] > 0:
        time_budget[0] -= 1
        return await _time_based(http, point, baseline)
    return None


async def _error_based(
    http: HTTPClient,
    point: InjectionPoint,
    baseline: Response,
    baseline_error: SqlErrorSignature | None,
) -> Finding | None:
    base_value = point.baseline() or "1"
    for payload in (f"{base_value}'", f'{base_value}"'):
        try:
            response = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        error = first_sql_error(response.text)
        # Report only a NEW error that the baseline did not already show.
        if error is not None and (baseline_error is None or error.dbms != baseline_error.dbms):
            return _finding(
                point,
                "error-based",
                Severity.CRITICAL,
                f"Injecting a single quote into {point.param!r} triggered a {error.dbms} error "
                f"({error.pattern.pattern!r}) that the baseline response did not contain. The "
                "parameter is concatenated into a SQL statement without parameterization.",
                response,
                error.pattern.search(response.text),
            )
    return None


async def _boolean_based(
    http: HTTPClient, point: InjectionPoint, baseline: Response
) -> Finding | None:
    base_value = point.baseline() or "1"
    # String-context and numeric-context true/false pairs.
    pairs = [
        (f"{base_value}' AND '1'='1", f"{base_value}' AND '1'='2"),
        (f"{base_value} AND 1=1", f"{base_value} AND 1=2"),
    ]
    base_len = len(baseline.text)
    if base_len == 0:
        return None
    for true_payload, false_payload in pairs:
        try:
            true_resp = await send_probe(http, point, true_payload)
            false_resp = await send_probe(http, point, false_payload)
        except HTTPClientError:
            continue
        if true_resp.status_code != 200 or false_resp.status_code != 200:
            continue
        true_len, false_len = len(true_resp.text), len(false_resp.text)
        true_matches_base = abs(true_len - base_len) <= _LEN_TOLERANCE * base_len
        false_differs = abs(false_len - true_len) >= _LEN_DIFFERENCE * max(true_len, 1)
        if true_matches_base and false_differs:
            return _finding(
                point,
                "boolean-based",
                Severity.HIGH,
                f"The always-true condition appended to {point.param!r} returned a response "
                f"matching the baseline ({true_len} vs {base_len} bytes) while the always-false "
                f"condition returned a markedly different one ({false_len} bytes). The parameter "
                "is evaluated inside a SQL query.",
                false_resp,
                None,
            )
    return None


async def _time_based(
    http: HTTPClient, point: InjectionPoint, baseline: Response
) -> Finding | None:
    delay = TIME_DELAY
    base_ms = baseline.exchange.elapsed_ms
    threshold_ms = base_ms + delay * 1000 * TIME_RATIO
    base_value = point.baseline() or "1"
    payloads = (
        f"{base_value}' AND SLEEP({delay})-- -",
        f"{base_value}' OR SLEEP({delay})-- -",
        f"{base_value} AND SLEEP({delay})",
        f"{base_value}' AND pg_sleep({delay})-- -",
        f"{base_value}'; WAITFOR DELAY '0:0:{delay}'-- -",
    )
    for payload in payloads:
        try:
            delayed = await send_probe(http, point, payload)
        except HTTPClientError:
            continue
        if delayed.exchange.elapsed_ms < threshold_ms:
            continue
        # Confirm: the same statement with a zero delay must come back fast. If it is also slow,
        # the endpoint is simply slow and this is not a time-based injection.
        control_payload = (
            payload.replace(f"SLEEP({delay})", "SLEEP(0)")
            .replace(f"pg_sleep({delay})", "pg_sleep(0)")
            .replace(f"0:0:{delay}", "0:0:0")
        )
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
            f"A payload asking the database to sleep for {delay}s delayed the response "
            f"({delayed.exchange.elapsed_ms:.0f} ms vs {base_ms:.0f} ms baseline), while the same "
            f"statement with a zero delay returned quickly ({control.exchange.elapsed_ms:.0f} ms). "
            "The injected condition is executed by the database, so data can be inferred even "
            "though no output or error is shown (blind injection).",
            delayed,
            None,
        )
    return None


def _finding(
    point: InjectionPoint,
    technique: str,
    severity: Severity,
    description: str,
    response: Response,
    matched: re.Match[str] | None,
) -> Finding:
    indicator = matched.group(0) if matched is not None else None
    return Finding(
        check=SqliCheck.name,
        title=f"SQL injection ({technique}) in parameter {point.param!r}",
        url=point.action,
        severity=severity,
        confidence=Confidence.PROBABLE,
        description=(
            f"The {point.source} parameter {point.param!r} ({point.method}) appears injectable. "
            + description
            + " Confirm manually before exploitation and treat the backend data as at risk."
        ),
        remediation=(
            "Use parameterized queries / prepared statements for all database access, never build "
            "SQL by string concatenation, validate and type-check input, and apply least-privilege "
            "database accounts."
        ),
        evidence=(response.exchange.to_evidence(indicator),),
        references=REFERENCES,
    )
