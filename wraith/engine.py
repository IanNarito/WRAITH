"""Engine: scope -> discovery -> concurrent checks -> de-duplicated, sorted findings."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from wraith.checks.base import BaseCheck
from wraith.config import ScanConfig
from wraith.context import ScanContext
from wraith.discovery import DiscoveryError, discover
from wraith.http_client import HTTPClient
from wraith.models import Finding, Severity
from wraith.registry import PluginRegistry, RegistryError
from wraith.scope import ScopeError, ScopeManager

logger = logging.getLogger("wraith.engine")


class ScanError(Exception):
    """The scan could not run (bad scope, unreachable target, unknown check...)."""


@dataclass(frozen=True)
class CheckFailure:
    check: str
    error: str


@dataclass(frozen=True)
class ScanResult:
    config: ScanConfig
    context: ScanContext
    findings: tuple[Finding, ...]
    failures: tuple[CheckFailure, ...]
    checks_run: tuple[str, ...]
    requests_sent: int
    blocked_requests: int
    started_at: datetime
    duration_s: float

    def exit_code(self, fail_on: Severity | None) -> int:
        """0 = clean, 1 = findings at/above ``fail_on``, 2 = scan incomplete (a check failed)."""
        if self.failures:
            return 2
        if fail_on is not None and any(f.severity.rank >= fail_on.rank for f in self.findings):
            return 1
        return 0


class Engine:
    def __init__(
        self,
        config: ScanConfig,
        *,
        registry: PluginRegistry | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.registry = registry or PluginRegistry()
        self._transport = transport

    async def run(self) -> ScanResult:
        config = self.config
        started_at = datetime.now(UTC)
        started = time.perf_counter()

        try:
            scope = ScopeManager(config.scope)
        except ScopeError as exc:
            raise ScanError(str(exc)) from exc
        if not scope.is_in_scope(config.target):
            raise ScanError(
                f"target {config.target} is not covered by the declared scope ({scope.describe()})"
            )
        try:
            checks = self.registry.select(config.checks, config.exclude, safe_mode=config.safe_mode)
        except RegistryError as exc:
            raise ScanError(str(exc)) from exc
        if not checks:
            raise ScanError("no checks selected")

        async with HTTPClient(config, scope, transport=self._transport) as http:
            try:
                ctx = await discover(config.target, http, scope)
            except DiscoveryError as exc:
                raise ScanError(str(exc)) from exc
            logger.info("running %d checks: %s", len(checks), ", ".join(c.name for c in checks))
            semaphore = asyncio.Semaphore(config.concurrency)
            outcomes = await asyncio.gather(
                *(self._run_check(check, ctx, http, semaphore) for check in checks)
            )
            requests_sent = http.requests_sent

        findings: list[Finding] = []
        failures: list[CheckFailure] = []
        for check_findings, failure in outcomes:
            findings.extend(check_findings)
            if failure is not None:
                failures.append(failure)

        return ScanResult(
            config=config,
            context=ctx,
            findings=finalize(findings),
            failures=tuple(failures),
            checks_run=tuple(c.name for c in checks),
            requests_sent=requests_sent,
            blocked_requests=len(scope.blocked),
            started_at=started_at,
            duration_s=time.perf_counter() - started,
        )

    async def _run_check(
        self,
        check: BaseCheck,
        ctx: ScanContext,
        http: HTTPClient,
        semaphore: asyncio.Semaphore,
    ) -> tuple[list[Finding], CheckFailure | None]:
        found: list[Finding] = []
        async with semaphore:
            try:
                async for finding in check.run(ctx, http):
                    if not finding.evidence:
                        logger.warning(
                            "dropping finding %r from %s: no evidence attached",
                            finding.title,
                            check.name,
                        )
                        continue
                    found.append(finding)
            except Exception as exc:  # one broken check must not sink the whole scan
                logger.error("check %s failed: %s: %s", check.name, type(exc).__name__, exc)
                logger.debug("traceback for %s", check.name, exc_info=True)
                return found, CheckFailure(check.name, f"{type(exc).__name__}: {exc}")
        logger.info("check %s: %d finding(s)", check.name, len(found))
        return found, None


def finalize(findings: list[Finding]) -> tuple[Finding, ...]:
    """De-duplicate (first wins) and sort: most severe first, then check, URL, title."""
    unique: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        unique.setdefault(finding.dedup_key, finding)
    return tuple(sorted(unique.values(), key=lambda f: (-f.severity.rank, f.check, f.url, f.title)))
