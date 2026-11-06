"""Core data models: Severity, Confidence, Evidence, Finding."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """0 for INFO up to 4 for CRITICAL."""
        return list(Severity).index(self)


class Confidence(StrEnum):
    CONFIRMED = "confirmed"  # directly observed and verified
    PROBABLE = "probable"  # strong indicator, small chance of being wrong
    INFORMATIONAL = "informational"  # context for the tester, not a vulnerability claim


@dataclass(frozen=True)
class Evidence:
    """The exact request sent and the part of the response that triggered a finding."""

    request: str
    response_snippet: str
    matched: str | None = None


@dataclass(frozen=True)
class Finding:
    check: str
    title: str
    url: str
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    evidence: tuple[Evidence, ...] = ()
    references: tuple[str, ...] = ()
    cvss: float | None = None

    @property
    def dedup_key(self) -> tuple[str, str, str]:
        return (self.check, self.title, self.url)
