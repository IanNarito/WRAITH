"""Core data models: Severity, Confidence, Evidence, Finding.

Step 1 only needs ``Severity`` (for ``--fail-on``); the rest lands in step 2.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)
