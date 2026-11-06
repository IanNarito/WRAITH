"""BaseCheck: the abstract class every check plugin extends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import ClassVar

from wraith.context import ScanContext
from wraith.http_client import HTTPClient
from wraith.models import Finding, Severity


class BaseCheck(ABC):
    """Subclass this in any module under ``wraith/checks/`` and it is picked up automatically.

    Contract:
      * send requests only through ``http`` (it enforces scope, rate limit, and safe mode);
      * verify before yielding: a missed finding is better than a false positive;
      * attach evidence to every finding (findings without evidence are dropped).
    """

    name: ClassVar[str]  # unique, snake_case; used by --checks / --exclude
    severity_hint: ClassVar[Severity]  # the most severe finding this check usually produces
    description: ClassVar[str]
    enabled_by_default: ClassVar[bool] = True
    requires_aggressive: ClassVar[bool] = False  # may change state on the target

    @abstractmethod
    def run(self, ctx: ScanContext, http: HTTPClient) -> AsyncIterator[Finding]:
        """Yield verified findings. Implement as ``async def run(...)`` containing ``yield``."""
