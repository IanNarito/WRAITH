"""Audit log: a timestamped (UTC) file recording the authorization affirmation, every scope
decision, and every request, for the engagement record.

It captures everything logged under the ``wraith`` logger at DEBUG level, independent of the
console verbosity.
"""

from __future__ import annotations

import getpass
import logging
import socket
import time
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Self

from wraith import __version__
from wraith.config import ScanConfig

logger = logging.getLogger("wraith.audit")

_FORMAT = "%(asctime)s.%(msecs)03dZ %(levelname)-7s %(name)s: %(message)s"


def default_audit_path(now: datetime) -> Path:
    return Path(f"wraith-audit-{now:%Y%m%dT%H%M%SZ}.log")


def _operator() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._handler: logging.Handler | None = None
        self._previous_level = logging.NOTSET

    def __enter__(self) -> Self:
        if self.path.parent != Path():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(self.path, encoding="utf-8")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        root = logging.getLogger("wraith")
        self._previous_level = root.level
        root.setLevel(logging.DEBUG)
        root.addHandler(handler)
        self._handler = handler
        logger.info("WRAITH %s audit log opened by %s", __version__, _operator())
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc is not None and not isinstance(exc, SystemExit):
            logger.error("scan aborted: %s: %s", type(exc).__name__, exc)
        logger.info("audit log closed")
        if self._handler is not None:
            root = logging.getLogger("wraith")
            root.removeHandler(self._handler)
            root.setLevel(self._previous_level)
            self._handler.close()
            self._handler = None

    def record_config(self, config: ScanConfig) -> None:
        logger.info(
            "scan config: target=%s scope=%s safe_mode=%s rate=%g concurrency=%d checks=%s "
            "exclude=%s proxy=%s",
            config.target,
            ",".join(config.scope),
            config.safe_mode,
            config.rate,
            config.concurrency,
            ",".join(config.checks) or "(defaults)",
            ",".join(config.exclude) or "-",
            config.proxy or "-",
        )

    def record_authorization(self, config: ScanConfig, *, affirmed: bool, method: str) -> None:
        if affirmed:
            logger.info(
                "AUTHORIZATION AFFIRMED by %s via %s: permission to test target=%s scope=%s",
                _operator(),
                method,
                config.target,
                ",".join(config.scope),
            )
        else:
            logger.warning(
                "AUTHORIZATION NOT GIVEN (%s); no requests sent for target=%s",
                method,
                config.target,
            )
