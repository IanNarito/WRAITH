"""ScanConfig: the fully parsed, validated settings for one scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from wraith.models import Severity

DEFAULT_RATE = 5.0  # requests per second
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 10.0  # seconds
DEFAULT_USER_AGENT = "WRAITH/0.1 (+authorized security testing)"


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"


class ConfigError(ValueError):
    """Raised when CLI input cannot form a valid ScanConfig."""


@dataclass(frozen=True)
class ScanConfig:
    target: str
    scope: tuple[str, ...]
    confirm_authorized: bool = False
    rate: float = DEFAULT_RATE
    concurrency: int = DEFAULT_CONCURRENCY
    checks: tuple[str, ...] = ()  # empty = all enabled-by-default checks
    exclude: tuple[str, ...] = ()
    output_format: OutputFormat = OutputFormat.TERMINAL
    output: Path | None = None
    proxy: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    safe_mode: bool = True
    fail_on: Severity | None = None
    verbosity: int = 0


def split_csv(value: str | None) -> tuple[str, ...]:
    """Split a comma-separated CLI value into trimmed, non-empty items."""
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def normalize_target(target: str) -> str:
    """Ensure the target is an absolute http(s) URL."""
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"target must be an http(s) URL with a host, got {target!r}")
    return target


def parse_headers(values: list[str]) -> dict[str, str]:
    """Parse repeated ``Name: value`` header arguments."""
    headers: dict[str, str] = {}
    for raw in values:
        name, sep, val = raw.partition(":")
        if not sep or not name.strip():
            raise ConfigError(f"header must look like 'Name: value', got {raw!r}")
        headers[name.strip()] = val.strip()
    return headers


def parse_cookies(values: list[str]) -> dict[str, str]:
    """Parse repeated ``name=value`` (or ``a=1; b=2``) cookie arguments."""
    cookies: dict[str, str] = {}
    for raw in values:
        for pair in raw.split(";"):
            if not pair.strip():
                continue
            name, sep, val = pair.partition("=")
            if not sep or not name.strip():
                raise ConfigError(f"cookie must look like 'name=value', got {pair!r}")
            cookies[name.strip()] = val.strip()
    return cookies
