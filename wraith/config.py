"""ScanConfig: the parsed, validated settings for one scan, plus YAML config loading."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse

import yaml

from wraith.models import Severity
from wraith.scope import ScopeError, parse_rule

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
    """Raised when input cannot form a valid ScanConfig."""


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
    cve: bool = False  # correlate detected versions against NVD (contacts NVD, not the target)
    nvd_api_key: str | None = None
    cve_cache: Path | None = None
    crawl_depth: int = 1  # same-origin BFS depth: 1 = links on the target page only
    max_pages: int = 30
    login_url: str | None = None  # form-login endpoint; scanning proceeds authenticated
    login_data: dict[str, str] = field(default_factory=dict)
    login_check: str | None = None  # substring expected in the post-login response


# Config-file key -> CLI parameter name.
FILE_KEYS: dict[str, str] = {
    "scope": "scope",
    "rate": "rate",
    "concurrency": "concurrency",
    "checks": "checks",
    "exclude": "exclude",
    "format": "output_format",
    "output": "output",
    "proxy": "proxy",
    "timeout": "timeout",
    "user_agent": "user_agent",
    "headers": "header",
    "cookies": "cookie",
    "safe_mode": "safe_mode",
    "fail_on": "fail_on",
    "verbose": "verbose",
    "cve": "cve",
    "cve_cache": "cve_cache",
    "crawl_depth": "crawl_depth",
    "max_pages": "max_pages",
    "login_url": "login_url",
    "login_data": "login_data",
    "login_check": "login_check",
}
FORBIDDEN_FILE_KEYS: dict[str, str] = {
    "target": "pass the target on the command line",
    "confirm_authorized": "authorization must be affirmed on the command line for each run",
    "nvd_api_key": "pass the NVD API key via --nvd-api-key or the NVD_API_KEY environment variable",
}


def load_config_file(path: Path) -> dict[str, Any]:
    """Load a YAML config file into CLI-parameter-named values."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a YAML mapping")

    values: dict[str, Any] = {}
    for key, value in raw.items():
        name = str(key).replace("-", "_")
        if name in FORBIDDEN_FILE_KEYS:
            reason = FORBIDDEN_FILE_KEYS[name]
            raise ConfigError(f"{key!r} is not allowed in a config file: {reason}")
        if name not in FILE_KEYS:
            raise ConfigError(f"unknown config key {key!r}; allowed: {', '.join(FILE_KEYS)}")
        if name == "headers" and isinstance(value, dict):
            value = [f"{k}: {v}" for k, v in value.items()]
        elif name in ("cookies", "login_data") and isinstance(value, dict):
            value = [f"{k}={v}" for k, v in value.items()]
        values[FILE_KEYS[name]] = value
    return values


def build_config(values: Mapping[str, Any]) -> ScanConfig:
    """Validate raw CLI/config values (keyed by CLI parameter name) into a ScanConfig."""
    target = normalize_target(str(values["target"]))
    scope = _items(values.get("scope"), "scope") or (urlparse(target).hostname or "",)
    for rule in scope:
        try:
            parse_rule(rule)
        except ScopeError as exc:
            raise ConfigError(str(exc)) from exc

    proxy = values.get("proxy") or None
    if proxy is not None:
        proxy = str(proxy)
        if urlparse(proxy).scheme not in ("http", "https") or not urlparse(proxy).hostname:
            raise ConfigError(f"proxy must be an http(s) URL like http://127.0.0.1:8080: {proxy!r}")

    output = values.get("output")
    fail_on = values.get("fail_on")
    cve_cache = values.get("cve_cache")
    api_key = values.get("nvd_api_key") or None
    login_url = values.get("login_url") or None
    if login_url is not None:
        login_url = normalize_target(str(login_url))
    login_check = values.get("login_check")
    return ScanConfig(
        target=target,
        scope=scope,
        confirm_authorized=_bool(values.get("confirm_authorized", False), "confirm_authorized"),
        rate=float(_number(values.get("rate", DEFAULT_RATE), "rate", minimum=0.1)),
        concurrency=int(
            _number(values.get("concurrency", DEFAULT_CONCURRENCY), "concurrency", minimum=1)
        ),
        checks=_items(values.get("checks"), "checks"),
        exclude=_items(values.get("exclude"), "exclude"),
        output_format=_enum(OutputFormat, values.get("output_format"), OutputFormat.TERMINAL),
        output=Path(output) if output is not None else None,
        proxy=proxy,
        timeout=float(_number(values.get("timeout", DEFAULT_TIMEOUT), "timeout", minimum=0.1)),
        user_agent=str(values.get("user_agent") or DEFAULT_USER_AGENT),
        headers=parse_headers(_strings(values.get("header"), "headers")),
        cookies=parse_cookies(_strings(values.get("cookie"), "cookies")),
        safe_mode=_bool(values.get("safe_mode", True), "safe_mode"),
        fail_on=None if fail_on is None else _enum(Severity, fail_on, Severity.INFO),
        verbosity=int(_number(values.get("verbose", 0) or 0, "verbose", minimum=0)),
        cve=_bool(values.get("cve", False), "cve"),
        nvd_api_key=str(api_key) if api_key is not None else None,
        cve_cache=Path(cve_cache) if cve_cache is not None else None,
        crawl_depth=int(_number(values.get("crawl_depth", 1), "crawl_depth", minimum=1)),
        max_pages=int(_number(values.get("max_pages", 30), "max_pages", minimum=1)),
        login_url=login_url,
        login_data=parse_form_pairs(_strings(values.get("login_data"), "login_data")),
        login_check=str(login_check) if login_check else None,
    )


def split_csv(value: str | None) -> tuple[str, ...]:
    """Split a comma-separated value into trimmed, non-empty items."""
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def normalize_target(target: str) -> str:
    """Ensure the target is an absolute http(s) URL."""
    target = target.strip()
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"target must be an http(s) URL with a host, got {target!r}")
    return target


def parse_headers(values: list[str]) -> dict[str, str]:
    """Parse ``Name: value`` header arguments."""
    headers: dict[str, str] = {}
    for raw in values:
        name, sep, val = raw.partition(":")
        if not sep or not name.strip():
            raise ConfigError(f"header must look like 'Name: value', got {raw!r}")
        headers[name.strip()] = val.strip()
    return headers


def parse_form_pairs(values: list[str]) -> dict[str, str]:
    """Parse ``field=value`` login-data arguments (value may contain further '=')."""
    pairs: dict[str, str] = {}
    for raw in values:
        name, sep, val = raw.partition("=")
        if not sep or not name.strip():
            raise ConfigError(f"login-data must look like 'field=value', got {raw!r}")
        pairs[name.strip()] = val
    return pairs


def parse_cookies(values: list[str]) -> dict[str, str]:
    """Parse ``name=value`` (or ``a=1; b=2``) cookie arguments."""
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


# --- coercion helpers -------------------------------------------------------------------------

_E = TypeVar("_E", bound=StrEnum)


def _items(value: Any, name: str) -> tuple[str, ...]:
    """A comma-separated string or a list of strings -> tuple of items."""
    if value is None:
        return ()
    if isinstance(value, str):
        return split_csv(value)
    if isinstance(value, list | tuple):
        return tuple(item for v in value for item in split_csv(str(v)))
    raise ConfigError(f"{name} must be a string or a list")


def _strings(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple):
        return [str(v) for v in value]
    raise ConfigError(f"{name} must be a string, list, or mapping")


def _number(value: Any, name: str, *, minimum: float) -> float:
    if isinstance(value, bool):
        raise ConfigError(f"{name} must be a number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be a number, got {value!r}") from exc
    if number < minimum:
        raise ConfigError(f"{name} must be at least {minimum}, got {value!r}")
    return number


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false, got {value!r}")
    return value


def _enum(cls: type[_E], value: Any, default: _E) -> _E:
    if value is None:
        return default
    if isinstance(value, cls):
        return value
    try:
        return cls(str(value).lower())
    except ValueError as exc:
        choices = ", ".join(member.value for member in cls)
        raise ConfigError(f"invalid value {value!r}; choose from {choices}") from exc
