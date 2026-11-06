"""ScopeManager: the hard safety boundary that decides which URLs may be requested.

Rules (comma-separated on the CLI):

* ``example.com``          exact host, any port
* ``example.com:8443``     exact host and port
* ``*.example.com``        glob (``fnmatch``) on the host; does NOT match ``example.com`` itself
* ``re:^api\\d+\\.example\\.com$``  regular expression on the host (full match, case-insensitive)
* ``https://example.com/x`` URLs are accepted; only host and explicit port are used

Only http and https URLs can ever be in scope.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

import httpx

logger = logging.getLogger("wraith.scope")

DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


class ScopeError(ValueError):
    """Raised for an invalid or unsafe scope rule."""


@dataclass(frozen=True)
class ScopeRule:
    raw: str
    kind: Literal["host", "glob", "regex"]
    pattern: str
    port: int | None = None

    def matches(self, host: str, port: int) -> bool:
        if self.port is not None and port != self.port:
            return False
        if self.kind == "host":
            return host == self.pattern
        if self.kind == "glob":
            return fnmatch.fnmatchcase(host, self.pattern)
        return re.fullmatch(self.pattern, host, re.IGNORECASE) is not None


def parse_rule(raw: str) -> ScopeRule:
    text = raw.strip()
    if not text:
        raise ScopeError("empty scope rule")

    if text[:3].lower() == "re:":
        pattern = text[3:]
        if not pattern:
            raise ScopeError(f"empty regex in scope rule {raw!r}")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ScopeError(f"invalid regex in scope rule {raw!r}: {exc}") from exc
        return ScopeRule(raw=raw, kind="regex", pattern=pattern)

    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].rpartition("@")[2]  # drop path and userinfo
    host, port = _split_host_port(text, raw)
    host = host.lower().rstrip(".")
    if not host or set(host) <= {"*", "."}:
        raise ScopeError(
            f"scope rule {raw!r} is too broad; name the hosts you are authorized to test"
        )
    kind: Literal["host", "glob"] = "glob" if any(c in host for c in "*?[") else "host"
    return ScopeRule(raw=raw, kind=kind, pattern=host, port=port)


def _split_host_port(text: str, raw: str) -> tuple[str, int | None]:
    if text.startswith("["):  # [IPv6]:port
        end = text.find("]")
        if end == -1:
            raise ScopeError(f"unterminated IPv6 address in scope rule {raw!r}")
        host, rest = text[1:end], text[end + 1 :]
        if not rest:
            return host, None
        if rest.startswith(":"):
            return host, _parse_port(rest[1:], raw)
        raise ScopeError(f"invalid scope rule {raw!r}")
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, _parse_port(port, raw)
    return text, None  # plain host, or bare IPv6 without port


def _parse_port(value: str, raw: str) -> int:
    if not value.isdigit() or not 0 < int(value) < 65536:
        raise ScopeError(f"invalid port in scope rule {raw!r}")
    return int(value)


class ScopeManager:
    """Decides whether a URL is in scope. Every outgoing request is checked here first."""

    def __init__(self, rules: Iterable[str]) -> None:
        self.rules: tuple[ScopeRule, ...] = tuple(parse_rule(r) for r in rules)
        if not self.rules:
            raise ScopeError("at least one scope rule is required")
        self.blocked: set[str] = set()

    def is_in_scope(self, url: str | httpx.URL) -> bool:
        """Pure decision, no logging. Use for classifying discovered links."""
        try:
            parsed = url if isinstance(url, httpx.URL) else httpx.URL(url)
        except (httpx.InvalidURL, TypeError):
            return False
        scheme = parsed.scheme.lower()
        if scheme not in DEFAULT_PORTS:
            return False
        port = parsed.port or DEFAULT_PORTS[scheme]
        # Compare both the unicode and the IDNA (punycode) spelling of the host.
        names = {
            parsed.host.lower().rstrip("."),
            parsed.raw_host.decode("ascii", "replace").lower().rstrip("."),
        }
        names.discard("")
        return any(rule.matches(name, port) for name in names for rule in self.rules)

    def check(self, url: str | httpx.URL) -> bool:
        """Scope decision for a request about to be sent; logs and records blocks."""
        allowed = self.is_in_scope(url)
        if allowed:
            logger.debug("scope ALLOW %s", url)
        else:
            self.blocked.add(str(url))
            logger.warning("scope BLOCK %s (out of scope, not sent)", url)
        return allowed

    def describe(self) -> str:
        return ", ".join(rule.raw for rule in self.rules)
