"""Shared async HTTP client.

Every request goes through, in order:
  safe-mode method gate -> ScopeManager -> token-bucket rate limiter -> concurrency semaphore.
Redirects are followed manually so every hop is scope-checked. Every exchange is recorded so
findings can carry the exact request and response as evidence.
"""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import itertools
import logging
import re
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from types import TracebackType
from typing import Any, Self

import httpx

from wraith.config import ScanConfig
from wraith.models import Evidence
from wraith.scope import ScopeManager

logger = logging.getLogger("wraith.http")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024
PREVIEW_CHARS = 8192  # body text kept on each recorded exchange
EVIDENCE_BODY_CHARS = 600  # body text included in a finding's evidence
_CHARSET_RE = re.compile(r"charset=[\"']?([\w.:-]+)", re.IGNORECASE)


class HTTPClientError(Exception):
    """A request could not be completed."""


class OutOfScopeError(HTTPClientError):
    """A request was blocked because its URL is outside the declared scope."""


class UnsafeMethodError(HTTPClientError):
    """A state-changing method was attempted while safe mode is on."""


class TokenBucket:
    """Global rate limiter: ``rate`` tokens per second, bursting up to ``capacity``."""

    def __init__(
        self,
        rate: float,
        capacity: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = rate
        self.capacity = max(1.0, capacity)
        self._tokens = self.capacity
        self._clock = clock
        self._last = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = self._clock()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


@dataclass(frozen=True)
class Exchange:
    """One recorded request/response pair."""

    id: int
    method: str
    url: str
    http_version: str
    request_headers: tuple[tuple[str, str], ...]
    status: int
    reason: str
    response_headers: tuple[tuple[str, str], ...]
    body_preview: str
    elapsed_ms: float

    def raw_request(self) -> str:
        target = httpx.URL(self.url).raw_path.decode("ascii", "replace")
        # httpx speaks HTTP/1.1 or HTTP/2; a 1.0 server reply doesn't change what we sent.
        sent_version = "HTTP/2" if self.http_version.startswith("HTTP/2") else "HTTP/1.1"
        lines = [f"{self.method} {target} {sent_version}"]
        lines += [f"{name}: {value}" for name, value in self.request_headers]
        return "\n".join(lines)

    def raw_response_head(self) -> str:
        lines = [f"{self.http_version} {self.status} {self.reason}".rstrip()]
        lines += [f"{name}: {value}" for name, value in self.response_headers]
        return "\n".join(lines)

    def to_evidence(self, matched: str | None = None, *, include_body: bool = True) -> Evidence:
        snippet = self.raw_response_head()
        if include_body and self.body_preview:
            snippet += "\n\n" + excerpt(self.body_preview, matched)
        return Evidence(request=self.raw_request(), response_snippet=snippet, matched=matched)


@dataclass(frozen=True)
class Response:
    url: httpx.URL
    status_code: int
    headers: httpx.Headers
    content: bytes
    text: str
    truncated: bool
    exchange: Exchange
    redirects: tuple[Exchange, ...] = ()  # earlier hops, oldest first


class HTTPClient:
    """One shared instance per scan. Use as an async context manager."""

    def __init__(
        self,
        config: ScanConfig,
        scope: ScopeManager,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        max_retries: int = 2,
        retry_backoff: float = 0.5,
        max_redirects: int = 5,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        self.scope = scope
        self.safe_mode = config.safe_mode
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes
        self.timeout = config.timeout
        self.proxy = config.proxy
        self.history: list[Exchange] = []
        self.raw_probes = 0  # non-HTTP probes (e.g. TLS handshakes) made through raw_slot()
        self._warned_raw_proxy = False
        self._ids = itertools.count(1)
        self._bucket = TokenBucket(config.rate)
        self._semaphore = asyncio.Semaphore(config.concurrency)

        extra: dict[str, Any] = {}
        if transport is not None:
            extra["transport"] = transport
        elif config.proxy:
            extra["proxy"] = config.proxy
        self._client = httpx.AsyncClient(
            http2=True,
            # Targets often have bad certs, and intercepting proxies re-sign TLS. Certificate
            # problems are reported by the TLS check, not allowed to block every other check.
            verify=False,
            timeout=config.timeout,
            headers={"User-Agent": config.user_agent, **config.headers},
            cookies=config.cookies,
            follow_redirects=False,
            **extra,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def requests_sent(self) -> int:
        return len(self.history) + self.raw_probes

    def cookie_names(self) -> list[str]:
        return [cookie.name for cookie in self._client.cookies.jar]

    @asynccontextmanager
    async def raw_slot(self, host: str, port: int, scheme: str = "https") -> AsyncIterator[None]:
        """Gate a non-HTTP connection (e.g. a raw TLS handshake) through scope + rate limits.

        The caller opens the connection inside the ``async with`` block.
        """
        url = httpx.URL(scheme=scheme, host=host, port=port, path="/")
        if not self.scope.check(url):
            raise OutOfScopeError(f"blocked out-of-scope connection to {host}:{port}")
        if self.proxy and not self._warned_raw_proxy:
            self._warned_raw_proxy = True
            logger.warning("raw TLS probes connect directly to the target, not via the proxy")
        await self._bucket.acquire()
        async with self._semaphore:
            self.raw_probes += 1
            logger.debug("raw %s connection to %s:%d", scheme, host, port)
            yield

    async def get(self, url: str | httpx.URL, **kwargs: Any) -> Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str | httpx.URL, **kwargs: Any) -> Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str | httpx.URL, **kwargs: Any) -> Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str | httpx.URL,
        *,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
        max_bytes: int | None = None,
        data: Mapping[str, str] | None = None,
        content: str | bytes | None = None,
        allow_unsafe: bool = False,
    ) -> Response:
        method = method.upper()
        if self.safe_mode and method not in SAFE_METHODS and not allow_unsafe:
            logger.warning("safe mode BLOCK %s %s (not sent)", method, url)
            raise UnsafeMethodError(f"{method} is not allowed in safe mode (needs --aggressive)")
        try:
            current = url if isinstance(url, httpx.URL) else httpx.URL(url)
        except httpx.InvalidURL as exc:
            raise HTTPClientError(f"invalid URL {url!r}: {exc}") from exc
        if not self.scope.check(current):
            raise OutOfScopeError(f"blocked out-of-scope request to {current}")

        hops: list[Exchange] = []
        for _ in range(self.max_redirects + 1):
            response = await self._send(method, current, headers, max_bytes, data, content)
            data = content = None  # a body belongs only to the first request, not a redirected GET
            location = response.headers.get("location")
            if (
                not follow_redirects
                or response.status_code not in REDIRECT_STATUSES
                or not location
            ):
                return replace(response, redirects=tuple(hops))
            try:
                next_url = current.join(location)
            except httpx.InvalidURL:
                return replace(response, redirects=tuple(hops))
            if not self.scope.check(next_url):
                logger.info("not following redirect from %s to out-of-scope %s", current, next_url)
                return replace(response, redirects=tuple(hops))
            hops.append(response.exchange)
            if response.status_code == 303 or (
                response.status_code in (301, 302) and method == "POST"
            ):
                method = "GET" if method != "HEAD" else method
            current = next_url
        raise HTTPClientError(f"more than {self.max_redirects} redirects starting at {url}")

    async def _send(
        self,
        method: str,
        url: httpx.URL,
        headers: Mapping[str, str] | None,
        max_bytes: int | None,
        data: Mapping[str, str] | None = None,
        content: str | bytes | None = None,
    ) -> Response:
        attempt = 0
        while True:
            await self._bucket.acquire()
            try:
                async with self._semaphore:
                    return await self._send_once(method, url, headers, max_bytes, data, content)
            except httpx.TransportError as exc:
                if attempt >= self.max_retries:
                    logger.info(
                        "%s %s failed after %d attempt(s): %r", method, url, attempt + 1, exc
                    )
                    raise HTTPClientError(
                        f"{method} {url} failed: {type(exc).__name__}: {exc}"
                    ) from exc
                attempt += 1
                logger.debug("retry %d for %s %s after %s", attempt, method, url, exc)
                await asyncio.sleep(self.retry_backoff * 2 ** (attempt - 1))

    async def _send_once(
        self,
        method: str,
        url: httpx.URL,
        headers: Mapping[str, str] | None,
        max_bytes: int | None,
        data: Mapping[str, str] | None = None,
        content: str | bytes | None = None,
    ) -> Response:
        request = self._client.build_request(
            method, url, headers=headers, data=data, content=content
        )
        started = time.perf_counter()
        raw = await self._client.send(request, stream=True)
        try:
            body, truncated = await self._read_capped(raw, max_bytes or self.max_body_bytes)
        finally:
            await raw.aclose()
        elapsed_ms = (time.perf_counter() - started) * 1000
        text = decode_body(body, raw.headers.get("content-type"))

        exchange = Exchange(
            id=next(self._ids),
            method=method,
            url=str(url),
            http_version=raw.http_version,
            request_headers=_raw_headers(request.headers),
            status=raw.status_code,
            reason=raw.reason_phrase,
            response_headers=_raw_headers(raw.headers),
            body_preview=text[:PREVIEW_CHARS],
            elapsed_ms=elapsed_ms,
        )
        self.history.append(exchange)
        logger.debug("%s %s -> %d (%.0f ms)", method, url, raw.status_code, elapsed_ms)
        return Response(
            url=url,
            status_code=raw.status_code,
            headers=raw.headers,
            content=body,
            text=text,
            truncated=truncated,
            exchange=exchange,
        )

    async def _read_capped(self, raw: httpx.Response, limit: int) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        async for chunk in raw.aiter_bytes():
            room = limit - size
            if len(chunk) > room:
                chunks.append(chunk[:room])
                return b"".join(chunks), True
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks), False


def _raw_headers(headers: httpx.Headers) -> tuple[tuple[str, str], ...]:
    """Headers with their on-the-wire casing, for faithful evidence."""
    return tuple((k.decode("latin-1"), v.decode("latin-1")) for k, v in headers.raw)


def decode_body(content: bytes, content_type: str | None) -> str:
    encoding = "utf-8"
    if content_type and (match := _CHARSET_RE.search(content_type)):
        with contextlib.suppress(LookupError):
            encoding = codecs.lookup(match.group(1)).name
    return content.decode(encoding, errors="replace")


def excerpt(body: str, needle: str | None, width: int = EVIDENCE_BODY_CHARS) -> str:
    """A window of ``body`` around ``needle`` (or its start if absent)."""
    if needle and (idx := body.find(needle)) >= 0:
        start = max(0, idx - width // 2)
        end = min(len(body), idx + len(needle) + width // 2)
    else:
        start, end = 0, min(len(body), width)
    return ("..." if start else "") + body[start:end] + ("..." if end < len(body) else "")
