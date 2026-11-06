import time

import httpx
import pytest

from wraith.config import ScanConfig
from wraith.http_client import (
    HTTPClient,
    HTTPClientError,
    OutOfScopeError,
    TokenBucket,
    UnsafeMethodError,
)
from wraith.scope import ScopeManager


class Recorder:
    """MockTransport handler that records every request that actually goes out."""

    def __init__(self) -> None:
        self.seen: list[str] = []
        self.fail_times = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(f"{request.method} {request.url}")
        if self.fail_times:
            self.fail_times -= 1
            raise httpx.ConnectError("boom", request=request)
        path = request.url.path
        if path == "/to-outside":
            return httpx.Response(302, headers={"Location": "http://out.test/"})
        if path == "/to-inside":
            return httpx.Response(301, headers={"Location": "/final"})
        if path == "/big":
            return httpx.Response(200, content=b"x" * 5000)
        return httpx.Response(200, text="hello world", headers={"Server": "test"})


def make_client(recorder: Recorder, **overrides: object) -> HTTPClient:
    values: dict[str, object] = {"target": "http://in.test/", "scope": ("in.test",), "rate": 1000.0}
    values.update(overrides)
    config = ScanConfig(**values)  # type: ignore[arg-type]
    return HTTPClient(
        config,
        ScopeManager(config.scope),
        transport=httpx.MockTransport(recorder),
        retry_backoff=0,
        max_body_bytes=1000,
    )


async def test_out_of_scope_request_is_never_sent() -> None:
    rec = Recorder()
    async with make_client(rec) as http:
        with pytest.raises(OutOfScopeError):
            await http.get("http://out.test/")
        assert http.scope.blocked == {"http://out.test/"}
    assert rec.seen == []


async def test_safe_mode_blocks_mutating_methods() -> None:
    rec = Recorder()
    async with make_client(rec) as http:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with pytest.raises(UnsafeMethodError):
                await http.request(method, "http://in.test/")
    assert rec.seen == []


async def test_aggressive_mode_allows_post() -> None:
    rec = Recorder()
    async with make_client(rec, safe_mode=False) as http:
        await http.request("POST", "http://in.test/")
    assert rec.seen == ["POST http://in.test/"]


async def test_redirect_to_out_of_scope_is_not_followed() -> None:
    rec = Recorder()
    async with make_client(rec) as http:
        response = await http.get("http://in.test/to-outside")
    assert response.status_code == 302
    assert rec.seen == ["GET http://in.test/to-outside"]


async def test_in_scope_redirect_is_followed_and_recorded() -> None:
    rec = Recorder()
    async with make_client(rec) as http:
        response = await http.get("http://in.test/to-inside")
        assert response.status_code == 200
        assert str(response.url) == "http://in.test/final"
        assert [hop.status for hop in response.redirects] == [301]
        assert http.requests_sent == 2


async def test_evidence_contains_raw_request_and_response() -> None:
    rec = Recorder()
    async with make_client(rec, headers={"X-Engagement": "ACME-42"}) as http:
        response = await http.get("http://in.test/page?q=1")
    evidence = response.exchange.to_evidence("world")
    assert evidence.request.startswith("GET /page?q=1 HTTP/1.1")
    assert "X-Engagement: ACME-42" in evidence.request
    assert "User-Agent: WRAITH" in evidence.request
    assert evidence.response_snippet.startswith("HTTP/1.1 200 OK")
    assert "server: test" in evidence.response_snippet.lower()
    assert "hello world" in evidence.response_snippet


async def test_body_is_capped() -> None:
    rec = Recorder()
    async with make_client(rec) as http:
        response = await http.get("http://in.test/big")
    assert response.truncated
    assert len(response.content) == 1000


async def test_transport_errors_are_retried_then_raised() -> None:
    rec = Recorder()
    rec.fail_times = 2
    async with make_client(rec) as http:
        response = await http.get("http://in.test/")
        assert response.status_code == 200
        assert len(rec.seen) == 3

        rec.fail_times = 10
        with pytest.raises(HTTPClientError):
            await http.get("http://in.test/")


async def test_token_bucket_spaces_requests() -> None:
    bucket = TokenBucket(rate=20)  # one token every 50 ms, no burst
    start = time.perf_counter()
    for _ in range(5):
        await bucket.acquire()
    assert time.perf_counter() - start >= 0.18
