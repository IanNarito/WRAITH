"""Shared fixtures. Tests only ever talk to the local pytest-httpserver or a MockTransport."""

from collections.abc import Callable
from typing import Any

import pytest
from pytest_httpserver import HTTPServer

from wraith.config import ScanConfig
from wraith.context import Page
from wraith.http_client import Exchange

ConfigFactory = Callable[..., ScanConfig]


@pytest.fixture(scope="session")
def httpserver_listen_address() -> tuple[str, int]:
    # An IP avoids slow localhost -> ::1 fallbacks on Windows for every new connection.
    return ("127.0.0.1", 0)


@pytest.fixture
def make_config(httpserver: HTTPServer) -> ConfigFactory:
    """Build a ScanConfig pointed at the local fixture server, fast and in scope."""

    def _make(**overrides: Any) -> ScanConfig:
        values: dict[str, Any] = {
            "target": httpserver.url_for("/"),
            "scope": ("127.0.0.1",),
            "rate": 1000.0,
            "timeout": 5.0,
        }
        values.update(overrides)
        return ScanConfig(**values)

    return _make


def make_page(
    headers: dict[str, str],
    *,
    url: str = "https://app.test/",
    body: str = "<html><body>hi</body></html>",
    content_type: str = "text/html; charset=utf-8",
    status: int = 200,
    extra: tuple[tuple[str, str], ...] = (),
) -> Page:
    """A Page as discovery would build it, for pure unit tests of checks."""
    all_headers = (("Content-Type", content_type), *headers.items(), *extra)
    exchange = Exchange(
        id=1,
        method="GET",
        url=url,
        http_version="HTTP/1.1",
        request_headers=(("Host", "app.test"),),
        status=status,
        reason="OK",
        response_headers=all_headers,
        body_preview=body,
        elapsed_ms=1.0,
    )
    return Page(url=url, status=status, headers=all_headers, body=body, exchange=exchange)
