"""Shared fixtures. Tests only ever talk to the local pytest-httpserver or a MockTransport."""

from collections.abc import Callable
from typing import Any

import pytest
from pytest_httpserver import HTTPServer

from wraith.config import ScanConfig

ConfigFactory = Callable[..., ScanConfig]


@pytest.fixture
def make_config(httpserver: HTTPServer) -> ConfigFactory:
    """Build a ScanConfig pointed at the local fixture server, fast and in scope."""

    def _make(**overrides: Any) -> ScanConfig:
        values: dict[str, Any] = {
            "target": httpserver.url_for("/"),
            "scope": ("localhost",),
            "rate": 1000.0,
            "timeout": 5.0,
        }
        values.update(overrides)
        return ScanConfig(**values)

    return _make
