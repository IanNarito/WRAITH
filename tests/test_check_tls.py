import ssl
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from tests.conftest import ConfigFactory
from wraith.checks.tls_config import Handshake, _expiry_finding
from wraith.config import ScanConfig
from wraith.engine import Engine
from wraith.models import Severity

CERT = Path(__file__).parent / "fixtures" / "localhost-selfsigned.pem"


@pytest.fixture
def https_server() -> Iterator[HTTPServer]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT)
    server = HTTPServer(host="127.0.0.1", port=0, ssl_context=context)
    server.expect_request("/").respond_with_data("<html>tls</html>", content_type="text/html")
    server.start()
    try:
        yield server
    finally:
        server.clear()
        server.stop()


async def test_self_signed_certificate_is_reported(https_server: HTTPServer) -> None:
    config = ScanConfig(
        target=https_server.url_for("/"),
        scope=("127.0.0.1",),
        rate=1000.0,
        timeout=5.0,
        checks=("tls_config",),
    )
    result = await Engine(config).run()
    assert result.failures == ()
    titles = {f.title for f in result.findings}
    assert "Self-signed TLS certificate" in titles
    # A modern test server must not be flagged for legacy protocols or weak ciphers.
    assert not any("Deprecated protocol" in t or "Weak TLS cipher" in t for t in titles)
    cert = next(f for f in result.findings if f.title == "Self-signed TLS certificate")
    assert cert.evidence[0].request.startswith("TLS handshake to 127.0.0.1:")
    assert result.requests_sent >= 2  # the HTTP fetch plus at least one counted TLS probe


async def test_plain_http_target_is_reported(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data("<html>x</html>", content_type="text/html")
    result = await Engine(make_config(checks=("tls_config",))).run()
    assert [(f.title, f.severity) for f in result.findings] == [
        ("Site served over unencrypted HTTP", Severity.MEDIUM)
    ]


def _cert_expiring_in(days: float) -> Handshake:
    stamp = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + days * 86400))
    return Handshake(version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256", cert={"notAfter": stamp})


def test_expiry_warning_threshold() -> None:
    now = time.time()
    soon = _expiry_finding("https://a.test/", "a.test", 443, _cert_expiring_in(5), now)
    assert soon is not None and soon.title == "TLS certificate expires soon"
    assert _expiry_finding("https://a.test/", "a.test", 443, _cert_expiring_in(90), now) is None
