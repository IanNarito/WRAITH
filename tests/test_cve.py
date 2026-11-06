import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pytest_httpserver import HTTPServer

from tests.conftest import ConfigFactory
from wraith.cve import CveCorrelator, severity_from_cvss
from wraith.engine import Engine
from wraith.models import Severity


def nvd_payload(*cves: tuple[str, float | None]) -> dict[str, Any]:
    vulns = []
    for cve_id, score in cves:
        metrics: dict[str, Any] = {}
        if score is not None:
            metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "X"}}]}
        vulns.append(
            {
                "cve": {
                    "id": cve_id,
                    "published": "2021-01-01T00:00:00",
                    "descriptions": [{"lang": "en", "value": f"desc for {cve_id}"}],
                    "metrics": metrics,
                }
            }
        )
    return {"vulnerabilities": vulns}


def make_correlator(handler: Any, **kwargs: Any) -> CveCorrelator:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return CveCorrelator(client=client, now=lambda: 1000.0, **kwargs)


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (9.8, Severity.CRITICAL),
        (7.5, Severity.HIGH),
        (5.0, Severity.MEDIUM),
        (2.0, Severity.LOW),
        (0.0, Severity.INFO),
        (None, Severity.INFO),
    ],
)
def test_severity_from_cvss(score: float | None, severity: Severity) -> None:
    assert severity_from_cvss(score) is severity


async def test_correlate_parses_sorts_and_filters() -> None:
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(
            200, json=nvd_payload(("CVE-2021-1", 5.0), ("CVE-2021-2", 9.1), ("CVE-2021-3", None))
        )

    correlator = make_correlator(handler, min_cvss=4.0)
    matches = await correlator.correlate("nginx", "1.18.0", cpe="cpe:2.3:a:f5:nginx")
    await correlator.aclose()

    assert [m.cve_id for m in matches] == ["CVE-2021-2", "CVE-2021-1"]  # sorted by score, filtered
    assert matches[0].cvss_severity is Severity.CRITICAL
    assert matches[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2021-2"
    assert "virtualMatchString=cpe%3A2.3%3A" in str(seen[0])
    assert "1.18.0" in str(seen[0])


async def test_keyword_search_when_no_cpe() -> None:
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(200, json=nvd_payload(("CVE-2020-9", 8.0)))

    correlator = make_correlator(handler)
    matches = await correlator.correlate("CoolCMS", "2.1")
    await correlator.aclose()
    assert [m.cve_id for m in matches] == ["CVE-2020-9"]
    assert "keywordSearch=CoolCMS+2.1" in str(seen[0]).replace("%20", "+")


async def test_network_failure_returns_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    correlator = make_correlator(handler)
    assert await correlator.correlate("nginx", "1.0") == []
    await correlator.aclose()


async def test_disk_cache_avoids_second_request(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=nvd_payload(("CVE-2022-1", 7.0)))

    c1 = make_correlator(handler, cache_dir=tmp_path)
    await c1.correlate("nginx", "1.18.0")
    await c1.aclose()
    assert calls["n"] == 1
    assert list(tmp_path.glob("*.json"))

    c2 = make_correlator(handler, cache_dir=tmp_path)
    matches = await c2.correlate("nginx", "1.18.0")
    await c2.aclose()
    assert calls["n"] == 1  # served from cache
    assert [m.cve_id for m in matches] == ["CVE-2022-1"]


class StubCorrelator:
    """Duck-typed correlator for the integration test; never touches the network."""

    def __init__(self, matches: Any) -> None:
        self._matches = matches
        self.queries: list[tuple[str, str, str | None]] = []

    async def correlate(self, product: str, version: str, cpe: str | None = None) -> Any:
        self.queries.append((product, version, cpe))
        return self._matches

    async def aclose(self) -> None:
        pass


async def test_fingerprint_emits_cve_finding(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    from wraith.cve import CveMatch

    httpserver.expect_request("/").respond_with_data(
        "<html>hi</html>", content_type="text/html", headers={"Server": "nginx/1.18.0"}
    )
    stub = StubCorrelator(
        [
            CveMatch(
                "CVE-2021-23017", 9.8, Severity.CRITICAL, "resolver bug", "https://nvd/x", None
            ),
            CveMatch("CVE-2019-9511", 7.5, Severity.HIGH, "http2 dos", "https://nvd/y", None),
        ]
    )
    result = await Engine(
        make_config(checks=("tech_fingerprint",)),
        correlator=stub,  # type: ignore[arg-type]
    ).run()

    cve = next(f for f in result.findings if "known CVE" in f.title)
    assert cve.title == "nginx 1.18.0 has 2 known CVE(s)"
    assert cve.severity is Severity.CRITICAL
    assert cve.cvss == 9.8
    assert "CVE-2021-23017" in cve.description
    assert "https://nvd/x" in cve.references
    assert ("nginx", "1.18.0", "cpe:2.3:a:f5:nginx") in stub.queries


async def test_no_cve_findings_without_correlator(
    httpserver: HTTPServer, make_config: ConfigFactory
) -> None:
    httpserver.expect_request("/").respond_with_data(
        "<html>hi</html>", content_type="text/html", headers={"Server": "nginx/1.18.0"}
    )
    result = await Engine(make_config(checks=("tech_fingerprint",))).run()
    assert not any("known CVE" in f.title for f in result.findings)


def test_nvd_payload_shape_is_valid_json() -> None:
    assert json.loads(json.dumps(nvd_payload(("CVE-1", 5.0))))["vulnerabilities"]
