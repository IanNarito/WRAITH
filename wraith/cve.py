"""CVE correlation: match detected products/versions against the public NVD database.

This is opt-in (``--cve``) enrichment. It queries the NVD CVE API
(services.nvd.nist.gov), **not the target**: it therefore uses its own HTTP client and does
not pass through the scan's ScopeManager. Only the detected product name, version, and
(when known) CPE are sent. Results are cached on disk, so repeat scans are fast and work
offline, and any network failure degrades to "no CVE data" rather than failing the scan.

Findings produced from this data are version-based inferences (confidence PROBABLE): a listed
CVE may not apply to the target's exact build or configuration, and absence of results is not
proof the component is safe.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from wraith import __version__
from wraith.models import Severity

logger = logging.getLogger("wraith.cve")

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 7 * 24 * 3600
# NVD asks for <=5 requests / rolling 30s without a key, <=50 with one. Stay well under.
_DELAY_NO_KEY = 6.5
_DELAY_WITH_KEY = 0.8


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    cvss_score: float | None
    cvss_severity: Severity
    description: str
    url: str
    published: str | None

    def sort_key(self) -> tuple[float, str]:
        return (-(self.cvss_score or 0.0), self.cve_id)


def severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


class CveCorrelator:
    """Look up known CVEs for a product/version via NVD, with an on-disk cache."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        cache_dir: Path | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 20.0,
        max_results: int = 2000,
        min_cvss: float = 0.0,
        now: Any = time.time,
    ) -> None:
        self.api_key = api_key
        self.cache_dir = cache_dir
        self.min_cvss = min_cvss
        self.max_results = max_results
        self._now = now
        self._owns_client = client is None
        self._delay = _DELAY_WITH_KEY if api_key else _DELAY_NO_KEY
        self._last_request = 0.0
        self._lock = asyncio.Lock()
        headers = {"User-Agent": f"WRAITH/{__version__} (CVE correlation)"}
        if api_key:
            headers["apiKey"] = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout, headers=headers)
        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def correlate(self, product: str, version: str, cpe: str | None = None) -> list[CveMatch]:
        """CVEs affecting ``product`` ``version``. Empty list on no match or lookup failure."""
        if cpe:
            params = {"virtualMatchString": f"{cpe}:{version}", "resultsPerPage": "2000"}
            query_key = f"cpe:{cpe}:{version}"
        else:
            params = {"keywordSearch": f"{product} {version}", "resultsPerPage": "2000"}
            query_key = f"kw:{product}:{version}"

        payload = self._read_cache(query_key)
        if payload is None:
            payload = await self._fetch(params)
            if payload is None:
                return []
            self._write_cache(query_key, payload)
        matches = _parse(payload)
        matches = [m for m in matches if (m.cvss_score or 0.0) >= self.min_cvss]
        matches.sort(key=lambda m: m.sort_key())
        return matches

    async def _fetch(self, params: dict[str, str]) -> dict[str, Any] | None:
        async with self._lock:
            wait = self._delay - (self._now() - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                response = await self._client.get(NVD_ENDPOINT, params=params)
                self._last_request = self._now()
                response.raise_for_status()
                data: dict[str, Any] = response.json()
                return data
            except (httpx.HTTPError, ValueError) as exc:
                self._last_request = self._now()
                logger.warning("NVD lookup failed (%s); skipping CVE data for this query", exc)
                return None

    def _cache_path(self, query_key: str) -> Path | None:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256(query_key.encode("utf-8")).hexdigest()[:20]
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, query_key: str) -> dict[str, Any] | None:
        path = self._cache_path(query_key)
        if path is None or not path.exists():
            return None
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            if self._now() - cached.get("fetched_at", 0) > CACHE_TTL_SECONDS:
                return None
            payload: dict[str, Any] = cached["payload"]
            return payload
        except (OSError, ValueError, KeyError):
            return None

    def _write_cache(self, query_key: str, payload: dict[str, Any]) -> None:
        path = self._cache_path(query_key)
        if path is None:
            return
        try:
            path.write_text(
                json.dumps({"fetched_at": self._now(), "payload": payload}),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.debug("could not write CVE cache %s: %s", path, exc)


def _parse(payload: dict[str, Any]) -> list[CveMatch]:
    matches: list[CveMatch] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score = _cvss_score(cve.get("metrics", {}))
        matches.append(
            CveMatch(
                cve_id=cve_id,
                cvss_score=score,
                cvss_severity=severity_from_cvss(score),
                description=_english(cve.get("descriptions", [])),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published=cve.get("published"),
            )
        )
    return matches


def _cvss_score(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            if isinstance(score, int | float):
                return float(score)
    return None


def _english(descriptions: list[dict[str, Any]]) -> str:
    for desc in descriptions:
        if desc.get("lang") == "en":
            return str(desc.get("value", "")).strip()
    return str(descriptions[0].get("value", "")).strip() if descriptions else ""
