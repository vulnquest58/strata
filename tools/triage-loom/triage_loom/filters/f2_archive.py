"""
Filter 2: Archive Cross-Reference

The golden rule: an endpoint is only considered "archive-confirmed" if it
appears in at least 2 independent archive sources (Wayback Machine, Common Crawl,
URLScan.io). Endpoints confirmed by only 1 source go to low_confidence.

Why 3 independent archives and not 1:
- Wayback Machine may not crawl a URL that CommonCrawl has, and vice-versa.
- URLScan is actively driven by security researchers — it finds endpoints
  that automated crawlers miss.
- Requiring corroboration from 2-of-3 eliminates sources that happened to
  crawl a transient page (e.g., a temporary redirect or a maintenance page).

API Design:
- Wayback Machine: CDX API (free, no key)
- Common Crawl: Index API (free, no key; needs latest index ID fetched first)
- URLScan.io: Search API (free, no key; rate-limited)
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus

import httpx
from rich.console import Console

from triage_loom.filters.base import BaseFilter, FilterResult
from triage_loom.models import ArchiveRecord, ArchiveSource, CorroborationLayer

logger = logging.getLogger(__name__)
console = Console(stderr=True)

ARCHIVE_SOURCES = ["wayback", "commoncrawl", "urlscan"]
MAX_RETRIES = 1
RETRY_DELAY_SECONDS = 7

_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_HEADERS = {"User-Agent": "Triage-Loom/1.0 (OSINT; archive-lookup)"}


class ArchiveCrossReferenceFilter(BaseFilter):
    """
    Filter 2: Cross-reference URLs against Wayback Machine, Common Crawl, and URLScan.
    Requires 2-of-3 sources to confirm a URL for high_confidence classification.
    """

    @property
    def name(self) -> str:
        return "ArchiveCrossReferenceFilter"

    @property
    def stage(self) -> int:
        return 2

    async def _query_with_retry(self, query_fn, *args) -> tuple[set[str], bool]:
        """يُرجع (النتائج، نجح_أم_لا)."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                result = await query_fn(*args)
                return result, True
            except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                    continue
                logger.warning(f"Archive source failed after retry: {e}")
                return set(), False
            except Exception as e:
                logger.warning(f"Archive source failed: {e}")
                return set(), False
        return set(), False

    async def run(self, asset_id: str, root_domain: str = "", **_: Any) -> FilterResult:
        """Check a single subdomain against all 3 archive sources."""
        domain = root_domain or asset_id
        records, failed_sources = await self.cross_reference(domain)

        # Find which sources confirmed this asset.
        confirmed_sources: list[str] = []
        if records.get("wayback"):
            confirmed_sources.append(CorroborationLayer.archive_wayback.value)
        if records.get("commoncrawl"):
            confirmed_sources.append(CorroborationLayer.archive_commoncrawl.value)
        if records.get("urlscan"):
            confirmed_sources.append(CorroborationLayer.archive_urlscan.value)

        passed = len(confirmed_sources) >= 2

        return FilterResult(
            passed=passed,
            layer_tag=confirmed_sources[0] if confirmed_sources else None,
            evidence={
                "confirmed_by": confirmed_sources,
                "url_count": {src: len(urls) for src, urls in records.items()},
                "failed_sources": failed_sources,
            },
            metadata={"archive_records": {src: list(urls) for src, urls in records.items()}},
        )

    async def cross_reference(self, root_domain: str) -> tuple[dict[str, set[str]], list[str]]:
        """
        Query all 3 archive sources with retry.
        Returns (results_by_source, failed_sources).
        A source that fails returns an empty set — failure of one source
        does NOT prevent corroboration from the remaining two.
        """
        failed_sources: list[str] = []
        results: dict[str, set[str]] = {}

        tasks = [
            ("wayback", self._query_with_retry(self._query_wayback, root_domain)),
            ("commoncrawl", self._query_with_retry(self._query_commoncrawl, root_domain)),
            ("urlscan", self._query_with_retry(self._query_urlscan, root_domain)),
        ]
        gathered = await asyncio.gather(*(t[1] for t in tasks))

        for (name, _), (urls, ok) in zip(tasks, gathered):
            results[name] = urls
            if not ok:
                failed_sources.append(name)

        return results, failed_sources

    # ------------------------------------------------------------------
    # Wayback Machine CDX API
    # ------------------------------------------------------------------

    async def _query_wayback(self, domain: str) -> set[str]:
        """
        Query the Wayback Machine CDX API for URLs under the given domain.
        CDX API: http://web.archive.org/cdx/search/cdx
        """
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "10000",
            "filter": "statuscode:200",
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get("http://web.archive.org/cdx/search/cdx", params=params)
            resp.raise_for_status()
            data = resp.json()
            # data is [[header], [url1], [url2], ...]
            if not data or len(data) < 2:
                return set()
            # Skip the header row.
            return {row[0] for row in data[1:] if row}

    # ------------------------------------------------------------------
    # Common Crawl Index API
    # ------------------------------------------------------------------

    async def _query_commoncrawl(self, domain: str) -> set[str]:
        """
        Query the Common Crawl Index API for URLs under the given domain.
        First fetches the latest available index, then queries it.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            # Step 1: fetch available indexes.
            index_resp = await client.get("https://index.commoncrawl.org/collinfo.json")
            index_resp.raise_for_status()
            indexes = index_resp.json()
            if not indexes:
                return set()
            # Use the most recent index.
            latest_index = indexes[0]["cdx-api"]

            # Step 2: query the latest index.
            params = {
                "url": f"*.{domain}",
                "output": "json",
                "fl": "url",
                "limit": "5000",
                "filter": "=status:200",
            }
            resp = await client.get(latest_index, params=params)
            resp.raise_for_status()

            urls: set[str] = set()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "url" in obj:
                        urls.add(obj["url"])
                except json.JSONDecodeError:
                    continue
            return urls

    # ------------------------------------------------------------------
    # URLScan.io
    # ------------------------------------------------------------------

    async def _query_urlscan(self, domain: str) -> set[str]:
        """
        Query URLScan.io for pages scanned under the given domain.
        No API key required for public data (rate limit: ~10 req/min).
        """
        params = {
            "q": f"domain:{domain}",
            "size": "1000",
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get("https://urlscan.io/api/v1/search/", params=params)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            return {
                r["page"]["url"]
                for r in results
                if "page" in r and "url" in r["page"]
            }

    def corroboration_count(self, url: str, results: dict[ArchiveSource, set[str]]) -> int:
        """Count how many independent sources confirmed this specific URL."""
        return sum(1 for source_urls in results.values() if url in source_urls)
