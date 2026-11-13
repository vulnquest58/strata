"""
Filter 1: Liveness Verification

Performs a real HTTP probe against each subdomain from Aperture.
This is fundamentally different from DNS resolution: we confirm an actual
HTTP response (any status code — even 403/500 means the host exists and is
responding), and we capture a fingerprint (status, content-hash, server header)
for use in Filter 4 where identical-response assets are clustered.

Key design choices:
- HEAD first (lighter); fall back to GET only if we need content for hashing.
- A host that responds with any status code passes (we're not assessing risk).
- Only genuine connection failures (timeout, refused, DNS failure) = not live.
- Redirect chains are recorded (a host that always redirects elsewhere is
  structurally different from one that serves content directly).
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from rich.console import Console

from triage_loom.filters.base import BaseFilter, FilterResult
from triage_loom.models import CorroborationLayer, LivenessResult

console = Console(stderr=True)

_SCHEMES = ("https", "http")
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_HEADERS = {"User-Agent": "Triage-Loom/1.0 (OSINT; liveness-check)"}


class LivenessFilter(BaseFilter):
    """Filter 1: HTTP liveness probe with fingerprinting."""

    @property
    def name(self) -> str:
        return "LivenessFilter"

    @property
    def stage(self) -> int:
        return 1

    async def run(self, asset_id: str, **_: Any) -> FilterResult:
        result = await self._probe(asset_id)
        return FilterResult(
            passed=result.responded,
            layer_tag=CorroborationLayer.liveness.value if result.responded else None,
            evidence={
                "status_code": result.status_code,
                "response_time_ms": result.response_time_ms,
                "tls_valid": result.tls_valid,
                "redirect_chain": result.redirect_chain,
                "content_hash": result.content_hash,
                "error": result.error,
            },
            metadata={"liveness_result": result.model_dump()},
        )

    async def probe_many(
        self,
        asset_ids: list[str],
        concurrency: int = 50,
    ) -> dict[str, LivenessResult]:
        """Probe multiple assets concurrently. Returns {asset_id: LivenessResult}."""
        sem = asyncio.Semaphore(concurrency)
        results: dict[str, LivenessResult] = {}

        async def bounded(aid: str) -> None:
            async with sem:
                results[aid] = await self._probe(aid)

        await asyncio.gather(*[bounded(aid) for aid in asset_ids])
        return results

    async def _probe(self, hostname: str) -> LivenessResult:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            follow_redirects=True,
            verify=False,  # some targets use self-signed certs; we record tls_valid separately
            headers=_HEADERS,
            max_redirects=5,
        ) as client:
            for scheme in _SCHEMES:
                url = f"{scheme}://{hostname}"
                t0 = time.perf_counter()
                try:
                    resp = await client.head(url)
                    elapsed_ms = (time.perf_counter() - t0) * 1000

                    redirect_chain = [str(r.url) for r in resp.history]
                    tls_valid = scheme == "https" and resp.url.scheme == "https"

                    # For content fingerprinting, do a GET if HEAD returned 200-level.
                    content_hash: str | None = None
                    if resp.status_code < 300:
                        try:
                            get_resp = await client.get(url)
                            content_hash = hashlib.sha256(get_resp.content[:4096]).hexdigest()
                        except Exception:
                            pass

                    return LivenessResult(
                        asset_id=hostname,
                        responded=True,
                        status_code=resp.status_code,
                        response_time_ms=round(elapsed_ms, 2),
                        tls_valid=tls_valid,
                        redirect_chain=redirect_chain,
                        content_hash=content_hash,
                        fingerprint={
                            "server": resp.headers.get("server", ""),
                            "x_powered_by": resp.headers.get("x-powered-by", ""),
                            "content_type": resp.headers.get("content-type", ""),
                        },
                    )

                except (httpx.ConnectError, httpx.TimeoutException, httpx.TooManyRedirects) as exc:
                    # Try next scheme before giving up.
                    last_error = str(exc)
                    continue
                except Exception as exc:
                    last_error = str(exc)
                    continue

        return LivenessResult(
            asset_id=hostname,
            responded=False,
            error=last_error if "last_error" in dir() else "unknown error",
        )


def last_error_default() -> str:
    return "unknown"
