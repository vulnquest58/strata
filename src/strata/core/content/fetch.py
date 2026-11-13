"""HTTP transport used by content engines, with an injectable protocol.

The default implementation uses only the standard library so the core keeps
running with zero third-party HTTP dependencies; tests inject an async stub.

ThrottledTransport adds per-host rate limiting and User-Agent rotation on top
of UrllibTransport; use it for any external scan to avoid bans.
"""

from __future__ import annotations

import asyncio
import itertools
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_DEFAULT_UA_POOL = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    ),
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "strata/0.2 (+https://github.com/vulnquest58/strata)",
]


@dataclass(frozen=True)
class FetchResponse:
    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes


@runtime_checkable
class HttpTransport(Protocol):
    async def get(
        self, url: str, *, timeout: float = 10.0, max_bytes: int = 2_000_000
    ) -> FetchResponse: ...


class UrllibTransport:
    """Stdlib HTTP client: follows redirects, returns error responses instead
    of raising for 4xx/5xx, and caps the body size."""

    def __init__(self, user_agent: str = DEFAULT_USER_AGENT):
        self._user_agent = user_agent

    async def get(
        self, url: str, *, timeout: float = 10.0, max_bytes: int = 2_000_000
    ) -> FetchResponse:
        return await asyncio.to_thread(self._get, url, timeout, max_bytes)

    def _get(self, url: str, timeout: float, max_bytes: int) -> FetchResponse:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self._user_agent,
                "Accept": "text/html,application/javascript,application/json,text/plain,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(max_bytes)
                return FetchResponse(
                    url=response.geturl() or url,
                    status=response.getcode(),
                    headers={
                        key.lower(): value for key, value in response.headers.items()
                    },
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(max_bytes) if exc.fp else b""
            return FetchResponse(
                url=exc.geturl() or url,
                status=exc.code,
                headers={key.lower(): value for key, value in (exc.headers or {}).items()},
                body=body,
            )


class ThrottledTransport:
    """Rate-limited transport with per-host delays and User-Agent rotation.

    Use this for external scans to avoid triggering WAF bans or rate limits.
    Per-host throttling is enforced globally across all concurrent coroutines.

    Args:
        per_host_delay: seconds to wait between requests to the same host.
        user_agents: pool of UA strings rotated per request (round-robin).
        proxy: optional HTTP/SOCKS5 proxy URL.
        max_retries: retry count on connection errors (not on 4xx/5xx).
    """

    def __init__(
        self,
        *,
        per_host_delay: float = 0.3,
        user_agents: list[str] | None = None,
        proxy: str | None = None,
        max_retries: int = 2,
    ) -> None:
        self._delay = per_host_delay
        self._ua_cycle = itertools.cycle(user_agents or _DEFAULT_UA_POOL)
        self._proxy = proxy
        self._max_retries = max_retries
        # host → last request time (epoch float); protected by an asyncio lock
        self._last: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def _next_ua(self) -> str:
        return next(self._ua_cycle)

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers: list[urllib.request.BaseHandler] = []
        if self._proxy:
            scheme = "https" if self._proxy.startswith("https") else "http"
            handlers.append(
                urllib.request.ProxyHandler({scheme: self._proxy, "http": self._proxy})
            )
        handlers.append(urllib.request.HTTPRedirectHandler())
        handlers.append(urllib.request.HTTPCookieProcessor())
        return urllib.request.build_opener(*handlers)

    async def _throttle(self, host: str) -> None:
        lock = self._locks[host]
        async with lock:
            elapsed = time.monotonic() - self._last[host]
            if elapsed < self._delay:
                await asyncio.sleep(self._delay - elapsed)
            self._last[host] = time.monotonic()

    async def get(
        self, url: str, *, timeout: float = 10.0, max_bytes: int = 2_000_000
    ) -> FetchResponse:
        host = urllib.parse.urlparse(url).hostname or url
        await self._throttle(host)
        ua = self._next_ua()
        for attempt in range(self._max_retries + 1):
            try:
                return await asyncio.to_thread(
                    self._get_sync, url, timeout, max_bytes, ua
                )
            except (urllib.error.URLError, OSError, TimeoutError):
                if attempt == self._max_retries:
                    # Return a synthetic 0-status response so callers don't crash
                    return FetchResponse(url=url, status=0, headers={}, body=b"")
                await asyncio.sleep(0.5 * (attempt + 1))
        return FetchResponse(url=url, status=0, headers={}, body=b"")

    def _get_sync(
        self, url: str, timeout: float, max_bytes: int, ua: str
    ) -> FetchResponse:
        opener = self._build_opener()
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": ua,
                "Accept": "text/html,application/javascript,application/json,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            },
        )
        try:
            with opener.open(req, timeout=timeout) as response:
                body = response.read(max_bytes)
                return FetchResponse(
                    url=response.geturl() or url,
                    status=response.getcode(),
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(max_bytes) if exc.fp else b""
            return FetchResponse(
                url=exc.geturl() or url,
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                body=body,
            )


def decode_body(response: FetchResponse) -> str:
    charset = "utf-8"
    content_type = response.headers.get("content-type", "")
    for part in content_type.split(";")[1:]:
        part = part.strip()
        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip().strip('"')
            break
    try:
        return response.body.decode(charset, errors="replace")
    except LookupError:
        return response.body.decode("utf-8", errors="replace")
