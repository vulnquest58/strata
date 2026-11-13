"""HTTP transport used by content engines, with an injectable protocol.

The default implementation uses only the standard library so the core keeps
running with zero third-party HTTP dependencies; tests inject an async stub.
"""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

DEFAULT_USER_AGENT = "strata/0.1 (+https://github.com/vulnquest58)"


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
