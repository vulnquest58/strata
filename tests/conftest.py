import pytest

from strata.core.content.fetch import FetchResponse
from strata.core.dns.resolver import NxDomain, Resolver


class StubTransport:
    """Programmable offline transport: mapping (host, rtype) -> values or error."""

    def __init__(self, table: dict[tuple[str, str], tuple[str, ...]]):
        self.table = table
        self.calls: list[tuple[str, str]] = []

    async def query(self, host: str, rtype: str) -> tuple[str, ...]:
        self.calls.append((host.lower(), rtype))
        entry = self.table.get((host.lower(), rtype))
        if entry is None:
            raise NxDomain(host)
        if isinstance(entry, Exception):
            raise entry
        return entry


class StubHttpTransport:
    """Programmable offline HTTP transport: URL -> FetchResponse or exception."""

    def __init__(self, routes: dict[str, FetchResponse | Exception] | None = None):
        self.routes = routes or {}
        self.calls: list[str] = []

    async def get(
        self, url: str, *, timeout: float = 10.0, max_bytes: int = 2_000_000
    ) -> FetchResponse:
        self.calls.append(url)
        entry = self.routes.get(url)
        if entry is None:
            return FetchResponse(url=url, status=404, headers={}, body=b"")
        if isinstance(entry, Exception):
            raise entry
        return entry


@pytest.fixture
def make_resolver():
    def _make(table: dict[tuple[str, str], tuple[str, ...]]) -> Resolver:
        return Resolver(StubTransport(table))

    return _make


@pytest.fixture
def stub_transport():
    return StubTransport


@pytest.fixture
def http_transport():
    return StubHttpTransport
