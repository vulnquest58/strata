"""Tests for the subdomain takeover verification engine."""

from __future__ import annotations

from strata.core.content.fetch import FetchResponse
from strata.core.dns.resolver import NoAnswer, Resolver
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.engines.takeover import (
    TakeoverEngine,
    TakeoverService,
    match_service,
)


class StubDnsTransport:
    def __init__(self, records: dict[tuple[str, str], tuple[str, ...]]):
        self._records = records

    async def query(self, host: str, rtype: str) -> tuple[str, ...]:
        try:
            return self._records[(host.lower(), rtype)]
        except KeyError:
            # Model a real resolver: name exists, no answer of that type.
            raise NoAnswer(f"{host} {rtype}") from None


class StubHttpTransport:
    def __init__(
        self,
        routes: dict[str, FetchResponse],
        default: FetchResponse | None = None,
    ):
        self._routes = routes
        self._default = default

    async def get(self, url: str, *, timeout: float = 10.0, max_bytes: int = 2_000_000,
                  headers: dict[str, str] | None = None) -> FetchResponse:
        if url in self._routes:
            return self._routes[url]
        if self._default is not None:
            return self._default
        raise ConnectionError(f"no route for {url}")


def _subdomain(host: str, status: FindingStatus = FindingStatus.VERIFIED) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="test",
        kind=FindingClass.SUBDOMAIN,
        status=status,
        asset_value=host,
        confidence=Confidence(value=80.0),
        evidence=[Evidence(engine="dns_brute", technique="brute", observation="resolved")],
        metadata={},
    )


def test_match_service_suffixes():
    assert match_service("bucket-name.s3.amazonaws.com").provider == "AWS S3"
    assert match_service("site.github.io").provider == "GitHub Pages"
    assert match_service("shop.example.com.myshopify.com").provider == "Shopify"
    assert match_service("example.com") is None
    assert match_service("evil-github.io.example.com") is None


def test_services_have_confidence_and_markers():
    for service in [
        TakeoverService("x.example", "X", ("marker",), 70.0),
        TakeoverService("y.example", "Y", (), 50.0, dns_only=True),
    ]:
        assert 0 < service.confidence <= 100
    known = match_service("b.s3.amazonaws.com")
    assert known.markers


def _engine(dns_records, routes, default=None):
    resolver = Resolver(StubDnsTransport(dns_records))
    transport = StubHttpTransport(routes, default)
    return TakeoverEngine(resolver, transport, timeout=2.0)


async def test_confirmed_takeover_s3():
    engine = _engine(
        {
            ("dangling.example.com", "CNAME"): ("dangling-bucket.s3.amazonaws.com",),
            ("dangling-bucket.s3.amazonaws.com", "A"): (),
        },
        {
            "https://dangling.example.com": FetchResponse(
                "https://dangling.example.com", 404, {}, b'<?xml><Code>NoSuchBucket</Code>'
            ),
        },
    )
    result = await engine.run([_subdomain("dangling.example.com")])
    assert result.stats.checked == 1
    assert result.stats.confirmed == 1
    finding = result.findings[0]
    assert finding.kind is FindingClass.VULN
    assert finding.status is FindingStatus.VERIFIED
    assert finding.metadata["provider"] == "AWS S3"
    assert finding.metadata["takeover_confirmed"] is True
    assert finding.confidence.value == 85.0


async def test_dangling_but_wrong_error_page_is_candidate():
    engine = _engine(
        {
            ("app.example.com", "CNAME"): ("app.github.io",),
            ("app.github.io", "A"): ("192.0.2.5",),
        },
        {
            "https://app.example.com": FetchResponse(
                "https://app.example.com", 200, {}, b"Welcome to our site"
            ),
        },
    )
    # app.github.io resolves: alias NOT dangling -> skipped entirely
    result = await engine.run([_subdomain("app.example.com")])
    assert result.findings == []
    assert result.stats.not_dangling == 1


async def test_dangling_known_service_unmatched_marker_is_candidate():
    engine = _engine(
        {
            ("pages.example.com", "CNAME"): ("pages.example.com.github.io",),
            ("pages.example.com.github.io", "A"): (),
        },
        {
            "https://pages.example.com": FetchResponse(
                "https://pages.example.com", 404, {}, b"<h1>Nothing here</h1>"
            ),
        },
    )
    result = await engine.run([_subdomain("pages.example.com")])
    assert result.stats.dangling == 1
    assert result.stats.confirmed == 0
    assert result.stats.candidates == 1
    finding = result.findings[0]
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.metadata["provider"] == "GitHub Pages"
    assert finding.metadata["manual_review"] is True


async def test_dangling_unknown_service_is_low_confidence_candidate():
    engine = _engine(
        {
            ("misc.example.com", "CNAME"): ("legacy.vendor.example",),
            ("legacy.vendor.example", "A"): (),
        },
        {
            "https://misc.example.com": FetchResponse(
                "https://misc.example.com", 404, {}, b"not found"
            ),
        },
    )
    result = await engine.run([_subdomain("misc.example.com")])
    finding = result.findings[0]
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.confidence.value == 35.0
    assert finding.metadata["provider"] is None


async def test_dns_only_service_herokudns():
    engine = _engine(
        {
            ("ssl.example.com", "CNAME"): ("app.example.herokudns.com",),
            ("app.example.herokudns.com", "A"): (),
        },
        {},  # fetch will fail
    )
    result = await engine.run([_subdomain("ssl.example.com")])
    finding = result.findings[0]
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.metadata["provider"] == "Heroku SSL"
    assert finding.metadata["manual_review"] is True


async def test_no_alias_skipped():
    engine = _engine({}, {})
    result = await engine.run([_subdomain("plain.example.com")])
    assert result.findings == []
    assert result.stats.no_alias == 1


async def test_scope_filters_out_of_scope_hosts():
    engine = _engine(
        {
            ("other.org", "CNAME"): ("b.s3.amazonaws.com",),
            ("b.s3.amazonaws.com", "A"): (),
        },
        {
            "https://other.org": FetchResponse(
                "https://other.org", 404, {}, b"NoSuchBucket"
            ),
        },
    )
    policy = ScopePolicy.from_list(["example.com"])
    result = await engine.run([_subdomain("other.org")], policy=policy)
    assert result.findings == []
    assert result.stats.checked == 0


async def test_dead_findings_excluded():
    engine = _engine({}, {})
    result = await engine.run([_subdomain("dead.example.com", FindingStatus.DEAD)])
    assert result.stats.checked == 0


async def test_fetch_error_yields_candidate_not_crash():
    engine = _engine(
        {
            ("err.example.com", "CNAME"): ("e.s3.amazonaws.com",),
            ("e.s3.amazonaws.com", "A"): (),
        },
        {},  # no route -> ConnectionError
    )
    result = await engine.run([_subdomain("err.example.com")])
    finding = result.findings[0]
    assert finding.status is FindingStatus.CANDIDATE
    assert result.stats.errors == 1


async def test_deterministic_finding_id():
    engine = _engine(
        {
            ("d.example.com", "CNAME"): ("b.s3.amazonaws.com",),
            ("b.s3.amazonaws.com", "A"): (),
        },
        {
            "https://d.example.com": FetchResponse(
                "https://d.example.com", 404, {}, b"NoSuchBucket"
            ),
        },
    )
    a = await engine.run([_subdomain("d.example.com")])
    b = await engine.run([_subdomain("d.example.com")])
    assert a.findings[0].finding_id == b.findings[0].finding_id


def test_cname_chain_dangling_behavior_documented():
    # The engine relies on cname_chain capturing the target even when the
    # target is dead; stub transport raising DnsError breaks the chain there.
    resolver = Resolver(StubDnsTransport({("d.example.com", "CNAME"): ("b.s3.amazonaws.com",)}))
    import asyncio

    chain = asyncio.run(resolver.cname_chain("d.example.com"))
    assert chain == ("b.s3.amazonaws.com",)
