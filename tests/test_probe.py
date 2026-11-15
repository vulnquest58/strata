import pytest

from strata.core.content.fetch import FetchResponse
from strata.core.schedule import select_probes
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.engines.probe_engine import ProbeEngine


def _finding(
    asset: str,
    *,
    kind: FindingClass = FindingClass.ENDPOINT,
    status: FindingStatus = FindingStatus.CANDIDATE,
    confidence: float = 50.0,
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="r1",
        kind=kind,
        status=status,
        asset_value=asset,
        confidence=Confidence(value=confidence),
        evidence=[Evidence(engine="content_crawl", technique="extract")],
    )


def _endpoint(url: str, confidence: float, status: FindingStatus = FindingStatus.CANDIDATE):
    return _finding(url, kind=FindingClass.ENDPOINT, status=status, confidence=confidence)


class TestSelectProbes:
    def test_budget_is_distributed_across_kinds_not_hogged(self):
        findings = [_endpoint(f"https://x.com/{i}", 50.0) for i in range(100)]
        findings += [
            _finding(
                f"h{i}.example.com",
                kind=FindingClass.SUBDOMAIN,
                confidence=50.0,
            )
            for i in range(10)
        ]
        ranked = select_probes(findings, budget=20)
        kinds = {finding.kind for finding, _ in ranked}
        assert kinds == {FindingClass.ENDPOINT, FindingClass.SUBDOMAIN}
        # endpoint count is ~10x subdomain count but gets only ~3x probes
        endpoints = sum(1 for f, _ in ranked if f.kind is FindingClass.ENDPOINT)
        subdomains = sum(1 for f, _ in ranked if f.kind is FindingClass.SUBDOMAIN)
        assert endpoints < endpoints_expected_upper(subdomains)

    def test_uncertain_claims_are_probed_first_within_kind(self):
        findings = [
            _endpoint("https://x.com/certain", 95.0),
            _endpoint("https://x.com/unsure", 50.0),
            _endpoint("https://x.com/hopeless", 5.0),
        ]
        ranked = select_probes(findings, budget=1)
        assert ranked[0][0].asset_value == "https://x.com/unsure"

    def test_verified_and_dead_never_selected(self):
        findings = [
            _endpoint("https://x.com/v", 50.0, FindingStatus.VERIFIED),
            _endpoint("https://x.com/d", 50.0, FindingStatus.DEAD),
        ]
        assert select_probes(findings, budget=10) == []

    def test_zero_budget_selects_nothing(self):
        findings = [_endpoint("https://x.com/a", 50.0)]
        assert select_probes(findings, budget=0) == []

    def test_small_kind_not_starved_to_zero(self):
        findings = [_endpoint(f"https://x.com/{i}", 50.0) for i in range(200)]
        findings += [_finding("h.example.com", kind=FindingClass.SUBDOMAIN, confidence=50.0)]
        ranked = select_probes(findings, budget=10)
        kinds = {finding.kind for finding, _ in ranked}
        assert FindingClass.SUBDOMAIN in kinds


def endpoints_expected_upper(subdomains: int) -> int:
    # ~sqrt ratio means endpoints should be at most ~4x subdomains for a 10:1 pool
    return max(subdomains * 4, subdomains + 1)


class _StubTransport:
    """Default response is the host's 404 page; specific URLs override."""

    NOT_FOUND = (
        "<html><head><title>Page Not Found - Example Corp</title></head>"
        "<body><h1>404 - Page Not Found</h1>"
        "<p>The page you requested does not exist. Return <a href='/'>home</a>.</p>"
        "<footer>Example Corp 2026 legal privacy contact</footer></body></html>"
    )

    def __init__(self, bodies: dict[str, tuple[int, str]] | None = None):
        self.bodies = bodies or {}
        self.default_status = 404
        self.default_body = self.NOT_FOUND

    async def get(self, url, *, timeout=10.0, max_bytes=2_000_000):
        status, body = self.bodies.get(
            url, (self.default_status, self.default_body)
        )
        return FetchResponse(
            url=url,
            status=status,
            headers={"content-type": "text/html"},
            body=body.encode(),
        )


@pytest.mark.asyncio
async def test_probe_engine_verifies_live_kills_soft404():
    transport = _StubTransport(
        {
            "https://example.com/real": (200, "genuine application dashboard content"),
            "https://example.com/ghost": (200, _StubTransport.NOT_FOUND),
        }
    )
    engine = ProbeEngine(transport, max_probe=10)
    findings = [
        _endpoint("https://example.com/real", 50.0),
        _endpoint("https://example.com/ghost", 50.0),
    ]
    result = await engine.run(findings)
    by_asset = {f.asset_value: f for f in result.findings}
    assert by_asset["https://example.com/real"].status is FindingStatus.VERIFIED
    assert by_asset["https://example.com/ghost"].status is FindingStatus.DEAD
    assert by_asset["https://example.com/ghost"].metadata.get("soft404") is True
    assert result.stats.probed == 2
    assert result.stats.baselines >= 1


@pytest.mark.asyncio
async def test_probe_engine_status_404_kills_even_without_soft404():
    transport = _StubTransport(
        {"https://example.com/gone": (404, "gone for good")}
    )
    engine = ProbeEngine(transport, max_probe=5)
    findings = [_endpoint("https://example.com/gone", 50.0)]
    result = await engine.run(findings)
    assert result.findings[0].status is FindingStatus.DEAD
    assert result.stats.dead == 1


@pytest.mark.asyncio
async def test_probe_engine_out_of_scope_skipped():
    from strata.core.policy.scope import ScopePolicy

    engine = ProbeEngine(_StubTransport({}), max_probe=5)
    findings = [_endpoint("https://evil.com/steal", 50.0)]
    result = await engine.run(
        findings, policy=ScopePolicy.from_list(["example.com"])
    )
    assert result.stats.out_of_scope == 1
    assert result.stats.probed == 0


@pytest.mark.asyncio
async def test_probe_engine_stamps_prior_confidence_for_ledger():
    transport = _StubTransport({"https://example.com/a": (200, "app")})
    engine = ProbeEngine(transport, max_probe=5)
    findings = [_endpoint("https://example.com/a", 50.0)]
    result = await engine.run(findings)
    finding = result.findings[0]
    assert finding.metadata["prior_confidence"] == 50.0
    assert finding.metadata["probe_status"] == 200
