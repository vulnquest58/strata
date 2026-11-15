import pytest
from conftest import StubTransport

from strata.core.dns.resolver import Resolver
from strata.core.dns.wildcard import canary_labels
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import FindingClass, FindingStatus
from strata.engines.dns_brute import DnsDiscoveryEngine, order_words


class FakeScope(ScopePolicy):
    def __init__(self) -> None:
        super().__init__(allowed=())

    def allows_domain(self, domain: str) -> bool:
        return True


def table_for(domain: str, live_words: dict[str, tuple[str, ...]]) -> dict:
    table: dict = {}
    for label in canary_labels(domain):
        table[(label, "A")] = ("203.0.113.7",)  # wildcard base
    for word, ips in live_words.items():
        host = f"{word}.{domain}"
        table[(host, "A")] = ips
        table[(host, "AAAA")] = ()
        table[(host, "CNAME")] = ()
    return table


def _engine(table, **kwargs):
    return DnsDiscoveryEngine(
        resolver=Resolver(table and StubTransport(table) or StubTransport({})),
        policy=FakeScope(),
        **kwargs,
    )


class TimeoutTransport(StubTransport):
    async def query(self, host, qtype, timeout=None):  # type: ignore[override]
        raise TimeoutError("slow")


class WildcardTransport(StubTransport):
    """A real wildcard: every name under the zone resolves to one IP."""

    def __init__(self, ip: tuple[str, ...]) -> None:
        super().__init__({})
        self._ip = ip

    async def query(self, host, qtype, timeout=None):  # type: ignore[override]
        if qtype == "A":
            return self._ip
        return ()


def test_order_words_priors_measured_words_first() -> None:
    ordered = order_words(
        ("alpha", "beta", "gamma", "delta"),
        {"beta": 0.4, "alpha": 0.8},
    )
    assert ordered == ("alpha", "beta", "gamma", "delta")


def test_order_words_is_deterministic_without_history() -> None:
    words = ("beta", "alpha", "gamma")
    assert order_words(words, None) == words
    assert order_words(words, {}) == words


class TestDeadRecording:
    @pytest.fixture
    def engine(self):
        table = table_for("example.com", {"api": ("192.0.2.1",)})
        return DnsDiscoveryEngine(
            resolver=Resolver(StubTransport(table)),
            policy=FakeScope(),
            wordlist="base",
            mutate=False,
        )

    async def test_nxdomain_words_become_dead_findings(self, engine):
        result = await engine.run("example.com")
        dead_assets = {f.asset_value for f in result.dead_findings}
        assert "api.example.com" not in dead_assets
        assert len(dead_assets) >= 1
        assert "mail.example.com" in dead_assets or any(
            ".example.com" in asset for asset in dead_assets
        )
        for finding in result.dead_findings:
            assert finding.status is FindingStatus.DEAD
            assert finding.kind is FindingClass.SUBDOMAIN
            assert finding.confidence.value == 15.0
            assert finding.evidence[0].engine == "dns_resolve"
            assert finding.evidence[0].technique == "a_probe"
        assert result.stats.recorded_dead == len(result.dead_findings)

    async def test_word_stats_track_attempts_and_hits(self, engine):
        result = await engine.run("example.com")
        api = result.word_stats["api"]
        assert api["attempts"] >= 1
        assert api["successes"] >= 1
        for _word, entry in result.word_stats.items():
            assert entry["successes"] <= entry["attempts"]

    async def test_timeouts_are_not_recorded_dead(self):
        table = table_for("example.com", {"api": ("192.0.2.1",)})
        engine = DnsDiscoveryEngine(
            resolver=Resolver(StubTransport(table)),
            policy=FakeScope(),
            wordlist="base",
            mutate=False,
        )
        result = await engine.run("example.com")
        # baseline: transport answers everything
        assert result.stats.recorded_dead >= 0

        timeout_engine = DnsDiscoveryEngine(
            resolver=Resolver(TimeoutTransport(table)),
            policy=FakeScope(),
            wordlist="base",
            mutate=False,
        )
        timeout_result = await timeout_engine.run("example.com")
        assert timeout_result.findings == []
        assert timeout_result.stats.recorded_dead == 0
        assert timeout_result.stats.candidates_tested > 0

    async def test_wildcard_hits_are_filtered_not_dead(self):
        engine = DnsDiscoveryEngine(
            resolver=Resolver(WildcardTransport(("203.0.113.7",))),
            policy=FakeScope(),
            wordlist="base",
            mutate=False,
        )
        result = await engine.run("example.com")
        assert result.findings == []
        assert result.stats.wildcard_filtered == result.stats.candidates_tested
        assert result.stats.candidates_tested >= 100
        assert result.stats.recorded_dead == 0
