from strata.core.dns.wildcard import (
    WildcardBase,
    canary_labels,
    detect_wildcard,
    is_wildcard_hit,
)


class TestCanaryLabels:
    def test_deterministic_per_domain(self):
        assert canary_labels("example.com") == canary_labels("example.com")
        assert canary_labels("example.com") != canary_labels("example.org")

    def test_contains_domain(self):
        labels = canary_labels("example.com", n=3)
        assert len(labels) == 3
        assert all(label.endswith(".example.com") for label in labels)


class TestDetectWildcard:
    async def test_no_wildcard_when_canary_is_nxdomain(self, make_resolver):
        resolver = make_resolver({})
        assert await detect_wildcard(resolver, "example.com") is None

    async def test_wildcard_detected_with_ips(self, make_resolver):
        table = {}
        for label in canary_labels("example.com"):
            table[(label, "A")] = ("203.0.113.9",)
        resolver = make_resolver(table)
        base = await detect_wildcard(resolver, "example.com")
        assert isinstance(base, WildcardBase)
        assert base.ips == ("203.0.113.9",)

    async def test_one_non_resolving_canary_blocks(self, make_resolver):
        labels = canary_labels("example.com")
        table = {(labels[0], "A"): ("203.0.113.9",)}
        resolver = make_resolver(table)
        assert await detect_wildcard(resolver, "example.com") is None


class TestWildcardFiltering:
    def test_exact_match_is_hit(self):
        base = WildcardBase(domain="example.com", ips=("203.0.113.9",))
        assert is_wildcard_hit(base, ("203.0.113.9",))

    def test_partial_overlap_is_not_hit(self):
        base = WildcardBase(domain="example.com", ips=("203.0.113.9",))
        # a real host behind a wildcard zone may share one address
        assert not is_wildcard_hit(base, ("203.0.113.9", "198.51.100.1"))

    def test_no_base_means_no_hit(self):
        assert not is_wildcard_hit(None, ("203.0.113.9",))

    def test_empty_ips_not_a_hit(self):
        base = WildcardBase(domain="example.com", ips=("203.0.113.9",))
        assert not is_wildcard_hit(base, ())
