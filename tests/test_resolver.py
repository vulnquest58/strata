import pytest

from strata.core.dns.resolver import (
    DnsError,
    NoAnswer,
    NxDomain,
    ResolvedHost,
    Resolver,
)


class TestResolver:
    async def test_resolve_full(self, make_resolver):
        resolver = make_resolver(
            {
                ("api.example.com", "A"): ("192.0.2.1", "192.0.2.2"),
                ("api.example.com", "AAAA"): ("2001:db8::1",),
                ("api.example.com", "CNAME"): ("edge.example.com",),
                ("edge.example.com", "A"): ("192.0.2.9",),
                ("edge.example.com", "AAAA"): (),
                ("edge.example.com", "CNAME"): (),
            }
        )
        host = await resolver.resolve("api.example.com")
        assert isinstance(host, ResolvedHost)
        assert host.a == ("192.0.2.1", "192.0.2.2")
        assert host.aaaa == ("2001:db8::1",)
        assert host.cname == "edge.example.com"
        assert host.ips == ("192.0.2.1", "192.0.2.2", "2001:db8::1")

    async def test_resolve_nxdomain_returns_none(self, make_resolver):
        resolver = make_resolver({})
        assert await resolver.resolve("missing.example.com") is None

    async def test_resolve_all_empty_returns_none(self, make_resolver):
        # some resolvers answer empty NOERROR for junk names; an all-empty
        # resolve is treated as nonexistent (dead, not candidate)
        resolver = make_resolver(
            {("bare.example.com", "A"): NoAnswer("bare.example.com")}
        )
        assert await resolver.resolve("bare.example.com") is None

    async def test_cname_chain_follows_and_stops(self, make_resolver):
        resolver = make_resolver(
            {
                ("a.example.com", "CNAME"): ("b.example.com",),
                ("b.example.com", "CNAME"): ("c.example.com",),
                ("c.example.com", "CNAME"): NoAnswer("c.example.com"),
            }
        )
        chain = await resolver.cname_chain("a.example.com")
        assert chain == ("b.example.com", "c.example.com")

    async def test_cname_chain_drops_nonexistent(self, make_resolver):
        resolver = make_resolver(
            {("gone.example.com", "CNAME"): NxDomain("gone.example.com")}
        )
        assert await resolver.cname_chain("gone.example.com") == ()

    async def test_resolver_type_error_propagates(self):
        class Broken:
            async def query(self, host, rtype):
                raise DnsError("boom")

        with pytest.raises(DnsError, match="boom"):
            await Resolver(Broken()).resolve("x.example.com")
