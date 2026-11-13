import pytest
from conftest import StubHttpTransport

from strata.core.content.fetch import FetchResponse
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import FindingClass, FindingStatus
from strata.engines.js_content import ContentDiscoveryEngine

BASE = "https://app.example.com"
JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
AWS_KEY = "AKIA2E7Q4Z6X8C1V3B5N"
GENERIC_KEY = "aB3dE5fG7hJ9kL2mN4pQ6rS8"

HTML = """<html><head>
<script src="/static/app.js"></script>
<script src="https://cdn.example.net/lib.js"></script>
</head><body>
<a href="/dashboard">dashboard</a>
<form action="/search?q=x"></form>
<script>const cfg = {url: "/api/v1/inline"};</script>
</body></html>"""

APP_JS = f"""
const api = "https://app.example.com/api/v2/orders";
const external = "https://external.example.org/track";
fetch("/api/v1/login", {{method: "POST"}});
axios.post("/api/v1/users/42");
const jwt = "{JWT}";
const awsKey = "{AWS_KEY}";
const apiKey = "{GENERIC_KEY}";
"""

ROBOTS = """User-agent: *
Disallow: /admin
Sitemap: https://app.example.com/sitemap.xml
"""

SITEMAP = """<urlset>
<url><loc>https://app.example.com/docs</loc></url>
<url><loc>https://app.example.com/blog/123</loc></url>
</urlset>"""


def base_routes() -> dict:
    return {
        BASE + "/": FetchResponse(
            BASE + "/", 200, {"content-type": "text/html; charset=utf-8"}, HTML.encode()
        ),
        BASE + "/static/app.js": FetchResponse(
            BASE + "/static/app.js",
            200,
            {"content-type": "application/javascript"},
            APP_JS.encode(),
        ),
        BASE + "/robots.txt": FetchResponse(
            BASE + "/robots.txt", 200, {"content-type": "text/plain"}, ROBOTS.encode()
        ),
        BASE + "/sitemap.xml": FetchResponse(
            BASE + "/sitemap.xml", 200, {"content-type": "application/xml"}, SITEMAP.encode()
        ),
    }


def build_engine(routes: dict, **kwargs) -> ContentDiscoveryEngine:
    return ContentDiscoveryEngine(
        StubHttpTransport(routes),
        ScopePolicy.from_list(["example.com"]),
        **kwargs,
    )


class TestContentEngine:
    async def test_discovers_endpoints_and_secrets(self):
        result = await build_engine(base_routes(), probe=False).run(BASE + "/")
        endpoints = {
            finding.asset_value
            for finding in result.findings
            if finding.kind is FindingClass.ENDPOINT
        }
        expected = {
            BASE + "/dashboard",
            BASE + "/search?q=x",
            BASE + "/api/v1/inline",
            BASE + "/api/v2/orders",
            BASE + "/api/v1/login",
            BASE + "/api/v1/users/42",
            BASE + "/admin",
            BASE + "/docs",
            BASE + "/blog/123",
        }
        assert expected <= endpoints

        secret_kinds = {
            finding.metadata["kind"]
            for finding in result.findings
            if finding.kind is FindingClass.SECRET
        }
        assert {"jwt", "aws_access_key", "generic_secret"} <= secret_kinds

        serialized = "\n".join(finding.model_dump_json() for finding in result.findings)
        for raw in (JWT, AWS_KEY, GENERIC_KEY):
            assert raw not in serialized

        assert result.stats.scripts_fetched == 1
        assert result.stats.endpoints_out_of_scope >= 2
        assert all(
            finding.status is FindingStatus.CANDIDATE
            for finding in result.findings
            if finding.kind is FindingClass.ENDPOINT
        )

    async def test_probing_upgrades_and_kills(self):
        routes = base_routes()
        routes[BASE + "/api/v1/login"] = FetchResponse(
            BASE + "/api/v1/login", 200, {}, b""
        )
        routes[BASE + "/dashboard"] = FetchResponse(
            BASE + "/dashboard", 404, {}, b""
        )
        result = await build_engine(routes, probe=True).run(BASE + "/")
        by_asset = {finding.asset_value: finding for finding in result.findings}
        login = by_asset[BASE + "/api/v1/login"]
        assert login.status is FindingStatus.VERIFIED
        assert any(
            evidence.engine == "content_probe" for evidence in login.evidence
        )
        assert by_asset[BASE + "/dashboard"].status is FindingStatus.DEAD
        assert result.stats.verified >= 1
        assert result.stats.dead >= 1

    async def test_probe_can_be_disabled(self):
        result = await build_engine(base_routes(), probe=False).run(BASE + "/")
        assert result.stats.probed == 0
        assert all(
            finding.status is FindingStatus.CANDIDATE
            for finding in result.findings
            if finding.kind is FindingClass.ENDPOINT
        )

    async def test_robots_can_be_disabled(self):
        result = await build_engine(base_routes(), probe=False, robots=False).run(
            BASE + "/"
        )
        assets = {finding.asset_value for finding in result.findings}
        assert BASE + "/admin" not in assets
        assert BASE + "/api/v1/login" in assets

    async def test_out_of_scope_seed_raises(self):
        engine = ContentDiscoveryEngine(
            StubHttpTransport({}),
            ScopePolicy.from_list(["other.example"]),
            probe=False,
        )
        with pytest.raises(PermissionError):
            await engine.run(BASE + "/")

    async def test_resume_skips_known_assets(self):
        result = await build_engine(base_routes(), probe=False).run(BASE + "/")
        known_endpoint = BASE + "/dashboard"
        known_secret = next(
            finding.asset_value
            for finding in result.findings
            if finding.kind is FindingClass.SECRET
        )
        resumed = await build_engine(
            base_routes(),
            probe=False,
            known={known_endpoint, known_secret},
        ).run(BASE + "/")
        assets = {finding.asset_value for finding in resumed.findings}
        assert known_endpoint not in assets
        assert known_secret not in assets
