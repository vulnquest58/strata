from conftest import StubHttpTransport

from strata.core.content.fetch import FetchResponse
from strata.core.schema.models import ConfidenceMethod, FindingClass
from strata.engines.http_fp import fingerprint_response, fingerprint_url


def test_fingerprint_response_extracts_waf_tech_and_headers() -> None:
    response = FetchResponse(
        url="https://app.example.com/",
        status=200,
        headers={
            "server": "cloudflare",
            "cf-ray": "abc123",
            "content-type": "text/html",
            "strict-transport-security": "max-age=31536000",
            "x-powered-by": "PHP/8.2",
        },
        body=b"<html><head><title>App</title></head></html>",
    )
    result = fingerprint_response(response, run_id="fp:example.com")

    assert result is not None
    assert result.waf == "Cloudflare"
    assert result.server == "cloudflare"
    assert "PHP" in result.tech_stack
    assert "content-security-policy" in result.finding.metadata["missing_critical_headers"]
    assert result.finding.kind is FindingClass.LIVE_HOST
    assert result.finding.confidence.method is ConfidenceMethod.HTTP_PROBE
    assert result.finding.metadata["waf"] == "Cloudflare"
    assert result.finding.evidence[0].meta["status"] == 200


async def test_fingerprint_url_returns_none_on_transport_error() -> None:
    transport = StubHttpTransport(
        {"https://down.example.com/": ConnectionError("refused")}
    )
    result = await fingerprint_url(
        "https://down.example.com/", transport=transport
    )
    assert result is None


async def test_fingerprint_url_returns_finding_for_live_response() -> None:
    transport = StubHttpTransport(
        {
            "https://app.example.com/": FetchResponse(
                "https://app.example.com/",
                200,
                {"server": "nginx", "content-type": "text/html"},
                b"<html>ok</html>",
            )
        }
    )
    result = await fingerprint_url(
        "https://app.example.com/", transport=transport, run_id="fp:example"
    )
    assert result is not None
    assert result.finding.asset_value == "https://app.example.com/"
    assert "Nginx" in result.tech_stack
