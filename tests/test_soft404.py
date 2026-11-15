import pytest

from strata.core.content.fetch import FetchResponse
from strata.core.content.soft404 import (
    Soft404Profile,
    build_profile,
    classify_response,
    extract_title,
    fetch_baseline,
    token_similarity,
    tokenize,
)


def _response(url: str, status: int, body: str) -> FetchResponse:
    return FetchResponse(
        url=url, status=status, headers={"content-type": "text/html"}, body=body.encode()
    )


_ERROR_BODY = (
    "<html><head><title>Page Not Found - Example Corp</title></head>"
    "<body><h1>404 - Page Not Found</h1>"
    "<p>The page you requested does not exist. Return <a href='/'>home</a>.</p>"
    "<footer>Example Corp 2026 legal privacy contact</footer></body></html>"
)


def _profile_from_body(body: str, status: int = 404) -> Soft404Profile:
    return build_profile(_response("https://example.com/__missing__", status, body))


def _token_profile(body: str, status: int = 404) -> Soft404Profile:
    return Soft404Profile(
        host="example.com",
        status=status,
        title=extract_title(body),
        tokens=tokenize(body),
        length=len(body),
        generic_404=True,
    )


def test_fetch_baseline_creates_fresh_profile():
    profile = _profile_from_body(_ERROR_BODY)
    assert profile.status == 404
    assert "not found" in profile.title.lower()
    assert "footer" not in profile.tokens
    assert "example" in profile.tokens or "corp" in profile.tokens


def test_404_status_is_not_found_even_without_baseline():
    response = _response("https://example.com/anything", 404, "<html><body>x</body></html>")
    assert classify_response(response, None) == "not_found"


def test_5xx_never_kills_a_claim():
    baseline = _token_profile(_ERROR_BODY)
    response = _response("https://example.com/app", 503, "maintenance")
    assert classify_response(response, baseline) == "uncertain"


def test_real_page_is_live_against_404_baseline():
    baseline = _token_profile(_ERROR_BODY)
    real = _response(
        "https://example.com/products",
        200,
        "<html><head><title>Products - Example Corp</title></head>"
        "<body><h1>Our product catalogue with prices</h1>"
        "<p>Inventory, shipping, and checkout details for every widget.</p></body></html>",
    )
    assert classify_response(real, baseline) == "live"


def test_200_with_not_found_content_is_soft404():
    baseline = _token_profile(_ERROR_BODY)
    soft = _response(
        "https://example.com/admin-backup",
        200,
        "<html><head><title>Page Not Found - Example Corp</title></head>"
        "<body><h1>404 - Page Not Found</h1>"
        "<p>The page you requested does not exist. Return <a href='/'>home</a>.</p>"
        "<footer>Example Corp 2026 legal privacy contact</footer></body></html>",
    )
    assert classify_response(soft, baseline) == "soft404"


def test_short_clone_detected_by_length_and_similarity():
    baseline = _token_profile(_ERROR_BODY)
    short = _response(
        "https://example.com/hidden",
        200,
        "<html><head><title>Page Not Found - Example Corp</title></head>"
        "<body><h1>404 - Page Not Found</h1>"
        "<p>The page you requested does not exist. Return home.</p></body></html>",
    )
    assert classify_response(short, baseline) == "soft404"


def test_similar_but_distinct_page_stays_live():
    baseline = _token_profile(_ERROR_BODY)
    distinct = _response(
        "https://example.com/news",
        200,
        "<html><head><title>News - Example Corp</title></head>"
        "<body><h1>Latest announcements</h1>"
        "<p>Release notes, security advisories, and press coverage.</p>"
        "<footer>Example Corp 2026 legal privacy contact</footer></body></html>",
    )
    verdict = classify_response(distinct, baseline)
    assert verdict == "live"


def test_network_failure_is_uncertain():
    response = _response("https://example.com/x", 0, "")
    baseline = _token_profile(_ERROR_BODY)
    assert classify_response(response, baseline) == "uncertain"


def test_token_similarity_bounds():
    a = frozenset({"alpha", "beta", "gamma"})
    b = frozenset({"alpha", "beta", "delta"})
    assert 0.0 < token_similarity(a, b) < 1.0
    assert token_similarity(a, frozenset()) == 0.0
    assert token_similarity(a, a) == 1.0


@pytest.mark.asyncio
async def test_fetch_baseline_uses_random_path():
    captured: list[str] = []

    class Transport:
        async def get(self, url, *, timeout=10.0, max_bytes=2_000_000):
            captured.append(url)
            return _response(url, 404, _ERROR_BODY)

    profile = await fetch_baseline("https://example.com/", Transport())
    assert profile is not None
    assert profile.status == 404
    assert captured and captured[0].startswith("https://example.com/")


@pytest.mark.asyncio
async def test_fetch_baseline_returns_none_on_transport_error():
    class Transport:
        async def get(self, url, *, timeout=10.0, max_bytes=2_000_000):
            raise OSError("boom")

    assert await fetch_baseline("https://example.com/", Transport()) is None
