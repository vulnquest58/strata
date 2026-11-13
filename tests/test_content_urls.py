import pytest

from strata.core.content.urls import (
    cluster_path,
    interest_score,
    is_valid_endpoint,
    normalise_url,
    param_names,
)


class TestNormaliseUrl:
    def test_lowercases_host_sorts_query_strips_tracking(self):
        raw = "HTTPS://App.Example.COM:443/api/v1/users?utm_source=news&b=2&a=1#frag"
        assert normalise_url(raw) == "https://app.example.com/api/v1/users?a=1&b=2"

    def test_keeps_non_default_port(self):
        assert normalise_url("http://example.com:8080/x") == "http://example.com:8080/x"

    def test_adds_root_path(self):
        assert normalise_url("https://example.com") == "https://example.com/"

    def test_blank_raises(self):
        with pytest.raises(ValueError, match="blank"):
            normalise_url("  ")

    def test_hostless_raises(self):
        with pytest.raises(ValueError, match="no host"):
            normalise_url("/relative/path")

    def test_bad_scheme_raises(self):
        with pytest.raises(ValueError, match="scheme"):
            normalise_url("ftp://example.com/x")


class TestParamNames:
    def test_sorted_unique(self):
        assert param_names("https://example.com/?b=2&a=1&b=3") == ["a", "b"]


class TestClusterPath:
    def test_replaces_numeric_ids(self):
        assert cluster_path("/api/v1/users/42") == "/api/v1/users/{id}"

    def test_replaces_uuid_and_hash(self):
        path = (
            "/x/123e4567-e89b-12d3-a456-426614174000/"
            "0123456789abcdef0123456789abcdef"
        )
        assert cluster_path(path) == "/x/{uuid}/{hash}"

    def test_keeps_static_paths(self):
        assert cluster_path("/api/v1/users") == "/api/v1/users"


class TestValidity:
    def test_in_scope_root_and_subdomain(self):
        assert is_valid_endpoint("https://example.com/a", "example.com")[0]
        assert is_valid_endpoint("https://app.example.com/a", "example.com")[0]

    def test_out_of_scope_rejected(self):
        valid, reason = is_valid_endpoint("https://evil.com/a", "example.com")
        assert not valid and reason == "out_of_scope"

    def test_static_asset_rejected(self):
        valid, reason = is_valid_endpoint("https://example.com/app.js", "example.com")
        assert not valid and reason == "static_asset"

    def test_template_rejected(self):
        assert not is_valid_endpoint("https://example.com/api/${id}", "example.com")[0]

    def test_non_http_scheme_rejected(self):
        assert is_valid_endpoint("mailto:x@example.com", "example.com")[1] == "scheme"


class TestInterestScore:
    def test_api_admin_with_params_scores_high(self):
        score, flags = interest_score(
            "https://example.com/api/admin/users?id=1", ["id"]
        )
        assert score >= 80
        assert {"api", "admin", "params", "interesting_params"} <= set(flags)

    def test_plain_path_scores_low(self):
        score, flags = interest_score("https://example.com/about")
        assert score == 10
        assert flags == []
