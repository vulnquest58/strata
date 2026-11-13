from strata.core.dns.origin import (
    OriginType,
    _cdn_networks,
    _hosting_asns,
    classify_by_asn,
    classify_origin,
)


class TestCidrClassification:
    def test_cloudflare_ip_via_dataset(self):
        result = classify_origin(None, ("104.16.1.1",))
        assert result.origin_type is OriginType.CDN
        assert result.provider == "cloudflare"
        assert result.via == "ip_cidr"

    def test_datasets_load_and_are_populated(self):
        assert len(_cdn_networks()) > 50
        assert len(_hosting_asns()) > 50

    def test_asn_lookup(self):
        result = classify_by_asn(16509)  # amazon_aws
        assert result is not None
        assert result.provider == "amazon_aws"
        assert result.origin_type is OriginType.CLOUD

    def test_unknown_asn_returns_none(self):
        assert classify_by_asn(64999) is None


class TestCnameSuffixClassification:
    def test_cloudfront_cname(self):
        result = classify_origin("d111111abcdef8.cloudfront.net.")
        assert result.origin_type is OriginType.CDN
        assert result.provider == "aws_cloudfront"
        assert result.via == "cname_suffix"

    def test_github_pages_cname(self):
        result = classify_origin("user.github.io")
        assert result.origin_type is OriginType.PAAS
        assert result.provider == "github_pages"

    def test_cname_beats_ip_inference(self):
        # a CloudFront CNAME even with a Cloudflare-ranged IP -> cloudfront wins
        result = classify_origin("x.cloudfront.net", ("104.16.1.1",))
        assert result.provider == "aws_cloudfront"

    def test_cname_takes_precedence_over_cidr(self):
        result = classify_origin("something.github.io", ("104.16.1.1",))
        assert result.provider == "github_pages"
        assert result.via == "cname_suffix"


class TestDefaults:
    def test_no_cname_no_ips(self):
        result = classify_origin(None, ())
        assert result.origin_type is OriginType.UNKNOWN

    def test_plain_ip_is_direct(self):
        result = classify_origin(None, ("198.51.100.7",))
        assert result.origin_type is OriginType.DIRECT

    def test_bad_ip_ignored(self):
        result = classify_origin(None, ("not-an-ip",))
        assert result.origin_type is OriginType.DIRECT
