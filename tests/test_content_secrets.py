from strata.core.content.secrets import (
    detect_secrets,
    mask_secret,
    secret_asset_id,
    secret_confidence,
    shannon_entropy,
)

JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
AWS_KEY = "AKIA2E7Q4Z6X8C1V3B5N"


class TestEntropy:
    def test_uniform_string_is_zero(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_symbols_is_one_bit(self):
        assert shannon_entropy("abab") == 1.0


class TestDetection:
    def test_jwt_and_aws(self):
        text = f'const jwt = "{JWT}";\nconst key = "{AWS_KEY}";\n'
        hits = detect_secrets(text)
        values = {(hit.kind, hit.value) for hit in hits}
        assert ("jwt", JWT) in values
        assert ("aws_access_key", AWS_KEY) in values
        jwt = next(hit for hit in hits if hit.kind == "jwt")
        assert jwt.line == 1
        assert secret_confidence(jwt) >= 80

    def test_generic_high_entropy_assignment(self):
        hits = detect_secrets('const apiKey = "aB3dE5fG7hJ9kL2mN4pQ6rS8";')
        assert [hit.kind for hit in hits] == ["generic_secret"]

    def test_placeholder_and_low_entropy_skipped(self):
        text = (
            'api_key = "your_api_key_here_1234567890"\n'
            'apiKey = "aaaaaaaaaaaaaaaaaaaaaaaa"\n'
        )
        assert detect_secrets(text) == []

    def test_specific_pattern_wins_over_generic(self):
        hits = detect_secrets(f'token: "{JWT}"')
        assert [hit.kind for hit in hits] == ["jwt"]
        assert hits[0].value == JWT


class TestMasking:
    def test_mask_keeps_edges(self):
        assert mask_secret("abcdefghijklmnop") == "abcdef...mnop"

    def test_short_fully_masked(self):
        assert mask_secret("short") == "*****"

    def test_asset_id_is_stable_and_leak_free(self):
        first = secret_asset_id("jwt", JWT)
        assert first == secret_asset_id("jwt", JWT)
        assert first.startswith("secret:jwt:")
        assert JWT not in first
        assert secret_asset_id("jwt", JWT + "x") != first
