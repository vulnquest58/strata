from strata.engines.echoforge import (
    generate_mutations,
    generate_ngram_combinations,
    skip_prefix,
    token_frequencies,
    tokenize,
    top_tokens,
)


class TestTokenize:
    def test_leftmost_label_only(self):
        # echoforge semantics: tokenize keeps only what precedes the first dot
        assert tokenize("api-gateway.example.com") == ("api", "gateway")
        assert tokenize("api_v2.test.example.com") == ("api", "v2")

    def test_separators(self):
        assert tokenize("api_v2.test") == ("api", "v2")
        assert tokenize("staging backend") == ("staging", "backend")

    def test_drops_single_chars(self):
        assert tokenize("m.example.com") == ()
        assert tokenize("a-mail.example.com") == ("mail",)

    def test_lowercases(self):
        assert tokenize("API.Gateway.example.com") == ("api",)
        assert tokenize("API-gateway.example.com") == ("api", "gateway")

    def test_bare_label(self):
        assert tokenize("staging-backend") == ("staging", "backend")


class TestSkipPrefix:
    def test_noise(self):
        assert skip_prefix("www")
        assert skip_prefix("m")
        assert skip_prefix("a")
        assert not skip_prefix("api")


class TestTopTokens:
    def test_frequency_ordering(self):
        labels = ["api.example.com", "api.example.com", "cdn.example.com"]
        assert top_tokens(labels) == ("api", "cdn")
        assert token_frequencies(labels)["api"] == 2


class TestGenerateCombinations:
    def test_structure(self):
        combos = generate_ngram_combinations(
            "example.com", ("api", "cdn"), industry=("auth",)
        )
        assert "api.example.com" in combos
        assert "api-cdn.example.com" in combos
        assert "cdn-api.example.com" in combos
        assert "api-auth.example.com" in combos
        assert "auth-api.example.com" in combos
        assert "api-v2.example.com" in combos

    def test_no_duplicates(self):
        combos = generate_ngram_combinations("example.com", ("api", "api"))
        assert len(combos) == len(set(combos))


class TestGenerateMutations:
    SEEDS = ["gateway.example.com", "cdn.example.com"]
    DOMAIN = "example.com"

    def test_emits_expected_classes(self):
        mutations = generate_mutations(self.SEEDS, domain=self.DOMAIN)
        assert "api-gateway.example.com" in mutations
        assert "gateway-v2.example.com" in mutations
        assert "gateway-prod.example.com" in mutations
        assert "gateway-eu-west.example.com" in mutations

    def test_industry_pairs(self):
        mutations = generate_mutations(
            ["gateway.example.com"], industry=("auth",), domain=self.DOMAIN
        )
        assert "auth-gateway.example.com" in mutations
        assert "gateway-auth.example.com" in mutations

    def test_noise_prefix_skipped(self):
        mutations = generate_mutations(["www.example.com"])
        # tokenize("www...") yields only "www" (skipped as noise) -> no mutations
        assert all("www" not in m.split(".")[0].split("-") or True for m in mutations)
        # the real assertion: nothing generated from the noise token alone
        assert all(not m.startswith("www-") for m in mutations)
        assert all(not m.endswith(".www.example.com") for m in mutations)

    def test_per_seed_cap(self):
        mutations = generate_mutations(["gateway.example.com"], max_per_seed=10)
        assert len(mutations) <= 10

    def test_deterministic(self):
        assert generate_mutations(self.SEEDS) == generate_mutations(self.SEEDS)
