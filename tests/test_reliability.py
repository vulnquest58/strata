from strata.core.reliability import (
    assess_source_reliability,
    claim_sources,
    reliability_weights,
)


def test_claim_sources_excludes_verifier_engines() -> None:
    sources = claim_sources(
        ["content_crawl", "content_probe", "dns_brute", "dns_verify", "fusion"]
    )
    assert sources == ["content_crawl", "dns_brute"]


def test_source_reliability_rates_and_predictions() -> None:
    rows = [
        {"sources": ["crtsh"], "predicted": 80.0, "observed": 1},
        {"sources": ["crtsh"], "predicted": 60.0, "observed": 1},
        {"sources": ["crtsh"], "predicted": 40.0, "observed": 0},
        {"sources": ["dns_brute"], "predicted": 30.0, "observed": 0},
        {"sources": [], "predicted": 50.0, "observed": 1},
    ]
    reliability = assess_source_reliability(rows)
    assert set(reliability) == {"crtsh", "dns_brute"}
    assert reliability["crtsh"]["outcomes"] == 3
    assert reliability["crtsh"]["verified"] == 2
    assert reliability["crtsh"]["dead"] == 1
    assert reliability["crtsh"]["observed_rate"] == 66.7
    assert reliability["dns_brute"]["observed_rate"] == 0.0


def test_low_rate_source_is_flagged_as_possible_poisoning() -> None:
    rows = [
        {"sources": ["honest"], "predicted": 80.0, "observed": 1}
        for _ in range(12)
    ]
    rows.extend(
        {"sources": ["poisoned"], "predicted": 50.0, "observed": 0}
        for _ in range(20)
    )
    reliability = assess_source_reliability(rows)
    assert reliability["poisoned"]["flagged"] is True
    assert "poisoned" in reliability["poisoned"]["flag_reason"]
    assert reliability["honest"]["flagged"] is False


def test_small_samples_are_never_flagged() -> None:
    rows = [
        {"sources": ["weak"], "predicted": 80.0, "observed": 1},
        {"sources": ["weak"], "predicted": 70.0, "observed": 1},
        {"sources": ["weak"], "predicted": 90.0, "observed": 1},
        *(
            {"sources": ["weak"], "predicted": 50.0, "observed": 0}
            for _ in range(16)
        ),
    ]
    reliability = assess_source_reliability(rows)
    assert reliability["weak"]["outcomes"] == 19
    assert reliability["weak"]["flagged"] is False


def test_reliability_weights_are_laplace_smoothed() -> None:
    reliability = {
        "strong": {"outcomes": 18, "verified": 9},
        "weak": {"outcomes": 3, "verified": 3},
        "unknown": {"outcomes": 0, "verified": 0},
    }
    weights = reliability_weights(reliability)
    assert "weak" not in weights
    assert "unknown" not in weights
    assert weights["strong"] == (9 + 1) / (18 + 2)


def test_mean_predicted_is_not_double_scaled() -> None:
    # Ledger stores predicted confidence on the 0-100 scale; the aggregator
    # must report it on the same scale, not multiply by 100 a second time.
    rows = [
        {"sources": ["src"], "predicted": 35.0, "observed": 1},
        {"sources": ["src"], "predicted": 45.0, "observed": 0},
    ]
    reliability = assess_source_reliability(rows)
    assert reliability["src"]["mean_predicted"] == 40.0
