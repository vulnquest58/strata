from strata.core.inference import (
    information_gain_bits,
    information_gain_from_confidence,
    rank_by_information_gain,
)
from strata.core.schema.models import Confidence, FindingClass, UnifiedFinding


def _finding(asset: str, confidence: float) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="r1",
        kind=FindingClass.ENDPOINT,
        asset_value=asset,
        confidence=Confidence(value=confidence),
    )


def test_entropy_is_maximal_at_half() -> None:
    assert information_gain_bits(0.5) == 1.0
    assert information_gain_bits(0.0) == 0.0
    assert information_gain_bits(1.0) == 0.0


def test_confidence_gain_conversion() -> None:
    assert information_gain_from_confidence(50.0) == 1.0
    assert information_gain_from_confidence(100.0) == 0.0


def test_scheduler_probes_uncertainty_first() -> None:
    findings = [
        _finding("certain.example.com", 95.0),
        _finding("unsure.example.com", 50.0),
        _finding("hopeless.example.com", 5.0),
        _finding("leaning.example.com", 30.0),
    ]
    ranked = rank_by_information_gain(findings)
    assets = [finding.asset_value for finding, _ in ranked]
    assert assets[0] == "unsure.example.com"
    assert assets[-1] == "hopeless.example.com"
    assert assets.index("leaning.example.com") < assets.index(
        "certain.example.com"
    )


def test_ranking_is_deterministic_on_ties() -> None:
    findings = [_finding("b.example.com", 50.0), _finding("a.example.com", 50.0)]
    ranked = rank_by_information_gain(findings)
    assert [finding.asset_value for finding, _ in ranked] == [
        "a.example.com",
        "b.example.com",
    ]
