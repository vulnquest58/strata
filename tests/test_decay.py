from datetime import UTC, datetime, timedelta

import pytest

from strata.core.decay import age_in_days, effective_confidence

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)


def test_fresh_claims_do_not_decay() -> None:
    discovered = NOW - timedelta(hours=1)
    assert effective_confidence(80.0, "candidate", discovered, now=NOW) == pytest.approx(
        80.0, abs=0.2
    )
    assert effective_confidence(80.0, "verified", discovered, now=NOW) == pytest.approx(
        80.0, abs=0.2
    )


def test_candidate_claims_decay_every_30_days() -> None:
    discovered = NOW - timedelta(days=30)
    assert effective_confidence(80.0, "candidate", discovered, now=NOW) == 40.0


def test_verified_claims_decay_every_90_days() -> None:
    discovered = NOW - timedelta(days=90)
    assert effective_confidence(80.0, "verified", discovered, now=NOW) == 40.0


def test_dead_claims_never_decay() -> None:
    discovered = NOW - timedelta(days=365)
    assert effective_confidence(80.0, "dead", discovered, now=NOW) == 80.0


def test_decay_never_reaches_zero() -> None:
    discovered = NOW - timedelta(days=3650)
    assert effective_confidence(80.0, "candidate", discovered, now=NOW) >= 1.0


def test_age_is_never_negative_for_clock_skew() -> None:
    discovered = NOW + timedelta(hours=2)
    assert age_in_days(discovered, NOW) == 0.0


def test_custom_half_lives() -> None:
    discovered = NOW - timedelta(days=10)
    value = effective_confidence(
        90.0,
        "candidate",
        discovered,
        now=NOW,
        half_lives={"candidate": 10.0},
    )
    assert value == 45.0
