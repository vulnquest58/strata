"""Belief half-life: confidence decays without fresh verification.

A claim is a statement about the world *as of a moment in time*. Infrastructure
changes, so unverified claims go stale fast and verified claims go stale slow.
Confidence is decayed exponentially by claim age relative to a per-status
half-life. The decayed value never mutates stored findings; it is computed at
assessment time (tension, reports) so the ledger stays immutable and the decay
policy can evolve.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

DEFAULT_HALF_LIVES_DAYS: Mapping[str, float] = {
    "stale": 21.0,
    "candidate": 30.0,
    "verified": 90.0,
}
MIN_EFFECTIVE_CONFIDENCE = 1.0


def age_in_days(discovered_at: datetime, now: datetime | None = None) -> float:
    current = now or datetime.now(UTC)
    if discovered_at.tzinfo is None:
        discovered_at = discovered_at.replace(tzinfo=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return max(0.0, (current - discovered_at).total_seconds() / 86400.0)


def effective_confidence(
    value: float,
    status: str,
    discovered_at: datetime,
    *,
    now: datetime | None = None,
    half_lives: Mapping[str, float] | None = None,
) -> float:
    """Decay a confidence value by claim age.

    Dead claims do not decay: the observation "this does not exist" was made
    at a point in time and is not softened by age.
    """
    if status == "dead":
        return max(0.0, min(100.0, value))
    table = half_lives if half_lives is not None else DEFAULT_HALF_LIVES_DAYS
    half_life = table.get(status)
    if not half_life or half_life <= 0:
        return max(0.0, min(100.0, value))
    age = age_in_days(discovered_at, now)
    decayed = value * (0.5 ** (age / half_life))
    return max(MIN_EFFECTIVE_CONFIDENCE, round(min(100.0, decayed), 1))


__all__ = [
    "DEFAULT_HALF_LIVES_DAYS",
    "MIN_EFFECTIVE_CONFIDENCE",
    "age_in_days",
    "effective_confidence",
]
