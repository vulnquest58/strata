"""Isotonic recalibration of claim confidence from the truth ledger.

The ledger records every claim outcome as ``(predicted confidence, observed)``
where ``observed`` is 1 for verified and 0 for dead. Reliability bands in
:mod:`strata.core.store.db` show whether the engine is over- or under-confident.

This module fits a monotone (isotonic) map from predicted confidence to
observed verify rate using pool-adjacent-violators, with three safeguards so
the map improves rather than corrupts future claims:

1. **Laplace smoothing** inside each isotonic block keeps small samples away
   from 0/1 extremes: ``p = (verified + 1) / (n + 2)``.
2. **Identity blending**: the calibrated value is blended with the raw value,
   weighted ``n / (n + 40)``, so a handful of outcomes cannot swing claims.
3. **Cross-validated gate**: the map is only activated when it beats the
   identity map on held-out folds (k-fold Brier comparison). Otherwise the
   model stays identity and the engine keeps its raw confidence.

The model never mutates stored findings; it is applied at report time so the
learning loop cannot feed its own output back into the ledger.

Known limitation: ledger outcomes are conditioned on claims the pipeline
chose to verify (high-EIG, plausible candidates), so calibrated confidence is
best read as the historical verify rate *among attempted claims*, not a
population-wide probability. The cross-validated gate guards against a map
that fails on held-out outcomes, but not against that selection effect.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "CalibrationModel",
    "isotonic_points",
]

IDENTITY_BLEND_K = 40.0
DEFAULT_MIN_SAMPLES = 30
DEFAULT_MIN_IMPROVEMENT = 0.01
DEFAULT_FOLDS = 5


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def isotonic_points(
    pairs: Iterable[tuple[float, int]], *, alpha: float = 1.0
) -> list[tuple[float, float]]:
    """Pool-adjacent-violators on ``(x, y)`` pairs.

    Returns block centres ``(mean_x, smoothed_y)`` on the 0-100 scale, with
    ``smoothed_y = (sum_y + alpha) / (count + 2*alpha)`` (Laplace).
    """
    ordered = sorted((_clamp(float(x)), int(y)) for x, y in pairs)
    if not ordered:
        return []
    # Each block tracks [sum_x, sum_y, count]; means are kept non-decreasing
    # by pooling adjacent violating blocks (weighted by count).
    blocks: list[list[float]] = []
    for x, y in ordered:
        blocks.append([x, float(y), 1.0])
        while len(blocks) >= 2:
            left, right = blocks[-2], blocks[-1]
            if left[1] / left[2] <= right[1] / right[2]:
                break
            blocks.pop()
            blocks.pop()
            blocks.append([left[0] + right[0], left[1] + right[1], left[2] + right[2]])
    # Collapse blocks sharing an x into a single pooled point: a confidence
    # value must map to exactly one calibrated value.
    pooled: list[list[float]] = []
    for sum_x, sum_y, count in blocks:
        mean_x = round(sum_x / count, 2)
        if pooled and pooled[-1][0] == mean_x:
            pooled[-1][1] += sum_y
            pooled[-1][2] += count
        else:
            pooled.append([mean_x, sum_y, count])

    # Laplace smoothing depends on block size, so a large near-perfect block
    # can end up *above* a smaller perfect block. Re-pool the smoothed values
    # (weighted by effective count) to restore monotonicity.
    smoothed: list[list[Any]] = []
    for mean_x, sum_y, count in pooled:
        value = (sum_y + alpha) / (count + 2.0 * alpha)
        smoothed.append([value * (count + 2.0 * alpha), count + 2.0 * alpha, [mean_x]])
    merged: list[list[Any]] = []
    for total, weight, xs in smoothed:
        merged.append([total, weight, list(xs)])
        while len(merged) >= 2:
            left, right = merged[-2], merged[-1]
            if left[0] / left[1] <= right[0] / right[1]:
                break
            merged.pop()
            merged.pop()
            merged.append([
                left[0] + right[0],
                left[1] + right[1],
                left[2] + right[2],
            ])
    points: list[tuple[float, float]] = []
    for total, weight, xs in merged:
        value = round(total / weight, 4)
        for mean_x in xs:
            points.append((mean_x, value))
    return points


def _interpolate(points: Sequence[tuple[float, float]], x: float) -> float:
    """Piecewise-linear interpolation over block centres; edges clamp."""
    if not points:
        return _clamp(x) / 100.0
    if x <= points[0][0]:
        return points[0][1]
    if x >= points[-1][0]:
        return points[-1][1]
    for (x0, y0), (x1, y1) in zip(points, points[1:], strict=False):
        if x0 <= x <= x1:
            if x1 <= x0:
                return y1
            ratio = (x - x0) / (x1 - x0)
            return y0 + (y1 - y0) * ratio
    return points[-1][1]


def _blended(
    points: Sequence[tuple[float, float]], weight: float, x: float
) -> float:
    iso = _interpolate(points, x) * 100.0
    return weight * iso + (1.0 - weight) * _clamp(x)


def _brier(
    pairs: Sequence[tuple[float, int]], points: Sequence[tuple[float, float]], weight: float
) -> float:
    if not pairs:
        return 0.0
    total = 0.0
    for x, y in pairs:
        predicted = _blended(points, weight, x) / 100.0
        total += (predicted - y) ** 2
    return total / len(pairs)


def _fit(pairs: Sequence[tuple[float, int]], *, alpha: float = 1.0) -> tuple[
    list[tuple[float, float]], float
]:
    weight = len(pairs) / (len(pairs) + IDENTITY_BLEND_K)
    return isotonic_points(pairs, alpha=alpha), weight


@dataclass(frozen=True)
class CalibrationModel:
    """Monotone confidence recalibration fitted from ledger outcomes."""

    scope: str = "identity"
    samples: int = 0
    applied: bool = False
    reason: str = "no outcomes"
    weight: float = 0.0
    brier_raw: float | None = None
    brier_calibrated: float | None = None
    points: tuple[tuple[float, float], ...] = field(default_factory=tuple)

    # -- fitting ---------------------------------------------------------

    @classmethod
    def from_outcomes(
        cls,
        outcomes: Iterable[Mapping[str, Any]],
        *,
        scope: str = "global",
        min_samples: int = DEFAULT_MIN_SAMPLES,
        min_improvement: float = DEFAULT_MIN_IMPROVEMENT,
        folds: int = DEFAULT_FOLDS,
    ) -> CalibrationModel:
        pairs = [
            (_clamp(float(o["predicted"])), int(o["observed"]))
            for o in outcomes
            if o.get("predicted") is not None and o.get("observed") is not None
        ]
        n = len(pairs)
        if n == 0:
            return cls(scope="identity", samples=0, reason="no outcomes")
        if n < min_samples:
            return cls(
                scope="identity",
                samples=n,
                reason=f"insufficient outcomes ({n} < {min_samples})",
            )

        # Cross-validated gate: only activate if the map beats identity.
        fold_count = max(2, min(folds, max(2, n // 10)))
        rng = random.Random(0)
        indices = list(range(n))
        rng.shuffle(indices)
        raw_total = 0.0
        calibrated_total = 0.0
        for fold in range(fold_count):
            test_idx = indices[fold::fold_count]
            test_set = set(test_idx)
            train_idx = [i for i in indices if i not in test_set]
            train_pairs = [pairs[i] for i in train_idx]
            test_pairs = [pairs[i] for i in test_idx]
            if not train_pairs or not test_pairs:
                continue
            train_points, train_weight = _fit(train_pairs)
            raw_total += _brier(test_pairs, [], 0.0)
            calibrated_total += _brier(test_pairs, train_points, train_weight)
        if raw_total > 0 and calibrated_total > raw_total * (1.0 - min_improvement):
            return cls(
                scope="identity",
                samples=n,
                reason="no cross-validated improvement",
                brier_raw=round(raw_total / fold_count, 4),
                brier_calibrated=round(calibrated_total / fold_count, 4),
            )

        points, weight = _fit(pairs)
        return cls(
            scope=scope,
            samples=n,
            applied=True,
            reason="cross-validated improvement",
            weight=round(weight, 4),
            brier_raw=round(raw_total / fold_count, 4),
            brier_calibrated=round(calibrated_total / fold_count, 4),
            points=tuple(points),
        )

    # -- applying --------------------------------------------------------

    def transform(self, confidence: float) -> float:
        """Map a raw 0-100 confidence to its calibrated value."""
        if not self.applied or not self.points:
            return _clamp(float(confidence))
        return round(_clamp(_blended(self.points, self.weight, float(confidence))), 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "samples": self.samples,
            "applied": self.applied,
            "reason": self.reason,
            "weight": self.weight,
            "brier_raw": self.brier_raw,
            "brier_calibrated": self.brier_calibrated,
            "points": [[x, y] for x, y in self.points],
        }
