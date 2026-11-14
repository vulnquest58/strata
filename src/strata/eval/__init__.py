"""Evaluation utilities: golden-surface scoring and precision/recall receipts."""

from strata.eval.benchmark import (
    BenchmarkScore,
    finding_key,
    load_expected,
    score_findings,
)

__all__ = ["BenchmarkScore", "finding_key", "load_expected", "score_findings"]
