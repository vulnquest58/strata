"""Golden-surface benchmark scoring.

Findings are compared against an explicit expected set so every change can
report precision, recall, and F1 instead of anecdotal "more results". Keys are
stable, human-readable strings:

    subdomain:www.example.com
    endpoint:https://example.com/api/users?user_id=1
    param:https://example.com/api/users?user_id=1::user_id

The default key ignores confidence and status: a benchmark asks "did Strata
surface this asset at all?" — calibration quality is measured separately.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from strata.core.schema.models import FindingClass, UnifiedFinding


def _normalise_asset(value: str) -> str:
    cleaned = value.strip().lower()
    if "://" in cleaned:
        return cleaned.rstrip("/")
    return cleaned.rstrip(".")


def finding_key(finding: UnifiedFinding) -> str:
    kind = finding.kind.value
    asset = _normalise_asset(finding.asset_value)
    if finding.kind is FindingClass.PARAM and finding.parent:
        return f"param:{_normalise_asset(finding.parent)}::{asset}"
    return f"{kind}:{asset}"


def load_expected(path: str | Path) -> set[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("expected", [])
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise ValueError("expected file must be a JSON list of strings")
    return {item.strip() for item in payload if item.strip()}


@dataclass
class BenchmarkScore:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    by_kind: dict[str, dict[str, int]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "by_kind": self.by_kind,
        }


def score_findings(
    findings: Iterable[UnifiedFinding], expected: Iterable[str]
) -> BenchmarkScore:
    expected_set = {item.strip() for item in expected if item.strip()}
    actual = {finding_key(finding) for finding in findings}

    true_positives = actual & expected_set
    false_positives = actual - expected_set
    false_negatives = expected_set - actual

    precision = (
        len(true_positives) / len(actual) if actual else 0.0
    )
    recall = (
        len(true_positives) / len(expected_set) if expected_set else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    by_kind: dict[str, dict[str, int]] = {}
    for key, bucket in (
        *((key, "tp") for key in true_positives),
        *((key, "fp") for key in false_positives),
        *((key, "fn") for key in false_negatives),
    ):
        kind = key.split(":", 1)[0]
        by_kind.setdefault(kind, {"tp": 0, "fp": 0, "fn": 0})[bucket] += 1

    return BenchmarkScore(
        true_positives=len(true_positives),
        false_positives=len(false_positives),
        false_negatives=len(false_negatives),
        precision=precision,
        recall=recall,
        f1=f1,
        by_kind=by_kind,
    )
