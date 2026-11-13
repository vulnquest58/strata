"""Evidence tension analysis (new methodology layer).

Strata treats findings as hypotheses, not facts. Confidence says how strongly
a hypothesis is supported. Evidence tension says how unstable the claim is:
which side of the claim is still under pressure, and how much probing is
needed to collapse it into a stable verified/dead state.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from strata.core.schema.models import FindingStatus, UnifiedFinding

_LIVE_ENGINES = {"content_probe", "dns_verify", "param_oracle"}


class TensionLabel:
    HOT = "hot"
    GHOST = "ghost"
    SHADOW = "shadow"
    STABLE = "stable"


@dataclass(frozen=True)
class TensionAssessment:
    finding_id: str
    asset_value: str
    kind: str
    status: str
    confidence: float
    score: int
    label: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "asset_value": self.asset_value,
            "kind": self.kind,
            "status": self.status,
            "confidence": self.confidence,
            "score": self.score,
            "label": self.label,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class TensionSummary:
    total: int
    by_label: dict[str, int]
    by_kind: dict[str, int]
    mean_score: float
    worst: TensionAssessment | None

    @property
    def hot(self) -> int:
        return self.by_label.get(TensionLabel.HOT, 0)

    @property
    def ghost(self) -> int:
        return self.by_label.get(TensionLabel.GHOST, 0)

    @property
    def shadow(self) -> int:
        return self.by_label.get(TensionLabel.SHADOW, 0)

    @property
    def stable(self) -> int:
        return self.by_label.get(TensionLabel.STABLE, 0)


def _source_count(finding: UnifiedFinding) -> int:
    value = finding.metadata.get("source_count")
    if isinstance(value, int) and value > 0:
        return value
    return 1


def _has_live_probe(finding: UnifiedFinding) -> bool:
    return any(evidence.engine in _LIVE_ENGINES for evidence in finding.evidence)


def assess_tension(finding: UnifiedFinding) -> TensionAssessment:
    score = 0
    reasons: list[str] = []

    if finding.status in (FindingStatus.CANDIDATE, FindingStatus.STALE):
        score += 25
        reasons.append(f"status={finding.status.value} is not yet stable")

    if _source_count(finding) <= 1:
        score += 15
        reasons.append("single-source claim")

    if not _has_live_probe(finding):
        score += 20
        reasons.append("no live-probe evidence")

    if finding.confidence.value >= 60 and finding.status is FindingStatus.CANDIDATE:
        score += 25
        reasons.append("high-confidence but still unverified")

    if finding.status is FindingStatus.DEAD and finding.confidence.value >= 50:
        score += 15
        reasons.append("dead claim with residual confidence")

    score = min(100, score)

    if finding.status is FindingStatus.DEAD and finding.confidence.value >= 50:
        label = TensionLabel.GHOST
    elif score >= 70 and finding.status is FindingStatus.CANDIDATE:
        label = TensionLabel.HOT
    elif score >= 50 and finding.confidence.value < 50:
        label = TensionLabel.SHADOW
    else:
        label = TensionLabel.STABLE

    return TensionAssessment(
        finding_id=finding.finding_id,
        asset_value=finding.asset_value,
        kind=finding.kind.value,
        status=finding.status.value,
        confidence=finding.confidence.value,
        score=score,
        label=label,
        reasons=reasons,
    )


def assess_tensions(findings: Iterable[UnifiedFinding]) -> list[TensionAssessment]:
    return [assess_tension(finding) for finding in findings]


def summarise_tension(
    findings: Iterable[UnifiedFinding],
) -> tuple[TensionSummary, list[TensionAssessment]]:
    items = assess_tensions(findings)
    by_label = Counter(assessment.label for assessment in items)
    by_kind = Counter(assessment.kind for assessment in items)
    mean_score = (
        round(sum(assessment.score for assessment in items) / len(items), 1)
        if items
        else 0.0
    )
    worst = max(items, key=lambda item: item.score) if items else None
    summary = TensionSummary(
        total=len(items),
        by_label=dict(sorted(by_label.items())),
        by_kind=dict(sorted(by_kind.items())),
        mean_score=mean_score,
        worst=worst,
    )
    return summary, items


def tension_markdown(
    findings: Iterable[UnifiedFinding], *, title: str = "Strata tension report"
) -> str:
    summary, items = summarise_tension(findings)
    lines = [
        f"# {title}",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Findings | {summary.total} |",
        f"| Hot | {summary.hot} |",
        f"| Ghost | {summary.ghost} |",
        f"| Shadow | {summary.shadow} |",
        f"| Stable | {summary.stable} |",
        f"| Mean tension | {summary.mean_score} |",
        "",
        "## Breakdown",
        "",
        "| Kind | Count |",
        "|---|---:|",
    ]
    for kind, count in summary.by_kind.items():
        lines.append(f"| {kind} | {count} |")
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Tension | Label | Confidence | Status | Kind | Asset | Reasons |",
            "|---:|---|---:|---|---|---|---|",
        ]
    )
    for assessment in items:
        asset = assessment.asset_value.replace("|", "\\|")
        reasons = "; ".join(assessment.reasons).replace("|", "\\|")
        lines.append(
            f"| {assessment.score} | {assessment.label} | {assessment.confidence:.1f} | "
            f"{assessment.status} | {assessment.kind} | {asset} | {reasons} |"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "TensionAssessment",
    "TensionLabel",
    "TensionSummary",
    "assess_tension",
    "assess_tensions",
    "summarise_tension",
    "tension_markdown",
]
