"""Cross-engine entity fusion (P4).

Resolves findings that refer to the same real-world entity across runs and
engines, then combines their independent confidence signals with a noisy-OR.
The result is a separate `UnifiedFinding` with provenance back to every source
finding.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC
from math import prod

from strata.core.content.urls import host_of, normalise_url
from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

FUSION_SOURCE = "fusion"


@dataclass(frozen=True)
class EntityGroup:
    kind: FindingClass
    key: str
    findings: tuple[UnifiedFinding, ...]


def entity_key(finding: UnifiedFinding) -> str:
    value = finding.asset_value.strip().lower()
    if finding.kind is FindingClass.ENDPOINT:
        try:
            return normalise_url(value)
        except ValueError:
            return value
    if finding.kind is FindingClass.PARAM:
        parent = (finding.parent or "").strip().lower()
        return f"{parent}|{value}"
    return value


def _is_fusion_finding(finding: UnifiedFinding) -> bool:
    return (
        finding.metadata.get("source") == FUSION_SOURCE
        or finding.run_id.startswith("fusion:")
    )


def _finding_order(finding: UnifiedFinding) -> tuple[str, str]:
    ts = finding.discovered_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return (ts.isoformat(), finding.finding_id)


def resolve_entities(
    findings: Iterable[UnifiedFinding],
) -> list[EntityGroup]:
    grouped: dict[tuple[FindingClass, str], list[UnifiedFinding]] = defaultdict(list)
    for finding in findings:
        if _is_fusion_finding(finding):
            continue
        grouped[(finding.kind, entity_key(finding))].append(finding)

    groups: list[EntityGroup] = []
    for (kind, key), members in grouped.items():
        ordered = tuple(sorted(members, key=_finding_order))
        groups.append(EntityGroup(kind=kind, key=key, findings=ordered))
    return sorted(
        groups,
        key=lambda group: (group.kind.value, group.key),
    )


def noisy_or_confidence(values: Iterable[float]) -> float:
    """Combine independent 0..100 confidence signals with a noisy-OR."""
    survival = prod(1.0 - max(0.0, min(100.0, value)) / 100.0 for value in values)
    return round(100.0 * (1.0 - survival), 1)


def _earliest_datetime(finding: UnifiedFinding):
    ts = finding.discovered_at
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts


def _preferred_parent(members: tuple[UnifiedFinding, ...]) -> str | None:
    counts = Counter(member.parent or "" for member in members)
    if not counts:
        return None
    preferred = max(counts.items(), key=lambda item: (item[1], item[0]))[0]
    return preferred or None


def _canonical_asset_value(
    kind: FindingClass, members: tuple[UnifiedFinding, ...], key: str
) -> str:
    if kind is FindingClass.ENDPOINT:
        return key
    if kind is FindingClass.PARAM:
        return key.split("|", 1)[1]
    return members[0].asset_value.strip().lower()


def _merge_evidence(members: tuple[UnifiedFinding, ...]) -> list[Evidence]:
    merged: dict[tuple[str, str, str], Evidence] = {}
    for member in members:
        for evidence in member.evidence:
            identity = (evidence.engine, evidence.technique, evidence.observation)
            existing = merged.get(identity)
            if existing is None or _earlier_ts(evidence.ts, existing.ts):
                merged[identity] = evidence
    return sorted(
        merged.values(),
        key=lambda evidence: (
            evidence.engine,
            evidence.technique,
            evidence.observation,
        ),
    )


def _earlier_ts(left, right) -> bool:
    if left.tzinfo is None:
        left = left.replace(tzinfo=UTC)
    if right.tzinfo is None:
        right = right.replace(tzinfo=UTC)
    return left < right


def _fused_status(members: tuple[UnifiedFinding, ...]) -> FindingStatus:
    statuses = {member.status for member in members}
    if FindingStatus.VERIFIED in statuses:
        return FindingStatus.VERIFIED
    if statuses == {FindingStatus.DEAD}:
        return FindingStatus.DEAD
    return FindingStatus.CANDIDATE


def _fused_components(members: tuple[UnifiedFinding, ...]) -> dict[str, float]:
    components: dict[str, float] = {}
    used: set[str] = set()
    for _index, member in enumerate(members, start=1):
        engine = next((e.engine for e in member.evidence if e.engine), member.run_id)
        base = f"{engine}:{member.run_id}"
        key = base
        suffix = 1
        while key in used:
            suffix += 1
            key = f"{base}#{suffix}"
        used.add(key)
        components[key] = member.confidence.value
    return components


def fuse_group(group: EntityGroup) -> UnifiedFinding:
    members = group.findings
    evidence = _merge_evidence(members)
    digest_source = f"{group.kind.value}|{group.key}".encode()
    digest = hashlib.sha256(digest_source).hexdigest()[:16]
    asset_value = _canonical_asset_value(group.kind, members, group.key)
    parent = _preferred_parent(members)
    if group.kind is FindingClass.ENDPOINT and not parent:
        parent = host_of(asset_value) or None

    if len(members) == 1:
        source = members[0]
        confidence = Confidence(
            value=source.confidence.value,
            method=source.confidence.method,
            components=dict(source.confidence.components),
        )
    else:
        confidence = Confidence(
            value=noisy_or_confidence(m.confidence.value for m in members),
            method=ConfidenceMethod.NOISY_OR,
            components=_fused_components(members),
        )

    return UnifiedFinding(
        finding_id=f"fusion:{digest}",
        run_id=f"fusion:{digest}",
        kind=group.kind,
        status=_fused_status(members),
        asset_value=asset_value,
        parent=parent,
        confidence=confidence,
        evidence=evidence,
        scope_ok=all(member.scope_ok for member in members),
        discovered_at=min(members, key=_finding_order).discovered_at,
        legacy=members[0].legacy,
        metadata={
            "source": FUSION_SOURCE,
            "entity_key": group.key,
            "source_count": len(members),
            "source_runs": sorted({member.run_id for member in members}),
            "source_finding_ids": [member.finding_id for member in members],
        },
    )


def fuse_findings(
    findings: Iterable[UnifiedFinding],
) -> list[UnifiedFinding]:
    """Fuse every resolved entity, including singleton groups."""
    return [fuse_group(group) for group in resolve_entities(findings)]


def strongest_evidence_strength(
    members: Iterable[UnifiedFinding],
) -> EvidenceStrength | None:
    strengths = [
        member.strongest_evidence() for member in members if member.evidence
    ]
    if not strengths:
        return None
    order = {
        EvidenceStrength.WEAK: 0,
        EvidenceStrength.CORROBORATED: 1,
        EvidenceStrength.STRONG: 2,
    }
    return max(strengths, key=lambda strength: order[strength])


__all__ = [
    "EntityGroup",
    "FUSION_SOURCE",
    "entity_key",
    "fuse_findings",
    "fuse_group",
    "noisy_or_confidence",
    "resolve_entities",
    "strongest_evidence_strength",
]
