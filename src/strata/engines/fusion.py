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
from strata.core.reliability import collapse_by_family, source_family
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


def _signal_components(finding: UnifiedFinding) -> dict[str, float]:
    """Flatten a finding into independent confidence signals.

    Prior fusion findings already contain their source signals; reusing those
    keys prevents double-counting when an entity is fused again after new
    evidence arrives.
    """
    if _is_fusion_finding(finding):
        return {
            str(key): float(value)
            for key, value in finding.confidence.components.items()
            if isinstance(value, (int, float))
        }
    engine = next((e.engine for e in finding.evidence if e.engine), finding.run_id)
    return {f"{engine}:{finding.run_id}": finding.confidence.value}


def _collect_components(members: tuple[UnifiedFinding, ...]) -> dict[str, float]:
    components: dict[str, float] = {}
    for member in members:
        for key, value in _signal_components(member).items():
            components.setdefault(key, value)
    return components


def _source_finding_ids(members: tuple[UnifiedFinding, ...]) -> list[str]:
    ids: list[str] = []
    for member in members:
        prior = member.metadata.get("source_finding_ids")
        if _is_fusion_finding(member) and isinstance(prior, list):
            ids.extend(str(item) for item in prior)
        else:
            ids.append(member.finding_id)
    return sorted(set(ids))


def _source_runs(members: tuple[UnifiedFinding, ...]) -> list[str]:
    runs: set[str] = set()
    for member in members:
        prior = member.metadata.get("source_runs")
        if _is_fusion_finding(member) and isinstance(prior, list):
            runs.update(str(item) for item in prior)
        else:
            runs.add(member.run_id)
    return sorted(runs)


def _merge_metadata(members: tuple[UnifiedFinding, ...]) -> dict[str, object]:
    """Preserve engine metadata (tech stack, params, headers) through fusion."""
    internal = {
        "source",
        "entity_key",
        "source_count",
        "source_runs",
        "source_finding_ids",
    }
    merged: dict[str, object] = {}
    for member in members:
        for key, value in member.metadata.items():
            if key in internal:
                continue
            if key not in merged:
                merged[key] = value
            elif isinstance(merged[key], list) and isinstance(value, list):
                seen = {str(item) for item in merged[key]}
                merged[key] = [
                    *merged[key],
                    *(item for item in value if str(item) not in seen),
                ]
    return merged


def _fused_components(members: tuple[UnifiedFinding, ...]) -> dict[str, float]:
    return _collect_components(members)


def fuse_group(
    group: EntityGroup,
    *,
    reliability: dict[str, float] | None = None,
) -> UnifiedFinding:
    members = group.findings
    evidence = _merge_evidence(members)
    digest_source = f"{group.kind.value}|{group.key}".encode()
    digest = hashlib.sha256(digest_source).hexdigest()[:16]
    asset_value = _canonical_asset_value(group.kind, members, group.key)
    parent = _preferred_parent(members)
    if group.kind is FindingClass.ENDPOINT and not parent:
        parent = host_of(asset_value) or None

    components = _collect_components(members)
    weights = reliability or {}
    statuses = {member.status for member in members}
    contested = FindingStatus.DEAD in statuses and statuses != {FindingStatus.DEAD}
    if len(members) == 1 and not _is_fusion_finding(members[0]):
        source = members[0]
        confidence = Confidence(
            value=source.confidence.value,
            method=source.confidence.method,
            components=dict(source.confidence.components),
        )
    elif len(components) <= 1:
        value = next(iter(components.values()), 0.0)
        confidence = Confidence(
            value=value,
            method=ConfidenceMethod.NOISY_OR,
            components=components,
        )
    else:
        weighted = {
            key: value * max(0.0, min(1.0, weights.get(key.split(":", 1)[0], 1.0)))
            for key, value in components.items()
        }
        # Correlated sources must not multiply: collapse to the strongest
        # signal per evidence family, then combine families with noisy-OR.
        family_components, _raw = collapse_by_family(weighted)
        confidence = Confidence(
            value=noisy_or_confidence(family_components.values()),
            method=ConfidenceMethod.NOISY_OR,
            components=components,
        )

    metadata = {
        **_merge_metadata(members),
        "source": FUSION_SOURCE,
        "entity_key": group.key,
        "source_count": len({source_family(key) for key in components}),
        "source_count_raw": len(components),
        "source_runs": _source_runs(members),
        "source_finding_ids": _source_finding_ids(members),
    }
    if contested:
        metadata["contested"] = True

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
        metadata=metadata,
    )


def fuse_findings(
    findings: Iterable[UnifiedFinding],
    *,
    reliability: dict[str, float] | None = None,
) -> list[UnifiedFinding]:
    """Fuse every resolved entity, including singleton groups."""
    return [
        fuse_group(group, reliability=reliability)
        for group in resolve_entities(findings)
    ]


def superseded_finding_ids(fused: UnifiedFinding) -> list[str]:
    """Raw finding IDs replaced by this fused entity (never the fused row)."""
    ids = fused.metadata.get("source_finding_ids")
    if not isinstance(ids, list):
        return []
    return [str(item) for item in ids if str(item) != fused.finding_id]


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
    "superseded_finding_ids",
]
