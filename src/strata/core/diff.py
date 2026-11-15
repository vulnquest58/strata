"""Longitudinal surface snapshots and drift diffs.

A snapshot freezes the surface belief state (kind, asset, status, confidence)
at a point in time. Diffing a snapshot against the current store turns two
scans into a statement about drift: what appeared, what died, what changed
status, and how much confidence moved. This is the substrate for tracking
infrastructure churn over weeks instead of treating every scan as new.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from strata.core.content.urls import normalise_url
from strata.core.schema.models import FindingClass, UnifiedFinding


def snapshot_key(kind: str, asset_value: str) -> str:
    value = asset_value.strip().lower()
    if kind == FindingClass.ENDPOINT.value:
        try:
            value = normalise_url(value)
        except ValueError:
            pass
    return f"{kind}|{value}"


@dataclass
class SurfaceSnapshot:
    target: str
    exported_at: str
    strata_version: str
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "exported_at": self.exported_at,
            "strata_version": self.strata_version,
            "entries": self.entries,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SurfaceSnapshot:
        if not isinstance(data, dict):
            raise ValueError("snapshot must be a JSON object")
        entries = data.get("entries")
        if not isinstance(entries, dict):
            raise ValueError("snapshot is missing an entries object")
        return cls(
            target=str(data.get("target", "")),
            exported_at=str(data.get("exported_at", "")),
            strata_version=str(data.get("strata_version", "")),
            entries={str(k): dict(v) for k, v in entries.items() if isinstance(v, dict)},
        )


def snapshot_from_findings(
    findings: Iterable[UnifiedFinding],
    *,
    target: str,
    strata_version: str,
    now: datetime | None = None,
) -> SurfaceSnapshot:
    timestamp = (now or datetime.now(UTC)).isoformat()
    snapshot = SurfaceSnapshot(
        target=target,
        exported_at=timestamp,
        strata_version=strata_version,
    )
    for finding in findings:
        snapshot.entries[snapshot_key(finding.kind.value, finding.asset_value)] = {
            "status": finding.status.value,
            "confidence": finding.confidence.value,
            "discovered_at": finding.discovered_at.isoformat(),
        }
    return snapshot


@dataclass
class SurfaceDiff:
    baseline_target: str
    current_target: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    status_changes: list[tuple[str, str, str]] = field(default_factory=list)
    confidence_changes: list[tuple[str, float, float]] = field(default_factory=list)

    @property
    def churn(self) -> int:
        return len(self.added) + len(self.removed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_target": self.baseline_target,
            "current_target": self.current_target,
            "added": self.added,
            "removed": self.removed,
            "status_changes": [
                {"key": key, "from": old, "to": new}
                for key, old, new in self.status_changes
            ],
            "confidence_changes": [
                {"key": key, "from": old, "to": new}
                for key, old, new in self.confidence_changes
            ],
            "churn": self.churn,
        }


def diff_snapshots(baseline: SurfaceSnapshot, current: SurfaceSnapshot) -> SurfaceDiff:
    diff = SurfaceDiff(
        baseline_target=baseline.target,
        current_target=current.target,
    )
    baseline_keys = set(baseline.entries)
    current_keys = set(current.entries)
    diff.added = sorted(current_keys - baseline_keys)
    diff.removed = sorted(baseline_keys - current_keys)
    for key in sorted(baseline_keys & current_keys):
        old = baseline.entries[key]
        new = current.entries[key]
        old_status = str(old.get("status", ""))
        new_status = str(new.get("status", ""))
        if old_status != new_status:
            diff.status_changes.append((key, old_status, new_status))
        old_conf = float(old.get("confidence", 0.0))
        new_conf = float(new.get("confidence", 0.0))
        if abs(new_conf - old_conf) >= 0.05:
            diff.confidence_changes.append((key, old_conf, new_conf))
    return diff


def diff_markdown(diff: SurfaceDiff, baseline: SurfaceSnapshot, current: SurfaceSnapshot) -> str:
    lines = [
        "# Strata surface diff",
        "",
        f"- baseline: {baseline.exported_at or 'unknown'} (target {baseline.target or 'n/a'})",
        f"- current:  {current.exported_at or 'now'} (target {current.target or 'n/a'})",
        f"- churn: {diff.churn} (+{len(diff.added)} new / -{len(diff.removed)} gone)",
        "",
        "## New assets",
        "",
    ]
    lines.extend(f"- {key}" for key in diff.added)
    if not diff.added:
        lines.append("- none")
    lines.extend(["", "## Gone assets", ""])
    lines.extend(f"- {key}" for key in diff.removed)
    if not diff.removed:
        lines.append("- none")
    lines.extend(["", "## Status changes", "", "| Key | From | To |", "|---|---|---|"])
    if diff.status_changes:
        lines.extend(f"| {key} | {old} | {new} |" for key, old, new in diff.status_changes)
    else:
        lines.append("| - | - | - |")
    lines.extend(
        [
            "",
            "## Confidence shifts",
            "",
            "| Key | From | To | Delta |",
            "|---|---:|---:|---:|",
        ]
    )
    if diff.confidence_changes:
        lines.extend(
            f"| {key} | {old:.1f} | {new:.1f} | {new - old:+.1f} |"
            for key, old, new in diff.confidence_changes
        )
    else:
        lines.append("| - | - | - | - |")
    return "\n".join(lines) + "\n"


__all__ = [
    "SurfaceDiff",
    "SurfaceSnapshot",
    "diff_markdown",
    "diff_snapshots",
    "snapshot_from_findings",
    "snapshot_key",
]
