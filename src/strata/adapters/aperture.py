"""Aperture JSONL importer: aperture's per-discovery records become
UnifiedFinding rows with per-source evidence preserved.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

_REQUIRED_FIELDS = (
    "asset_id",
    "asset_type",
    "source_plugin",
    "per_source_raw_confidence",
    "adjusted_confidence",
    "consensus_count",
    "discovered_at",
)


def _parse_discovered_at(raw: str) -> datetime:
    cleaned = raw.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _evidence_strength(consensus_count: int) -> EvidenceStrength:
    if consensus_count >= 3:
        return EvidenceStrength.STRONG
    if consensus_count == 2:
        return EvidenceStrength.CORROBORATED
    return EvidenceStrength.WEAK


def parse_aperture_record(record: dict) -> UnifiedFinding:
    missing = [f for f in _REQUIRED_FIELDS if f not in record]
    if missing:
        raise ValueError(f"aperture record missing fields: {missing}")

    if record["asset_type"] not in ("subdomain", "domain"):
        raise ValueError(
            f"unsupported asset_type '{record['asset_type']}' for P0 importer"
        )

    per_source: dict[str, float] = {
        str(k): float(v) for k, v in record["per_source_raw_confidence"].items()
    }
    sources = [s.strip() for s in str(record["source_plugin"]).split(",") if s.strip()]
    if not sources:
        raise ValueError("aperture record has an empty source_plugin")

    consensus = int(record.get("consensus_count", 1))
    strength = _evidence_strength(consensus)

    evidence = []
    for source in sources:
        meta = dict(record.get("metadata") or {})
        meta["resolved_ips"] = list(record.get("resolved_ips") or [])
        meta["aperture_id"] = record.get("id")
        meta["scan_id"] = record.get("scan_id")
        evidence.append(
            Evidence(
                engine=source,
                technique=meta.get("source", "passive_discovery"),
                observation=(
                    f"aperture discovered {record['asset_id']} "
                    f"(consensus={consensus})"
                ),
                strength=strength,
                ts=_parse_discovered_at(record["discovered_at"]),
                meta=meta,
            )
        )

    legacy = {
        k: record[k]
        for k in (
            "id",
            "scan_id",
            "raw_confidence",
            "combined_confidence",
            "effective_confidence",
            "decay_factor",
            "temporal_stability",
        )
        if k in record
    }

    return UnifiedFinding(
        run_id=f"aperture:{record.get('scan_id', 'unknown')}",
        kind=FindingClass.SUBDOMAIN,
        status=FindingStatus.CANDIDATE,
        asset_value=str(record["asset_id"]),
        parent=record.get("parent_asset"),
        confidence=Confidence(
            value=float(record["adjusted_confidence"]),
            method="imported",
            components=per_source,
        ),
        evidence=evidence,
        discovered_at=_parse_discovered_at(record["discovered_at"]),
        legacy=legacy,
        metadata=dict(record.get("metadata") or {}),
    )


def load_aperture_jsonl(path: str | Path) -> Iterator[UnifiedFinding]:
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            try:
                yield parse_aperture_record(record)
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc
