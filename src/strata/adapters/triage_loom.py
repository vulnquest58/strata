"""Triage Loom output importer (P4).

Reads Triage Loom's high/low-confidence JSONL exports and converts each
triaged cluster into Strata endpoint and parameter findings, preserving the
corroboration layers and novelty context that produced the ranking.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from strata.core.content.urls import normalise_url
from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

_LAYER_SCORES = {
    "liveness": 80.0,
    "archive_wayback": 65.0,
    "archive_commoncrawl": 65.0,
    "archive_urlscan": 65.0,
    "param_archive_static": 75.0,
    "param_js_static": 75.0,
    "param_openapi": 75.0,
}


def _layer_score(layer: str) -> float:
    return _LAYER_SCORES.get(layer, 60.0)


def _layers(record: dict[str, Any]) -> list[str]:
    raw = record.get("corroboration_layers") or []
    if not isinstance(raw, list):
        return []
    layers: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, dict):
            layer = str(item.get("layer") or item.get("name") or "")
        else:
            layer = str(item)
        layer = layer.strip().lower()
        if layer and layer not in seen:
            seen.add(layer)
            layers.append(layer)
    return layers


def _run_id(record: dict[str, Any]) -> str:
    root = str(record.get("root_domain") or "unknown")
    asset = str(record.get("asset_id") or "unknown")
    endpoint = str(record.get("endpoint_pattern") or "unknown")
    return f"triage_loom:{root}:{asset}:{endpoint}"


def _endpoint_url(record: dict[str, Any]) -> str:
    raw = str(record.get("representative_url") or "").strip()
    if raw:
        try:
            return normalise_url(raw)
        except ValueError:
            return raw.lower()
    raw = str(record.get("endpoint_pattern") or "").strip()
    if raw:
        return raw.lower()
    raise ValueError("Triage Loom record is missing a representative endpoint")


def _endpoint_evidence(
    record: dict[str, Any], layers: list[str], url: str
) -> list[Evidence]:
    if not layers:
        return [
            Evidence(
                engine="triage_loom",
                technique="endpoint_cluster",
                observation=f"unranked cluster for {url}",
                strength=EvidenceStrength.WEAK,
                meta={
                    "endpoint_pattern": record.get("endpoint_pattern"),
                    "cluster_size": record.get("cluster_size"),
                },
            )
        ]
    evidence: list[Evidence] = []
    for layer in layers:
        strength = EvidenceStrength.STRONG if layer == "liveness" else EvidenceStrength.CORROBORATED
        evidence.append(
            Evidence(
                engine="triage_loom",
                technique=layer,
                observation=f"corroboration layer {layer} for {url}",
                strength=strength,
                meta={
                    "layer": layer,
                    "endpoint_pattern": record.get("endpoint_pattern"),
                    "cluster_size": record.get("cluster_size"),
                },
            )
        )
    return evidence


def _endpoint_confidence(
    record: dict[str, Any], layers: list[str]
) -> Confidence:
    if layers:
        components = {layer: _layer_score(layer) for layer in layers}
        value = _noisy_or(components.values())
    else:
        components = {"endpoint_cluster": 35.0}
        value = 35.0
    novelty = record.get("novelty")
    if isinstance(novelty, dict) and isinstance(novelty.get("total"), (int, float)):
        components["novelty"] = max(0.0, min(100.0, float(novelty["total"]) * 100.0))
    return Confidence(
        value=value,
        method=ConfidenceMethod.NOISY_OR,
        components=components,
    )


def _noisy_or(values) -> float:
    survival = 1.0
    for value in values:
        survival *= 1.0 - max(0.0, min(100.0, value)) / 100.0
    return round(100.0 * (1.0 - survival), 1)


def parse_triage_loom_record(record: dict[str, Any]) -> Iterator[UnifiedFinding]:
    if not isinstance(record, dict):
        raise ValueError("Triage Loom record must be a JSON object")
    root_domain = str(record.get("root_domain") or "").strip().lower()
    asset_id = str(record.get("asset_id") or "").strip().lower()
    if not root_domain and not asset_id:
        raise ValueError("Triage Loom record is missing root_domain and asset_id")

    endpoint_url = _endpoint_url(record)
    layers = _layers(record)
    run_id = _run_id(record)
    parent = asset_id or root_domain
    high_confidence = bool(record.get("is_high_confidence"))

    priority = record.get("investigation_priority")
    cluster_size = record.get("cluster_size")
    metadata = {
        "source": "triage_loom",
        "endpoint_pattern": record.get("endpoint_pattern"),
        "representative_url": endpoint_url,
        "cluster_size": cluster_size if isinstance(cluster_size, int) else None,
        "corroboration_layers": layers,
        "investigation_priority": (
            float(priority) if isinstance(priority, (int, float)) else None
        ),
        "is_high_confidence": high_confidence,
    }
    if isinstance(record.get("novelty"), dict):
        metadata["novelty"] = record["novelty"]
    if isinstance(record.get("first_seen"), str):
        metadata["first_seen"] = record["first_seen"]
    if isinstance(record.get("last_confirmed_live"), str):
        metadata["last_confirmed_live"] = record["last_confirmed_live"]

    endpoint = UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.ENDPOINT,
        status=(
            FindingStatus.VERIFIED if high_confidence else FindingStatus.CANDIDATE
        ),
        asset_value=endpoint_url,
        parent=parent,
        confidence=_endpoint_confidence(record, layers),
        evidence=_endpoint_evidence(record, layers, endpoint_url),
        metadata=metadata,
    )
    yield endpoint

    parameters = record.get("parameters") or []
    if not isinstance(parameters, list):
        return
    for raw in parameters:
        if isinstance(raw, dict):
            name = str(raw.get("name") or "")
        else:
            name = str(raw)
        name = name.strip().lower()
        if not name:
            continue
        yield UnifiedFinding(
            run_id=run_id,
            kind=FindingClass.PARAM,
            status=(
                FindingStatus.VERIFIED if high_confidence else FindingStatus.CANDIDATE
            ),
            asset_value=name,
            parent=endpoint_url,
            confidence=Confidence(
                value=70.0 if layers else 35.0,
                method=ConfidenceMethod.NOISY_OR,
                components={"param_corroboration": 70.0 if layers else 35.0},
            ),
            evidence=[
                Evidence(
                    engine="triage_loom",
                    technique="parameter_corroboration",
                    observation=f"parameter {name} corroborated for {endpoint_url}",
                    strength=(
                        EvidenceStrength.CORROBORATED if layers else EvidenceStrength.WEAK
                    ),
                    meta={
                        "parameter": name,
                        "endpoint": endpoint_url,
                        "endpoint_pattern": record.get("endpoint_pattern"),
                        "cluster_size": cluster_size,
                    },
                )
            ],
            metadata={
                "source": "triage_loom",
                "endpoint": endpoint_url,
                "endpoint_pattern": record.get("endpoint_pattern"),
                "corroboration_layers": layers,
                "is_high_confidence": high_confidence,
            },
        )


def load_triage_loom_jsonl(path: str | Path) -> Iterator[UnifiedFinding]:
    """Load a Triage Loom high/low-confidence JSONL export."""
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
                yield from parse_triage_loom_record(record)
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc


__all__ = [
    "load_triage_loom_jsonl",
    "parse_triage_loom_record",
]
