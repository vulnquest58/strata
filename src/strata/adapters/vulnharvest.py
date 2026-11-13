"""VulnHarvest report importer (P2).

A VulnHarvest JSON report contains endpoints (with probe status, params, and
interest scoring), secrets (masked previews + hashes), and API schema docs.
Each item becomes a UnifiedFinding; live status codes are the evidence that
lets an imported endpoint be verified or dead.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strata.core.content.secrets import secret_asset_id
from strata.core.content.urls import normalise_url
from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)


def _parse_timestamp(raw: Any, fallback: datetime) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        return fallback
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _as_int_list(values: Any) -> list[int]:
    result: list[int] = []
    for value in values or []:
        try:
            result.append(int(value))
        except (TypeError, ValueError):
            continue
    return result


def _status_from_codes(codes: list[int]) -> FindingStatus:
    if not codes:
        return FindingStatus.CANDIDATE
    if any(200 <= code < 400 for code in codes):
        return FindingStatus.VERIFIED
    if all(code in (404, 410) for code in codes):
        return FindingStatus.DEAD
    return FindingStatus.CANDIDATE


def _clamped_score(value: Any, default: float = 50.0) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(100.0, score))


def _endpoint_finding(
    endpoint: dict, run_id: str, discovered_at: datetime
) -> UnifiedFinding:
    url = endpoint.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("VulnHarvest endpoint is missing a url")
    normalised = normalise_url(url)

    codes = _as_int_list(endpoint.get("status_codes_seen"))
    status = _status_from_codes(codes)
    score = _clamped_score(endpoint.get("interest_score"))
    source = str(endpoint.get("source") or "archive")
    params = endpoint.get("params")
    names = params.get("names") if isinstance(params, dict) else None
    names = [str(name) for name in names] if isinstance(names, list) else []

    observation = f"harvested {normalised} via {source}"
    if codes:
        observation += f" (status={codes})"
    metadata = {
        "source": source,
        "params": names,
        "status_codes_seen": codes,
        "interest_flags": list(endpoint.get("interest_flags") or []),
        "cluster_pattern": str(endpoint.get("cluster_pattern") or ""),
        "waf_protected": bool(endpoint.get("waf_protected")),
        "waf_provider": str(endpoint.get("waf_provider") or ""),
        "notes": str(endpoint.get("notes") or "")[:500],
    }
    discovery_context = endpoint.get("discovery_context")
    if isinstance(discovery_context, dict):
        metadata["discovery_context"] = discovery_context

    return UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.ENDPOINT,
        status=status,
        asset_value=normalised,
        parent=endpoint.get("host") or None,
        confidence=Confidence(
            value=score,
            components={"interest_score": score},
        ),
        evidence=[
            Evidence(
                engine="vulnharvest",
                technique=source,
                observation=observation,
                strength=(
                    EvidenceStrength.CORROBORATED
                    if codes
                    else EvidenceStrength.WEAK
                ),
                meta={
                    "status_codes_seen": codes,
                    "interest_flags": metadata["interest_flags"],
                },
            )
        ],
        discovered_at=discovered_at,
        metadata=metadata,
        legacy={
            key: endpoint[key]
            for key in ("url_normalized", "cluster_pattern", "interest_flags")
            if key in endpoint
        },
    )


def _secret_finding(secret: dict, run_id: str, discovered_at: datetime) -> UnifiedFinding:
    kind = str(secret.get("type") or secret.get("kind") or "unknown")
    preview = str(secret.get("value_preview") or secret.get("value") or "")
    digest = str(secret.get("full_value_hash") or "")
    if not preview and not digest:
        raise ValueError("VulnHarvest secret has neither preview nor hash")
    asset = (
        f"secret:{kind}:{digest[:16]}"
        if digest
        else secret_asset_id(kind, f"{preview}:{secret.get('line_number', '')}")
    )
    confidence = _clamped_score(secret.get("confidence"))
    js_url = str(secret.get("js_file_url") or "")
    line = secret.get("line_number")
    return UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.SECRET,
        status=FindingStatus.CANDIDATE,
        asset_value=asset,
        parent=js_url or None,
        confidence=Confidence(
            value=confidence,
            components={"hunter_confidence": confidence},
        ),
        evidence=[
            Evidence(
                engine="vulnharvest",
                technique="secret_regex",
                observation=(
                    f"{kind} candidate found in {js_url or 'harvested content'}"
                    f" (line {line})"
                ),
                strength=(
                    EvidenceStrength.CORROBORATED
                    if confidence >= 80
                    else EvidenceStrength.WEAK
                ),
                meta={
                    "type": kind,
                    "value_preview": preview[:64],
                    "entropy": secret.get("entropy"),
                    "confidence_label": secret.get("confidence_label"),
                    "js_file_live": secret.get("js_file_live"),
                },
            )
        ],
        discovered_at=discovered_at,
        metadata={
            "type": kind,
            "line_number": line,
            "js_file_url": js_url,
            "confidence_label": str(secret.get("confidence_label") or ""),
        },
    )


def _schema_finding(url: str, run_id: str, discovered_at: datetime) -> UnifiedFinding:
    normalised = normalise_url(url)
    return UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.ENDPOINT,
        status=FindingStatus.CANDIDATE,
        asset_value=normalised,
        confidence=Confidence(value=50.0, components={"api_schema": 50.0}),
        evidence=[
            Evidence(
                engine="vulnharvest",
                technique="api_schema",
                observation=f"API schema document discovered at {normalised}",
                meta={"kind": "api_schema"},
            )
        ],
        discovered_at=discovered_at,
        metadata={"source": "api_schema"},
    )


def parse_vulnharvest_report(
    report: dict, *, now: datetime | None = None
) -> Iterator[UnifiedFinding]:
    if not isinstance(report, dict):
        raise ValueError("VulnHarvest report must be a JSON object")
    meta = report.get("meta") or {}
    if not isinstance(meta, dict):
        raise ValueError("VulnHarvest report meta must be an object")
    endpoints = report.get("endpoints") or []
    if not isinstance(endpoints, list):
        raise ValueError("VulnHarvest report endpoints must be a list")
    secrets = report.get("secrets") or []
    if not isinstance(secrets, list):
        raise ValueError("VulnHarvest report secrets must be a list")
    api_schemas = report.get("api_schemas") or []
    if not isinstance(api_schemas, list):
        raise ValueError("VulnHarvest report api_schemas must be a list")

    target = str(meta.get("target") or "unknown")
    harvest_id = str(meta.get("harvest_id") or target)
    run_id = f"vulnharvest:{harvest_id}"
    fallback = now or datetime.now(UTC)
    discovered_at = _parse_timestamp(meta.get("started_at"), fallback)

    for index, endpoint in enumerate(endpoints):
        if not isinstance(endpoint, dict):
            raise ValueError(f"VulnHarvest endpoints[{index}] must be an object")
        try:
            yield _endpoint_finding(endpoint, run_id, discovered_at)
        except ValueError as exc:
            raise ValueError(f"VulnHarvest endpoints[{index}]: {exc}") from exc
    for index, secret in enumerate(secrets):
        if not isinstance(secret, dict):
            raise ValueError(f"VulnHarvest secrets[{index}] must be an object")
        try:
            yield _secret_finding(secret, run_id, discovered_at)
        except ValueError as exc:
            raise ValueError(f"VulnHarvest secrets[{index}]: {exc}") from exc
    for index, schema in enumerate(api_schemas):
        if not isinstance(schema, dict):
            raise ValueError(f"VulnHarvest api_schemas[{index}] must be an object")
        url = schema.get("url")
        if not isinstance(url, str) or not url.strip():
            raise ValueError(f"VulnHarvest api_schemas[{index}]: missing url")
        try:
            yield _schema_finding(url, run_id, discovered_at)
        except ValueError as exc:
            raise ValueError(f"VulnHarvest api_schemas[{index}]: {exc}") from exc


def load_vulnharvest_report(
    path: str | Path, *, now: datetime | None = None
) -> Iterator[UnifiedFinding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    yield from parse_vulnharvest_report(data, now=now)
