"""jsast report importer (P2).

jsast's JSON export carries AST-derived endpoints and secrets. The importer
maps those artifacts to ENDPOINT/SECRET findings, preserving method, line,
category, and scoring metadata while never storing raw secret values.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strata.core.content.secrets import mask_secret, secret_asset_id
from strata.core.content.urls import normalise_url
from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)


def _score(item: dict) -> float:
    score = item.get("score")
    if isinstance(score, (int, float)):
        return max(0.0, min(100.0, float(score)))
    confidence = item.get("confidence")
    if isinstance(confidence, (int, float)):
        value = float(confidence)
        if 0.0 < value <= 1.0:
            value *= 100.0
        return max(0.0, min(100.0, value))
    return 50.0


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _params(item: dict) -> list[str]:
    params = item.get("params")
    if isinstance(params, dict):
        return sorted(str(key) for key in params)
    if isinstance(params, list):
        return [str(param) for param in params]
    return []


def _endpoint_finding(
    item: dict, source: str, run_id: str, discovered_at: datetime
) -> UnifiedFinding:
    url = item.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("jsast endpoint is missing a url")
    normalised = normalise_url(url)
    method = str(item.get("method") or "GET").upper()
    category = str(item.get("category") or "ast_endpoint")
    confidence = _score(item)
    high_value = bool(item.get("high_value"))
    headers = item.get("headers")
    header_names = sorted(str(key) for key in headers) if isinstance(headers, dict) else []
    line = _as_int(item.get("source_line"))
    return UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.ENDPOINT,
        status=(
            FindingStatus.VERIFIED if item.get("validated") else FindingStatus.CANDIDATE
        ),
        asset_value=normalised,
        parent=source or None,
        confidence=Confidence(
            value=confidence,
            components={"ast_score": confidence},
        ),
        evidence=[
            Evidence(
                engine="jsast",
                technique=category,
                observation=f"AST endpoint {method} {normalised} (line {line})",
                strength=(
                    EvidenceStrength.CORROBORATED
                    if high_value or confidence >= 70
                    else EvidenceStrength.WEAK
                ),
                meta={
                    "method": method,
                    "params": _params(item),
                    "header_names": header_names,
                    "auth_required": bool(item.get("auth_required")),
                    "high_value": high_value,
                    "source_line": line,
                },
            )
        ],
        discovered_at=discovered_at,
        metadata={
            "method": method,
            "params": _params(item),
            "header_names": header_names,
            "auth_required": bool(item.get("auth_required")),
            "high_value": high_value,
            "category": category,
            "priority": str(item.get("priority") or ""),
            "is_reachable": item.get("is_reachable"),
            "is_dead_code": item.get("is_dead_code"),
            "validated": bool(item.get("validated")),
        },
    )


def _secret_finding(
    item: dict, source: str, run_id: str, discovered_at: datetime
) -> UnifiedFinding:
    kind = str(item.get("kind") or "unknown")
    value = str(item.get("value") or "")
    if not value:
        raise ValueError("jsast secret is missing a value")
    line = _as_int(item.get("source_line"))
    asset = secret_asset_id(kind, f"{value}:{line}:{source}")
    confidence = _score(item)
    preview = value if "..." in value else mask_secret(value)
    return UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.SECRET,
        status=FindingStatus.CANDIDATE,
        asset_value=asset,
        parent=source or None,
        confidence=Confidence(
            value=confidence,
            components={"ast_score": confidence},
        ),
        evidence=[
            Evidence(
                engine="jsast",
                technique="ast_secret",
                observation=f"{kind} secret candidate (line {line})",
                strength=(
                    EvidenceStrength.CORROBORATED
                    if confidence >= 70
                    else EvidenceStrength.WEAK
                ),
                meta={
                    "kind": kind,
                    "value_preview": preview[:64],
                    "variable_name": str(item.get("variable_name") or ""),
                    "entropy": item.get("entropy"),
                    "source_line": line,
                    "is_dead_code": item.get("is_dead_code"),
                    "validated": bool(item.get("validated")),
                },
            )
        ],
        discovered_at=discovered_at,
        metadata={
            "kind": kind,
            "line_number": line,
            "variable_name": str(item.get("variable_name") or ""),
            "source": source,
        },
    )


def parse_jsast_report(report: dict, *, now: datetime | None = None) -> Iterator[UnifiedFinding]:
    if not isinstance(report, dict):
        raise ValueError("jsast report must be a JSON object")
    endpoints = report.get("endpoints") or []
    if not isinstance(endpoints, list):
        raise ValueError("jsast report endpoints must be a list")
    secrets = report.get("secrets") or []
    if not isinstance(secrets, list):
        raise ValueError("jsast report secrets must be a list")

    source = str(report.get("source") or "report")
    run_id = f"jsast:{source}"
    discovered_at = now or datetime.now(UTC)

    for index, endpoint in enumerate(endpoints):
        if not isinstance(endpoint, dict):
            raise ValueError(f"jsast endpoints[{index}] must be an object")
        try:
            yield _endpoint_finding(endpoint, source, run_id, discovered_at)
        except ValueError as exc:
            raise ValueError(f"jsast endpoints[{index}]: {exc}") from exc
    for index, secret in enumerate(secrets):
        if not isinstance(secret, dict):
            raise ValueError(f"jsast secrets[{index}] must be an object")
        try:
            yield _secret_finding(secret, source, run_id, discovered_at)
        except ValueError as exc:
            raise ValueError(f"jsast secrets[{index}]: {exc}") from exc


def _extract_json_object(text: str) -> dict:
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start >= 0:
        try:
            value, _ = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict) and (
            "endpoints" in value or "secrets" in value or "stats" in value
        ):
            return value
        start = text.find("{", start + 1)
    raise ValueError("no jsast JSON report found in output")


def load_jsast_report(
    path: str | Path, *, now: datetime | None = None
) -> Iterator[UnifiedFinding]:
    """Load a jsast JSON export, tolerating log lines before the payload."""
    text = Path(path).read_text(encoding="utf-8")
    yield from parse_jsast_report(_extract_json_object(text), now=now)
