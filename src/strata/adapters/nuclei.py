"""Nuclei output importer and target exporter.

Nuclei emits one JSON object per line (`-json` / `-jsonl`). Each matcher
result is an actual detection executed against the target, so imported
results become `kind=VULN` findings with status `verified` — the template
matched at request time — while keeping the provenance (template id,
severity, CVE, tags) in evidence and metadata.

Strata's belief model treats external scanner output as a source with its
own reliability: nuclei detections are strong evidence but never a
substitute for the CVE-window reasoning in `core/vulns.py` (those carry
engine `cve_map`; these carry engine `nuclei`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

# nuclei severity -> belief confidence
_SEVERITY_CONFIDENCE = {
    "critical": 90.0,
    "high": 80.0,
    "medium": 70.0,
    "low": 60.0,
    "info": 40.0,
    "unknown": 50.0,
}


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


def parse_nuclei_result(result: dict, *, now: datetime | None = None) -> UnifiedFinding:
    if not isinstance(result, dict):
        raise ValueError("nuclei result must be a JSON object")
    host = result.get("host") or result.get("matched-at") or result.get("url")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("nuclei result has no host/matched-at")
    host = host.strip()
    info = result.get("info") if isinstance(result.get("info"), dict) else {}
    template_id = str(
        result.get("template-id") or result.get("templateID") or result.get("id") or ""
    ).strip()
    if not template_id:
        raise ValueError("nuclei result has no template id")
    name = str(info.get("name") or template_id)
    severity = str(info.get("severity") or "unknown").lower()
    classification = (
        info.get("classification")
        if isinstance(info.get("classification"), dict)
        else {}
    )
    cve = str(classification.get("cve-id") or "").strip() or None
    tags = [str(t) for t in (info.get("tags") or []) if str(t)]
    matched_at = str(result.get("matched-at") or host)
    matcher_status = result.get("matcher-status")
    if matcher_status is None:
        matcher_status = result.get("matcher_status", True)
    matched = bool(matcher_status)

    extracted = result.get("extracted-results")
    extracted = (
        [str(item) for item in extracted]
        if isinstance(extracted, list)
        else []
    )

    fallback = now or datetime.now(UTC)
    discovered_at = _parse_timestamp(result.get("timestamp"), fallback)
    confidence_value = _SEVERITY_CONFIDENCE.get(severity, 50.0)
    digest = hashlib.sha256(f"nuclei|{host}|{template_id}".encode()).hexdigest()[:16]

    observation = f"nuclei template {template_id} ({name}) matched {matched_at}"
    if cve:
        observation += f" [{cve}]"

    status = FindingStatus.VERIFIED if matched else FindingStatus.CANDIDATE
    strength = EvidenceStrength.CORROBORATED if matched else EvidenceStrength.WEAK

    meta = {
        "template_id": template_id,
        "severity": severity,
        "cve": cve,
        "tags": tags,
        "matcher_status": matched,
        "type": str(result.get("type") or ""),
        "extracted": extracted[:10],
        "description": str(info.get("description") or "")[:500],
    }

    return UnifiedFinding(
        finding_id=f"nuclei:{digest}",
        run_id=f"nuclei:{template_id}",
        kind=FindingClass.VULN,
        status=status,
        asset_value=host,
        parent=host,
        confidence=Confidence(
            value=confidence_value,
            method=ConfidenceMethod.BAYESIAN,
            components={"nuclei": confidence_value},
        ),
        evidence=[
            Evidence(
                engine="nuclei",
                technique="template_match",
                observation=observation,
                strength=strength,
                meta={
                    "template_id": template_id,
                    "severity": severity,
                    "cve": cve,
                    "tags": tags,
                    "matched_at": matched_at,
                    "extracted": extracted[:10],
                },
            )
        ],
        discovered_at=discovered_at,
        metadata=meta,
    )


def load_nuclei_jsonl(path: str | Path, *, now: datetime | None = None) -> Iterator[UnifiedFinding]:
    """Read a nuclei -jsonl (or single-line -json) stream file."""
    for line_number, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"nuclei line {line_number}: invalid JSON ({exc})") from exc
        try:
            yield parse_nuclei_result(record, now=now)
        except ValueError as exc:
            raise ValueError(f"nuclei line {line_number}: {exc}") from exc


def load_nuclei_json(path: str | Path, *, now: datetime | None = None) -> Iterator[UnifiedFinding]:
    """Read a nuclei -json stream file (one JSON array or NDJSON)."""
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return
    if stripped.startswith("["):
        records = json.loads(stripped)
        if not isinstance(records, list):
            raise ValueError("nuclei JSON array expected")
        for index, record in enumerate(records):
            try:
                yield parse_nuclei_result(record, now=now)
            except ValueError as exc:
                raise ValueError(f"nuclei record {index}: {exc}") from exc
        return
    yield from load_nuclei_jsonl(path, now=now)


def export_nuclei_targets(findings, *, include_candidates: bool = False) -> list[str]:
    """URL target list for a nuclei run, ranked most valuable first.

    Includes verified live hosts and endpoints; optionally candidates.
    Dead claims never make the target list.
    """
    from strata.core.schema.models import FindingClass, FindingStatus

    statuses = {FindingStatus.VERIFIED}
    if include_candidates:
        statuses.add(FindingStatus.CANDIDATE)
    kinds = {
        FindingClass.LIVE_HOST,
        FindingClass.ENDPOINT,
        FindingClass.SUBDOMAIN,
    }
    urls: set[str] = set()
    for finding in findings:
        if finding.kind not in kinds or finding.status not in statuses:
            continue
        value = finding.asset_value.strip()
        if value.startswith("http://") or value.startswith("https://"):
            urls.add(value.rstrip("/"))
        else:
            urls.add(f"https://{value}")
    return sorted(urls, key=lambda u: (u.count("/"), u))


__all__ = [
    "export_nuclei_targets",
    "load_nuclei_json",
    "load_nuclei_jsonl",
    "parse_nuclei_result",
]
