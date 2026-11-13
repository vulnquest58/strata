"""
Investigation Priority Ranking + Explain command backend.

investigation_priority() is the single formula that determines the order in which
a security researcher should review findings. Every factor is informational:

    priority = corroboration_layers × novelty_score × min(structural_complexity, 3.0)

- corroboration_layers: number of filter stages that confirmed this finding (1–5).
  More layers = more confidence it's a real, distinct target.
- novelty_score: from Filter 5 (0–1). Unusual infra/recency/uniqueness.
- structural_complexity: number of unique parameters + HTTP methods observed.
  Capped at 3.0 to prevent one endpoint with 50 parameters from dominating the list.

The explain() function produces a full human-readable audit trail for any finding,
answering: "Why did this endpoint receive this priority score?"
"""
from __future__ import annotations

from typing import Any

from triage_loom.models import CorroborationLayer, TriagedFinding


def investigation_priority(finding: TriagedFinding) -> float:
    """
    Compute the investigation priority for a triaged finding.
    All components are structural/statistical — zero relation to vulnerability likelihood.

    Returns a float. Higher = review sooner.
    """
    corroboration = float(finding.corroboration_count)  # 0–5
    novelty = finding.novelty.total if finding.novelty else 0.5

    # structural_complexity = unique parameter count (capped at 3 to prevent outlier dominance)
    param_count = float(len(finding.parameters))
    structural_complexity = min(param_count, 3.0) if param_count > 0 else 0.5

    return round(corroboration * novelty * structural_complexity, 4)


def explain(finding: TriagedFinding) -> dict[str, Any]:
    """
    Produce a full audit trail for a triaged finding.
    Every field explains exactly where its value came from and why.

    Returns a structured dict suitable for CLI display or JSON export.
    This is the implementation backing the `triage-loom explain` command.
    """
    corroboration_detail = _explain_corroboration(finding)
    novelty_detail = _explain_novelty(finding)
    priority_detail = _explain_priority(finding)

    return {
        "endpoint_pattern": finding.endpoint_pattern,
        "representative_url": finding.representative_url,
        "cluster_size": finding.cluster_size,
        "confidence_tier": "HIGH" if finding.is_high_confidence else "LOW",
        "investigation_priority": finding.investigation_priority,
        "archive_sources_failed": finding.archive_sources_failed,

        "corroboration": corroboration_detail,
        "novelty": novelty_detail,
        "priority_breakdown": priority_detail,

        "parameters": {
            "corroborated": finding.parameters,
            "count": len(finding.parameters),
        },

        "infra_context": finding.infra_context,
        "temporal": {
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "last_confirmed_live": finding.last_confirmed_live.isoformat()
            if finding.last_confirmed_live
            else None,
        },
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _explain_corroboration(finding: TriagedFinding) -> dict[str, Any]:
    layer_explanations = {
        CorroborationLayer.liveness:             "HTTP probe returned a response (host is live)",
        CorroborationLayer.archive_wayback:      "URL found in Wayback Machine CDX index",
        CorroborationLayer.archive_commoncrawl:  "URL found in Common Crawl index",
        CorroborationLayer.archive_urlscan:      "URL found in URLScan.io scan results",
        CorroborationLayer.param_archive_static: "Parameters extracted from archived query strings",
        CorroborationLayer.param_js_static:      "Parameters extracted from linked JavaScript files",
        CorroborationLayer.param_openapi:        "Parameters extracted from OpenAPI/Swagger spec",
    }

    layers_with_explanations = [
        {
            "layer": layer.value,
            "explanation": layer_explanations.get(layer, "unknown"),
        }
        for layer in finding.corroboration_layers
    ]

    return {
        "total_layers": finding.corroboration_count,
        "threshold_for_high_confidence": 2,
        "is_high_confidence": finding.is_high_confidence,
        "archive_sources_failed": finding.archive_sources_failed,
        "layers": layers_with_explanations,
    }


def _explain_novelty(finding: TriagedFinding) -> dict[str, Any]:
    if not finding.novelty:
        return {"available": False, "reason": "Novelty filter not run for this finding"}

    n = finding.novelty
    return {
        "total_score": n.total,
        "components": {
            "infra_deviation": {
                "score": n.infra_deviation,
                "weight": 0.4,
                "explanation": "How different is this asset's ASN/CDN from the organisation's typical infrastructure",
            },
            "recency": {
                "score": n.recency,
                "is_default": n.recency_is_default,
                "weight": 0.3,
                "explanation": (
                    "Default fallback score (first_seen date unavailable from archives)"
                    if n.recency_is_default
                    else "How recently was this endpoint first observed (linear decay over 2 years)"
                ),
            },
            "structural_uniqueness": {
                "score": n.structural_uniqueness,
                "weight": 0.3,
                "explanation": f"Inverse of cluster size ({finding.cluster_size} URLs in this pattern cluster)",
            },
        },
    }


def _explain_priority(finding: TriagedFinding) -> dict[str, Any]:
    novelty_total = finding.novelty.total if finding.novelty else 0.5
    param_count = float(len(finding.parameters))
    structural_complexity = min(param_count, 3.0) if param_count > 0 else 0.5

    return {
        "formula": "corroboration_layers × novelty_score × min(parameter_count, 3.0)",
        "values": {
            "corroboration_layers": finding.corroboration_count,
            "novelty_score": novelty_total,
            "structural_complexity": structural_complexity,
            "parameter_count_raw": param_count,
            "cap_applied": param_count > 3.0,
        },
        "result": finding.investigation_priority,
    }
