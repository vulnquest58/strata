"""
Pydantic models shared across the entire Triage Loom pipeline.

Design rule: no import of filter or storage logic here — models are pure data
structures. Triage Loom consumes Aperture's JSONL output and enriches each
finding through 5 independent filter stages before ranking.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Aperture Finding (input — mirrors Aperture's JSON output exactly)
# ---------------------------------------------------------------------------

class AssetType(str, Enum):
    subdomain = "subdomain"
    ip = "ip"
    cname = "cname"
    mx = "mx"


class ApertureFinding(BaseModel):
    """Mirrors the JSON structure produced by aperture discover."""
    id: str
    scan_id: str
    asset_id: str
    asset_type: AssetType = AssetType.subdomain
    parent_asset: str
    source_plugin: str
    raw_confidence: float = 0.0
    per_source_raw_confidence: dict[str, float] = Field(default_factory=dict)
    combined_confidence: float = 0.0
    adjusted_confidence: float = 0.0
    effective_confidence: float | None = None
    decay_factor: float = 1.0
    consensus_count: int = 1
    temporal_stability: float = 0.0
    resolved_ips: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    discovered_at: datetime


# ---------------------------------------------------------------------------
# Liveness (Filter 1 output)
# ---------------------------------------------------------------------------

class LivenessResult(BaseModel):
    asset_id: str
    responded: bool
    status_code: int | None = None
    response_time_ms: float | None = None
    tls_valid: bool = False
    redirect_chain: list[str] = Field(default_factory=list)
    # content_hash is used in Filter 4 to cluster assets with identical backends
    content_hash: str | None = None
    fingerprint: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Archive Cross-Reference (Filter 2 output)
# ---------------------------------------------------------------------------

class ArchiveSource(str, Enum):
    wayback = "wayback"
    commoncrawl = "commoncrawl"
    urlscan = "urlscan"


class ArchiveRecord(BaseModel):
    url: str
    sources: list[ArchiveSource] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def corroboration_count(self) -> int:
        return len(self.sources)


# ---------------------------------------------------------------------------
# Parameter Corroboration (Filter 3 output)
# ---------------------------------------------------------------------------

class ParameterTechnique(str, Enum):
    archive_static = "archive_static"   # extracted from archived query strings
    js_static      = "js_static"        # extracted from JS fetch/XHR/axios calls
    openapi        = "openapi"          # extracted from OpenAPI/Swagger spec


class ParameterRecord(BaseModel):
    name: str
    techniques: list[ParameterTechnique] = Field(default_factory=list)
    example_values: list[str] = Field(default_factory=list)

    @property
    def corroboration_count(self) -> int:
        return len(self.techniques)

    @property
    def is_corroborated(self) -> bool:
        return self.corroboration_count >= 2


# ---------------------------------------------------------------------------
# URL Cluster (Filter 4 output)
# ---------------------------------------------------------------------------

class EndpointCluster(BaseModel):
    """A group of structurally similar URLs reduced to a single representative."""
    pattern: str                    # normalised pattern e.g. "/api/v1/users/{id}"
    representative_url: str         # one concrete example
    member_count: int
    member_urls: list[str] = Field(default_factory=list)
    parameters: list[ParameterRecord] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    # Infrastructure context filled in during Filter 5
    asn: str | None = None
    cdn: str | None = None
    representative_ip: str | None = None


# ---------------------------------------------------------------------------
# Novelty Score (Filter 5 output)
# ---------------------------------------------------------------------------

class NoveltyScore(BaseModel):
    infra_deviation: float   # 0–1: how different is this asset's infra from the baseline?
    recency: float           # 0–1: how recently was this URL first seen?
    recency_is_default: bool = False  # True if recency is a placeholder (first_seen was null)
    structural_uniqueness: float  # 0–1: inverse of cluster size (small cluster = unique)
    total: float             # weighted sum


# ---------------------------------------------------------------------------
# Corroboration Layer enum (for explain command audit trail)
# ---------------------------------------------------------------------------

class CorroborationLayer(str, Enum):
    liveness             = "liveness"
    archive_wayback      = "archive_wayback"
    archive_commoncrawl  = "archive_commoncrawl"
    archive_urlscan      = "archive_urlscan"
    param_archive_static = "param_archive_static"
    param_js_static      = "param_js_static"
    param_openapi        = "param_openapi"


# ---------------------------------------------------------------------------
# Triaged Finding (final output)
# ---------------------------------------------------------------------------

class TriagedFinding(BaseModel):
    """
    The canonical output record from Triage Loom.
    Each field is traceable to a specific filter stage — nothing is "magic".
    """
    # Origin
    aperture_finding_id: str
    asset_id: str
    root_domain: str

    # Endpoint cluster (Filter 4)
    endpoint_pattern: str
    representative_url: str
    cluster_size: int

    # Corroboration evidence (audit trail for `explain` command)
    corroboration_layers: list[CorroborationLayer] = Field(default_factory=list)
    archive_sources_failed: list[str] = Field(default_factory=list)

    # Parameters (Filter 3)
    parameters: list[str] = Field(default_factory=list)

    # Infrastructure context
    infra_context: dict[str, Any] = Field(default_factory=dict)

    # Temporal info
    first_seen: datetime | None = None
    last_confirmed_live: datetime | None = None

    # Scores
    novelty: NoveltyScore | None = None
    investigation_priority: float = 0.0

    # Confidence tier
    is_high_confidence: bool = False  # True if corroboration_layers >= 2

    @field_validator("corroboration_layers", mode="before")
    @classmethod
    def deduplicate_layers(cls, v: list) -> list:
        seen: set = set()
        result = []
        for item in v:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    @property
    def corroboration_count(self) -> int:
        return len(self.corroboration_layers)
