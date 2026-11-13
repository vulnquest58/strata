"""The Strata finding contract (P0, frozen).

Rule: a candidate is not a finding. Every `UnifiedFinding` must trace to at
least one `Evidence` record, and `status` transitions are constrained by the
evidence a finding actually carries.
"""

from __future__ import annotations

import enum
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_KNOWN_TLD_RE = re.compile(r"^[a-z]{2,63}$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class FindingClass(enum.StrEnum):
    SUBDOMAIN = "subdomain"
    TAKEOVER = "takeover"
    LIVE_HOST = "live_host"
    ENDPOINT = "endpoint"
    SECRET = "secret"
    PARAM = "param"


class FindingStatus(enum.StrEnum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    STALE = "stale"
    DEAD = "dead"


class EvidenceStrength(enum.StrEnum):
    WEAK = "weak"
    CORROBORATED = "corroborated"
    STRONG = "strong"


class ConfidenceMethod(enum.StrEnum):
    BAYESIAN = "bayesian"
    NOISY_OR = "noisy_or"
    ML = "ml"
    IMPORTED = "imported"


def utc_now() -> datetime:
    return datetime.now(UTC)


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    engine: str = Field(min_length=1)
    technique: str = Field(min_length=1)
    observation: str = Field(default="")
    strength: EvidenceStrength = EvidenceStrength.WEAK
    ts: datetime = Field(default_factory=utc_now)
    meta: dict[str, Any] = Field(default_factory=dict)


class Confidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    value: float = Field(ge=0.0, le=100.0)
    method: ConfidenceMethod = ConfidenceMethod.IMPORTED
    components: dict[str, float] = Field(default_factory=dict)

    @field_validator("components")
    @classmethod
    def _components_in_range(cls, v: dict[str, float]) -> dict[str, float]:
        for source, score in v.items():
            if not 0.0 <= score <= 100.0:
                raise ValueError(f"component '{source}' score {score} outside 0..100")
        return v


class UnifiedFinding(BaseModel):
    model_config = ConfigDict(frozen=False)

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str = Field(min_length=1)
    kind: FindingClass
    status: FindingStatus = FindingStatus.CANDIDATE
    asset_value: str = Field(min_length=1)
    parent: str | None = None
    confidence: Confidence
    evidence: list[Evidence] = Field(default_factory=list)
    scope_ok: bool = True
    discovered_at: datetime = Field(default_factory=utc_now)
    legacy: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("asset_value")
    @classmethod
    def _asset_value_nonblank(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("asset_value must not be blank")
        return v

    @field_validator("parent", mode="before")
    @classmethod
    def _parent_normalized(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip().lower()
            return v or None
        return v

    @model_validator(mode="after")
    def _status_requires_evidence(self) -> UnifiedFinding:
        if self.status is FindingStatus.VERIFIED and not self.evidence:
            raise ValueError("status=verified requires at least one evidence record")
        if self.status is FindingStatus.DEAD and not self.evidence:
            raise ValueError("status=dead requires at least one evidence record")
        return self

    @model_validator(mode="after")
    def _subdomain_shape(self) -> UnifiedFinding:
        if self.kind is FindingClass.SUBDOMAIN:
            labels = self.asset_value.split(".")
            if len(labels) < 2:
                raise ValueError(
                    f"subdomain '{self.asset_value}' needs at least two labels"
                )
            for label in labels[:-1] + [labels[-1]]:
                if not _LABEL_RE.match(label):
                    raise ValueError(f"invalid domain label '{label}'")
            tld = labels[-1]
            if not _KNOWN_TLD_RE.match(tld):
                raise ValueError(f"suspicious TLD '{tld}'")
        return self

    def dedup_key(self) -> tuple[str, str, str]:
        return (self.run_id, self.kind.value, self.asset_value)

    def strongest_evidence(self) -> EvidenceStrength | None:
        if not self.evidence:
            return None
        order = [
            EvidenceStrength.WEAK,
            EvidenceStrength.CORROBORATED,
            EvidenceStrength.STRONG,
        ]
        return max((e.strength for e in self.evidence), key=order.index)


def is_probable_domain(value: str) -> bool:
    labels = value.strip().lower().split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL_RE.match(label) for label in labels) and _KNOWN_TLD_RE.match(
        labels[-1]
    ) is not None


__all__ = [
    "Confidence",
    "ConfidenceMethod",
    "Evidence",
    "EvidenceStrength",
    "FindingClass",
    "FindingStatus",
    "UnifiedFinding",
    "is_probable_domain",
    "utc_now",
]
