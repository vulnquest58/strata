"""Attack-value ranking: what would an attacker click first?

Evidence tension measures how *stable* a claim is; attack value measures how
*valuable* it is to an attacker. A perfectly verified `images.kali.org` is
stable and boring; a shaky `vpn-internal.example.com` is shaky and urgent.
Hunters triage by attack value, so the surface needs both numbers.

The score is additive evidence of attacker interest with explicit reasons —
no hidden ML, every point traceable:

- asset-name keywords (login, admin, api, graphql, actuator, jenkins, ...)
- kind (secrets and vulnerable versions outrank static pages)
- metadata signals (missing security headers, disclosed versions, WAF,
  parameter richness, verified reachability)
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from strata.core.schema.models import FindingClass, FindingStatus, UnifiedFinding

# asset-name keyword tiers: (pattern, points, reason)
_KEYWORD_TIERS: tuple[tuple[re.Pattern[str], int, str], ...] = (
    (
        re.compile(r"admin|manage|manager|panel|cpanel|wp-admin|console|dashboard", re.I),
        25,
        "admin/management surface",
    ),
    (
        re.compile(r"login|signin|sso|auth|oauth|saml|session|token", re.I),
        20,
        "authentication surface",
    ),
    (re.compile(r"api|rest|v1|v2|graphql|apiv", re.I), 15, "API surface"),
    (
        re.compile(r"swagger|openapi|api-docs|docs|graphql-playground|graphiql", re.I),
        15,
        "API documentation/schema",
    ),
    (
        re.compile(r"actuator|metrics|env|debug|trace|heapdump|phpinfo", re.I),
        20,
        "debug/diagnostics endpoint",
    ),
    (
        re.compile(
            r"jenkins|gitlab|gitea|jira|confluence|sonarqube|nexus|artifactory", re.I
        ),
        25,
        "devops/collab platform",
    ),
    (
        re.compile(r"git|\.svn|\.hg|backup|dump|bak|old|archive-copy", re.I),
        15,
        "source/backup exposure",
    ),
    (
        re.compile(
            r"staging|stage|dev|test|uat|qa|sandbox|internal|intranet|vpn|rdp|remote",
            re.I,
        ),
        15,
        "non-production/internal surface",
    ),
    (
        re.compile(r"upload|uploadify|file|import|export|download", re.I),
        10,
        "file handling surface",
    ),
    (
        re.compile(r"mail|smtp|webmail|exchange|outlook|owa", re.I),
        10,
        "mail infrastructure",
    ),
)

_KIND_BASE: dict[FindingClass, int] = {
    FindingClass.SECRET: 45,
    FindingClass.VULN: 40,
    FindingClass.PARAM: 25,
    FindingClass.TAKEOVER: 30,
    FindingClass.LIVE_HOST: 15,
    FindingClass.ENDPOINT: 10,
    FindingClass.SUBDOMAIN: 5,
}


@dataclass(frozen=True)
class AttackAssessment:
    asset_value: str
    kind: str
    value: int
    reasons: list[str]


def _host_part(asset_value: str) -> str:
    if asset_value.startswith(("http://", "https://")):
        split = urlsplit(asset_value)
        return f"{split.netloc.lower()}{split.path.lower()}"
    return asset_value.lower()


def attack_value(finding: UnifiedFinding) -> AttackAssessment:
    score = _KIND_BASE.get(finding.kind, 10)
    reasons: list[str] = []

    name = f"{_host_part(finding.asset_value)} {finding.parent or ''}"
    for pattern, points, reason in _KEYWORD_TIERS:
        if pattern.search(name):
            score += points
            reasons.append(reason)

    if finding.kind is FindingClass.PARAM:
        reasons.append("injected parameter")

    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    tech_stack = metadata.get("tech_stack")
    if isinstance(tech_stack, list) and tech_stack:
        score += 8
        reasons.append("known technology stack")
    versions = metadata.get("versions")
    if isinstance(versions, dict) and versions:
        score += 12
        reasons.append("disclosed software versions")
    if metadata.get("cve"):
        score += 15
        reasons.append("known CVE match")
    missing = metadata.get("missing_critical_headers")
    if isinstance(missing, list) and missing:
        score += 8
        reasons.append("missing critical security headers")
    if metadata.get("waf"):
        score += 3
        reasons.append("WAF fronted (evasion required)")
    params = metadata.get("param_count")
    if isinstance(params, int) and params:
        score += min(3 * params, 12)
        reasons.append(f"{params} parameter(s)")

    if finding.status is FindingStatus.VERIFIED:
        score += 10
        reasons.append("verified reachable")
    elif finding.status is FindingStatus.DEAD:
        score = min(score, 5)
        reasons.append("dead claim (informational only)")

    if finding.kind is FindingClass.SECRET:
        score = max(score, 80)

    value = max(0, min(100, score))
    return AttackAssessment(
        asset_value=finding.asset_value,
        kind=finding.kind.value,
        value=value,
        reasons=reasons,
    )


def rank_by_attack_value(
    findings: Iterable[UnifiedFinding],
) -> list[tuple[UnifiedFinding, AttackAssessment]]:
    """Live claims ranked by attacker value, strongest first."""
    ranked = []
    for finding in findings:
        if finding.status is FindingStatus.DEAD:
            continue
        ranked.append((finding, attack_value(finding)))
    ranked.sort(key=lambda pair: (-pair[1].value, pair[1].asset_value))
    return ranked


__all__ = ["AttackAssessment", "attack_value", "rank_by_attack_value"]
