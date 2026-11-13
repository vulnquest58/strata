"""Passive DNS source aggregator.

Built-in free sources (no key required):
  - crt.sh       — Certificate Transparency logs
  - HackerTarget — free DNS lookup API
  - RapidDNS     — free subdomain search
  - AlienVault OTX — free tier (no key for basic lookups)

Optional API-key sources (activated via config or env):
  - VirusTotal   — STRATA_VIRUSTOTAL_KEY
  - SecurityTrails — STRATA_SECURITYTRAILS_KEY

Usage:
    findings = await query_passive_dns("example.com", config=get_config())
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime

from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

log = logging.getLogger(__name__)

_SUBDOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


@dataclass
class PassiveDnsResult:
    source: str
    domain: str
    subdomains: list[str] = field(default_factory=list)
    error: str | None = None


def _fetch_json(url: str, timeout: float = 15.0, headers: dict | None = None) -> object:
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (compatible; strata-passive/0.2; +https://github.com/vulnquest58/strata)",
    )
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(4_000_000))


def _fetch_text(url: str, timeout: float = 15.0, headers: dict | None = None) -> str:
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (compatible; strata-passive/0.2; +https://github.com/vulnquest58/strata)",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(2_000_000).decode("utf-8", errors="replace")


def _clean(name: str, root: str) -> str | None:
    """Normalise and validate a candidate subdomain name."""
    name = name.strip().lower().lstrip("*").lstrip(".")
    if not name:
        return None
    if not name.endswith(f".{root}") and name != root:
        return None
    if not _SUBDOMAIN_RE.match(name):
        return None
    return name


# ------------------------------------------------------------------ #
# Source implementations                                               #
# ------------------------------------------------------------------ #

def _query_crtsh(domain: str) -> PassiveDnsResult:
    result = PassiveDnsResult(source="crtsh", domain=domain)
    try:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        data = _fetch_json(url)
        seen: set[str] = set()
        for entry in data or []:
            for name in str(entry.get("name_value", "")).split("\n"):
                cleaned = _clean(name, domain)
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    result.subdomains.append(cleaned)
    except Exception as exc:
        result.error = str(exc)
        log.debug("crt.sh error for %s: %s", domain, exc)
    return result


def _query_hackertarget(domain: str) -> PassiveDnsResult:
    result = PassiveDnsResult(source="hackertarget", domain=domain)
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        text = _fetch_text(url, timeout=20.0)
        if "API count exceeded" in text or "error" in text.lower()[:40]:
            result.error = text.strip()
            return result
        seen: set[str] = set()
        for line in text.splitlines():
            parts = line.split(",", 1)
            if parts:
                cleaned = _clean(parts[0], domain)
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    result.subdomains.append(cleaned)
    except Exception as exc:
        result.error = str(exc)
        log.debug("hackertarget error for %s: %s", domain, exc)
    return result


def _query_rapiddns(domain: str) -> PassiveDnsResult:
    result = PassiveDnsResult(source="rapiddns", domain=domain)
    try:
        url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1&down=1"
        text = _fetch_text(url, timeout=20.0)
        # HTML table: <td>sub.domain.com</td>
        matches = re.findall(r"<td>([^<]+\." + re.escape(domain) + r")</td>", text)
        seen: set[str] = set()
        for name in matches:
            cleaned = _clean(name, domain)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.subdomains.append(cleaned)
    except Exception as exc:
        result.error = str(exc)
        log.debug("rapiddns error for %s: %s", domain, exc)
    return result


def _query_alienvault(domain: str) -> PassiveDnsResult:
    result = PassiveDnsResult(source="alienvault", domain=domain)
    try:
        url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain/"
            f"{urllib.parse.quote(domain)}/passive_dns"
        )
        data = _fetch_json(url)
        seen: set[str] = set()
        for entry in (data or {}).get("passive_dns", []):
            hostname = entry.get("hostname", "")
            cleaned = _clean(hostname, domain)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.subdomains.append(cleaned)
    except Exception as exc:
        result.error = str(exc)
        log.debug("alienvault error for %s: %s", domain, exc)
    return result


def _query_virustotal(domain: str, api_key: str) -> PassiveDnsResult:
    result = PassiveDnsResult(source="virustotal", domain=domain)
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}/subdomains?limit=40"
        data = _fetch_json(url, headers={"x-apikey": api_key})
        seen: set[str] = set()
        for entry in (data or {}).get("data", []):
            name = entry.get("id", "")
            cleaned = _clean(name, domain)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.subdomains.append(cleaned)
        # paginate once more if there's a cursor
        cursor = (data or {}).get("meta", {}).get("cursor")
        if cursor:
            url2 = url + f"&cursor={urllib.parse.quote(cursor)}"
            data2 = _fetch_json(url2, headers={"x-apikey": api_key})
            for entry in (data2 or {}).get("data", []):
                name = entry.get("id", "")
                cleaned = _clean(name, domain)
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    result.subdomains.append(cleaned)
    except Exception as exc:
        result.error = str(exc)
        log.debug("virustotal error for %s: %s", domain, exc)
    return result


def _query_securitytrails(domain: str, api_key: str) -> PassiveDnsResult:
    result = PassiveDnsResult(source="securitytrails", domain=domain)
    try:
        url = f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(domain)}/subdomains?children_only=false"
        data = _fetch_json(url, headers={"APIKEY": api_key})
        seen: set[str] = set()
        for sub in (data or {}).get("subdomains", []):
            name = f"{sub}.{domain}"
            cleaned = _clean(name, domain)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.subdomains.append(cleaned)
    except Exception as exc:
        result.error = str(exc)
        log.debug("securitytrails error for %s: %s", domain, exc)
    return result


# ------------------------------------------------------------------ #
# Main entry point                                                     #
# ------------------------------------------------------------------ #

async def query_passive_dns(
    domain: str,
    *,
    config=None,
) -> list[PassiveDnsResult]:
    """Query all enabled passive DNS sources concurrently."""
    from strata.core.config import get_config

    cfg = config or get_config()
    pdn = cfg.passive_dns

    tasks: list[tuple[str, object]] = []

    if pdn.crtsh:
        tasks.append(("crtsh", lambda: _query_crtsh(domain)))
    if pdn.hackertarget:
        tasks.append(("hackertarget", lambda: _query_hackertarget(domain)))
    if pdn.rapiddns:
        tasks.append(("rapiddns", lambda: _query_rapiddns(domain)))
    if pdn.alienvault:
        tasks.append(("alienvault", lambda: _query_alienvault(domain)))
    if pdn.virustotal and cfg.keys.virustotal:
        key = cfg.keys.virustotal
        tasks.append(("virustotal", lambda k=key: _query_virustotal(domain, k)))
    if pdn.securitytrails and cfg.keys.securitytrails:
        key = cfg.keys.securitytrails
        tasks.append(("securitytrails", lambda k=key: _query_securitytrails(domain, k)))

    results = await asyncio.gather(
        *[asyncio.to_thread(fn) for _, fn in tasks],
        return_exceptions=True,
    )

    output: list[PassiveDnsResult] = []
    for (_name, _fn), res in zip(tasks, results, strict=False):
        if isinstance(res, Exception):
            output.append(PassiveDnsResult(source=_name, domain=domain, error=str(res)))
        else:
            output.append(res)
    return output


def passive_dns_to_findings(
    results: list[PassiveDnsResult],
    *,
    run_id: str = "passive_dns",
    policy=None,
) -> list[UnifiedFinding]:
    """Convert PassiveDnsResult list to UnifiedFinding list."""
    # Aggregate: subdomain → set of sources
    source_map: dict[str, set[str]] = {}
    for result in results:
        for sub in result.subdomains:
            if policy and not policy.allows_domain(sub):
                continue
            source_map.setdefault(sub, set()).add(result.source)

    findings: list[UnifiedFinding] = []
    now = datetime.now(UTC)

    for subdomain, sources in source_map.items():
        n = len(sources)
        # noisy-OR: each source contributes 55% base confidence
        base = 55.0
        combined = round(100.0 * (1.0 - (1.0 - base / 100.0) ** n), 1)
        strength = (
            EvidenceStrength.STRONG if n >= 3
            else EvidenceStrength.CORROBORATED if n >= 2
            else EvidenceStrength.WEAK
        )
        evidence = [
            Evidence(
                engine="passive_dns",
                technique=f"ct_aggregation:{','.join(sorted(sources))}",
                observation=f"found in {n} source(s): {', '.join(sorted(sources))}",
                strength=strength,
                meta={"sources": sorted(sources), "source_count": n},
            )
        ]
        findings.append(
            UnifiedFinding(
                run_id=run_id,
                kind=FindingClass.SUBDOMAIN,
                status=FindingStatus.CANDIDATE,
                asset_value=subdomain,
                confidence=Confidence(
                    value=combined,
                    method=ConfidenceMethod.NOISY_OR if n > 1 else ConfidenceMethod.IMPORTED,
                    components={s: base for s in sources},
                ),
                evidence=evidence,
                scope_ok=True,
                discovered_at=now,
            )
        )
    return sorted(findings, key=lambda f: (-f.confidence.value, f.asset_value))


__all__ = [
    "PassiveDnsResult",
    "passive_dns_to_findings",
    "query_passive_dns",
]

