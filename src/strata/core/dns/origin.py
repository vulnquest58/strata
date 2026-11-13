"""Origin classification: what is actually serving a resolved host?

Ported from origintrace (CIDR dataset, hosting ASN dataset) and dnsphantom
filter_origin.py (CNAME/rDNS provider patterns). Classification is fully
offline: datasets ship in core/dns/data/. ASN lookup requires an external
API and is therefore a separate opt-in enricher, not part of this module.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


class OriginType(StrEnum):
    CDN = "cdn"
    CLOUD = "cloud"
    PAAS = "paas"
    HOSTING = "hosting"
    DIRECT = "direct"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OriginClassification:
    origin_type: OriginType
    provider: str
    confidence: float
    via: str  # "cname_suffix" | "ip_cidr" | "default"
    matched: str = ""


# CNAME/rDNS suffix patterns: (suffix, provider, origin_type, confidence).
# Ported from dnsphantom filter_origin.py CDN_RDNS_PATTERNS + takeover.py
# VULN_PATTERNS + filter_origin HOSTING_RDNS_PATTERNS (the rDNS entries that
# also appear as CNAME targets).
CNAME_SUFFIX_PATTERNS: tuple[tuple[str, str, OriginType, float], ...] = (
    ("cloudfront.net", "aws_cloudfront", OriginType.CDN, 0.90),
    ("cloudflare.net", "cloudflare", OriginType.CDN, 0.85),
    ("akamai.net", "akamai", OriginType.CDN, 0.95),
    ("akamaiedge.net", "akamai", OriginType.CDN, 0.95),
    ("edgesuite.net", "akamai", OriginType.CDN, 0.95),
    ("edgekey.net", "akamai", OriginType.CDN, 0.95),
    ("fastly.net", "fastly", OriginType.CDN, 0.95),
    ("incapsula.com", "imperva_incapsula", OriginType.CDN, 0.95),
    ("llnwd.net", "limelight", OriginType.CDN, 0.90),
    ("edgecastcdn.net", "edgecast", OriginType.CDN, 0.90),
    ("gcdn.net", "gcore", OriginType.CDN, 0.85),
    ("cdn77.net", "cdn77", OriginType.CDN, 0.85),
    ("b-cdn.net", "bunny", OriginType.CDN, 0.85),
    ("amazonaws.com", "aws", OriginType.CLOUD, 0.75),
    ("azurewebsites.net", "azure", OriginType.PAAS, 0.90),
    ("cloudapp.azure.com", "azure", OriginType.CLOUD, 0.85),
    ("blob.core.windows.net", "azure", OriginType.CLOUD, 0.85),
    ("googleusercontent.com", "google_cloud", OriginType.CLOUD, 0.80),
    ("googleapis.com", "google_cloud", OriginType.CLOUD, 0.80),
    ("appspot.com", "google_app_engine", OriginType.PAAS, 0.90),
    ("herokuapp.com", "heroku", OriginType.PAAS, 0.90),
    ("github.io", "github_pages", OriginType.PAAS, 0.90),
    ("netlify.app", "netlify", OriginType.PAAS, 0.90),
    ("vercel.app", "vercel", OriginType.PAAS, 0.90),
    ("pages.dev", "cloudflare_pages", OriginType.PAAS, 0.90),
    ("surge.sh", "surge", OriginType.PAAS, 0.90),
    ("readthedocs.io", "readthedocs", OriginType.PAAS, 0.85),
    ("wordpress.com", "wordpress", OriginType.PAAS, 0.85),
    ("myshopify.com", "shopify", OriginType.PAAS, 0.85),
    ("zendesk.com", "zendesk", OriginType.PAAS, 0.85),
    ("freshdesk.com", "freshdesk", OriginType.PAAS, 0.85),
    ("helpscout.net", "helpscout", OriginType.PAAS, 0.85),
    ("ghost.io", "ghost", OriginType.PAAS, 0.85),
    ("pantheonsite.io", "pantheon", OriginType.PAAS, 0.85),
    ("bitbucket.io", "bitbucket_pages", OriginType.PAAS, 0.85),
)


@lru_cache(maxsize=1)
def _cdn_networks() -> tuple[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network], ...]:
    """Load origintrace's CDN CIDR dataset (providers -> ip_network list)."""
    raw = json.loads((DATA_DIR / "cdn_ip_ranges.json").read_text(encoding="utf-8"))
    nets: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for provider, ranges in raw.items():
        slug = provider.lower().replace(" ", "_")
        for cidr in ranges:
            nets.append((slug, ipaddress.ip_network(cidr, strict=False)))
    return tuple(nets)


@lru_cache(maxsize=1)
def _hosting_asns() -> dict[int, tuple[str, str]]:
    """Load origintrace's hosting ASN dataset: asn -> (provider, type)."""
    raw = json.loads((DATA_DIR / "hosting_asns.json").read_text(encoding="utf-8"))
    out: dict[int, tuple[str, str]] = {}
    for provider, info in raw.items():
        for asn in info.get("asns", []):
            normalized = int(str(asn).upper().lstrip("AS"))
            out[normalized] = (provider, info.get("type", "hosting"))
    return out


def classify_by_asn(asn: int) -> OriginClassification | None:
    entry = _hosting_asns().get(asn)
    if entry is None:
        return None
    provider, asn_type = entry
    origin_type = OriginType.CLOUD if asn_type == "cloud" else OriginType.HOSTING
    return OriginClassification(origin_type, provider, 0.80, "ip_asn")


def classify_origin(
    cname: str | None,
    ips: tuple[str, ...] = (),
    asn: int | None = None,
) -> OriginClassification:
    """Classify the origin behind a host.

    Priority (mirrors origintrace's edge-first rule and dnsphantom's
    hosting-priority override):
    1. CNAME suffix match (an explicit delegation beats IP inference)
    2. IP in a known CDN CIDR range
    3. ASN in the hosting/cloud dataset (when the caller has an ASN)
    4. default -> DIRECT/UNKNOWN
    """
    if cname:
        lowered = cname.lower().rstrip(".")
        for suffix, provider, origin_type, confidence in CNAME_SUFFIX_PATTERNS:
            if lowered.endswith(suffix):
                return OriginClassification(
                    origin_type, provider, confidence, "cname_suffix", suffix
                )

    for ip_text in ips:
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        for provider, network in _cdn_networks():
            if ip in network:
                return OriginClassification(OriginType.CDN, provider, 0.90, "ip_cidr", str(network))

    if asn is not None:
        by_asn = classify_by_asn(asn)
        if by_asn is not None:
            return by_asn

    if not ips:
        return OriginClassification(OriginType.UNKNOWN, "", 0.0, "default")
    return OriginClassification(OriginType.DIRECT, "", 0.30, "default")
