"""HTTP fingerprinting engine (P2+).

Detects technology stack, WAF presence, and security header posture
from a single HTTP response — zero API keys, zero third-party deps.

Outputs a UnifiedFinding of kind LIVE_HOST with metadata:
  tech_stack  : list[str]   — detected technologies
  waf         : str | None  — detected WAF product
  sec_headers : dict        — present/missing security headers
  server      : str | None  — Server header value
  cdn         : str | None  — CDN product if detected
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from strata.core.content.fetch import FetchResponse, HttpTransport, UrllibTransport
from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

# ------------------------------------------------------------------ #
# Signature databases (no external files, embedded inline)            #
# ------------------------------------------------------------------ #

_WAF_SIGNATURES: list[tuple[str, str]] = [
    # (header_or_body_pattern, waf_name)
    (r"(?i)x-sucuri-id", "Sucuri"),
    (r"(?i)server:\s*sucuri", "Sucuri"),
    (r"(?i)x-firewall-protection", "Incapsula"),
    (r"(?i)x-cdn:\s*incapsula", "Incapsula"),
    (r"(?i)__utmz.*incap_ses", "Incapsula"),
    (r"(?i)cf-ray", "Cloudflare"),
    (r"(?i)server:\s*cloudflare", "Cloudflare"),
    (r"(?i)x-akamai-transformed", "Akamai"),
    (r"(?i)akamai-ghost", "Akamai"),
    (r"(?i)x-cdn:\s*akamai", "Akamai"),
    (r"(?i)x-azure-ref", "Azure Front Door"),
    (r"(?i)x-ms-ref", "Azure Front Door"),
    (r"(?i)server:\s*awselb", "AWS ELB"),
    (r"(?i)x-amz-cf-id", "AWS CloudFront"),
    (r"(?i)x-amz-rid", "AWS CloudFront"),
    (r"(?i)x-barracuda-url", "Barracuda"),
    (r"(?i)barra_counter_session", "Barracuda"),
    (r"(?i)x-distil-cs", "Distil Networks"),
    (r"(?i)x-px-\w", "PerimeterX"),
    (r"(?i)__pxvid", "PerimeterX"),
    (r"(?i)x-forwarded-by:\s*imperva", "Imperva"),
    (r"(?i)visid_incap", "Imperva"),
    (r"(?i)server:\s*imperva", "Imperva"),
    (r"(?i)x-reblaze-protection", "Reblaze"),
    (r"(?i)x-waf-event-info", "F5 BIG-IP"),
    (r"(?i)bigipserver", "F5 BIG-IP"),
    (r"(?i)ts[0-9a-f]{8,}", "F5 BIG-IP"),
    (r"(?i)x-fw-\w", "Fortinet FortiWeb"),
    (r"(?i)fortigate", "Fortinet FortiGate"),
    (r"(?i)server:\s*mod_security", "ModSecurity"),
    (r"(?i)mod_security", "ModSecurity"),
    (r"(?i)server:\s*naxsi", "NAXSI"),
]

_TECH_SIGNATURES: list[tuple[str, str]] = [
    # (header_or_body_pattern, tech_name)
    (r"(?i)x-powered-by:\s*php", "PHP"),
    (r"(?i)x-powered-by:\s*asp\.net", "ASP.NET"),
    (r"(?i)x-powered-by:\s*express", "Express.js"),
    (r"(?i)x-powered-by:\s*next\.js", "Next.js"),
    (r"(?i)x-powered-by:\s*laravel", "Laravel"),
    (r"(?i)server:\s*nginx", "Nginx"),
    (r"(?i)server:\s*apache", "Apache"),
    (r"(?i)server:\s*iis", "IIS"),
    (r"(?i)server:\s*gunicorn", "Gunicorn/Python"),
    (r"(?i)server:\s*uvicorn", "Uvicorn/Python"),
    (r"(?i)server:\s*caddy", "Caddy"),
    (r"(?i)server:\s*openresty", "OpenResty"),
    (r"(?i)server:\s*litespeed", "LiteSpeed"),
    (r"(?i)x-generator:\s*drupal", "Drupal"),
    (r"(?i)x-drupal-\w", "Drupal"),
    (r"(?i)<meta[^>]+generator[^>]+wordpress", "WordPress"),
    (r"(?i)wp-content/", "WordPress"),
    (r"(?i)wp-json/", "WordPress"),
    (r"(?i)x-wp-\w", "WordPress"),
    (r"(?i)/sites/default/files/", "Drupal"),
    (r"(?i)__cf_bm|cf_clearance", "Cloudflare"),
    (r"(?i)laravel_session", "Laravel"),
    (r"(?i)django_session|csrfmiddlewaretoken", "Django"),
    (r"(?i)rack\.session|rails", "Ruby on Rails"),
    (r"(?i)phpsessid", "PHP"),
    (r"(?i)jsessionid", "Java/Tomcat"),
    (r"(?i)asp\.net_sessionid", "ASP.NET"),
    (r"(?i)struts", "Apache Struts"),
    (r"(?i)x-shopify-\w", "Shopify"),
    (r"(?i)x-wix-\w|wixsite\.com", "Wix"),
    (r"(?i)ghost/\d", "Ghost CMS"),
    (r"(?i)x-nextjs-\w|/__next/", "Next.js"),
    (r"(?i)x-nuxt|/__nuxt/", "Nuxt.js"),
    (r"(?i)x-svelte|/svelte/", "SvelteKit"),
    (r"(?i)graphql", "GraphQL"),
    (r"(?i)x-hasura-\w", "Hasura"),
]

_CDN_SIGNATURES: list[tuple[str, str]] = [
    (r"(?i)cf-ray|server:\s*cloudflare", "Cloudflare"),
    (r"(?i)x-amz-cf-id", "AWS CloudFront"),
    (r"(?i)x-azure-ref", "Azure CDN"),
    (r"(?i)x-akamai-transformed|akamaized\.net", "Akamai"),
    (r"(?i)x-fastly-request-id|fastly", "Fastly"),
    (r"(?i)x-cache:\s*hit.*varnish|via:\s*varnish", "Varnish"),
    (r"(?i)x-bunnycdn|bunnycdn", "BunnyCDN"),
    (r"(?i)x-cdn:\s*imperva", "Imperva CDN"),
]

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "x-xss-protection",
]


@dataclass
class FingerprintResult:
    url: str
    status: int
    server: str | None
    tech_stack: list[str]
    waf: str | None
    cdn: str | None
    sec_headers: dict[str, str | None]  # header → value or None if missing
    raw_headers: dict[str, str]
    finding: UnifiedFinding | None = None


def _all_text(response: FetchResponse) -> str:
    """Combine all headers and body into one searchable string."""
    header_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    body_text = response.body.decode("utf-8", errors="replace")[:50_000]
    return header_text + "\n" + body_text


def fingerprint_response(response: FetchResponse, *, run_id: str = "http_fp") -> FingerprintResult:
    """Fingerprint a single HTTP response without any additional requests."""
    combined = _all_text(response)
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    # Server header
    server = headers_lower.get("server")

    # WAF detection
    waf: str | None = None
    for pattern, name in _WAF_SIGNATURES:
        if re.search(pattern, combined):
            waf = name
            break

    # CDN detection
    cdn: str | None = None
    for pattern, name in _CDN_SIGNATURES:
        if re.search(pattern, combined):
            cdn = name
            break

    # Technology stack
    tech_stack: list[str] = []
    seen: set[str] = set()
    for pattern, name in _TECH_SIGNATURES:
        if name not in seen and re.search(pattern, combined):
            tech_stack.append(name)
            seen.add(name)

    # Security headers audit
    sec_headers: dict[str, str | None] = {}
    for hdr in _SECURITY_HEADERS:
        sec_headers[hdr] = headers_lower.get(hdr)

    missing_critical = [
        h for h in ("strict-transport-security", "content-security-policy", "x-frame-options")
        if sec_headers.get(h) is None
    ]

    # Build evidence
    observations: list[str] = []
    if tech_stack:
        observations.append(f"tech: {', '.join(tech_stack)}")
    if waf:
        observations.append(f"WAF: {waf}")
    if cdn:
        observations.append(f"CDN: {cdn}")
    if missing_critical:
        observations.append(f"missing security headers: {', '.join(missing_critical)}")

    observation = "; ".join(observations) if observations else f"HTTP {response.status}"

    finding = UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.LIVE_HOST,
        status=FindingStatus.VERIFIED,
        asset_value=response.url,
        confidence=Confidence(
            value=85.0,
            method=ConfidenceMethod.HTTP_PROBE,
            components={"http_fp": 85.0},
        ),
        evidence=[
            Evidence(
                engine="http_fp",
                technique="response_analysis",
                observation=observation,
                strength=EvidenceStrength.STRONG,
                meta={
                    "status": response.status,
                    "server": server,
                    "tech_stack": tech_stack,
                    "waf": waf,
                    "cdn": cdn,
                    "sec_headers": {
                        k: ("present" if v is not None else "missing")
                        for k, v in sec_headers.items()
                    },
                },
            )
        ],
        scope_ok=True,
        discovered_at=datetime.now(UTC),
        metadata={
            "tech_stack": tech_stack,
            "waf": waf,
            "cdn": cdn,
            "server": server,
            "sec_headers": sec_headers,
            "missing_critical_headers": missing_critical,
        },
    )

    return FingerprintResult(
        url=response.url,
        status=response.status,
        server=server,
        tech_stack=tech_stack,
        waf=waf,
        cdn=cdn,
        sec_headers=sec_headers,
        raw_headers=dict(response.headers),
        finding=finding,
    )


async def fingerprint_url(
    url: str,
    *,
    transport: HttpTransport | None = None,
    timeout: float = 10.0,
    run_id: str = "http_fp",
) -> FingerprintResult | None:
    """Fetch a URL and return its fingerprint, or None on network error."""
    t = transport or UrllibTransport()
    try:
        response = await t.get(url, timeout=timeout, max_bytes=200_000)
        return fingerprint_response(response, run_id=run_id)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).debug("fingerprint_url error %s: %s", url, exc)
        return None


__all__ = [
    "FingerprintResult",
    "fingerprint_response",
    "fingerprint_url",
]

