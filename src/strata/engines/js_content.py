"""Content discovery engine (P2).

Absorbs the deterministic core of VulnHarvest's crawler (HTML script
discovery, robots/sitemap paths, JS endpoint regexes) and its secret scanner,
plus jsast's endpoint/secret artifact model. Every extracted artifact becomes
a UnifiedFinding with extraction evidence; optional HTTP probing upgrades
endpoints to verified or dead.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from strata.core.content.fetch import HttpTransport, decode_body
from strata.core.content.secrets import (
    detect_secrets,
    mask_secret,
    secret_asset_id,
    secret_confidence,
)
from strata.core.content.urls import (
    host_of,
    interest_score,
    is_valid_endpoint,
    normalise_url,
    param_names,
)
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL
)
HTML_LINK_RE = re.compile(r"(?:href|action)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'`<>\\]+", re.IGNORECASE)
RELATIVE_PATH_RE = re.compile(r"[\"'`](/(?!/)[^\"'`\s<>]{1,300})[\"'`]")
FETCH_CALL_RE = re.compile(
    r"(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*[\"'`]([^\"'`]{1,300})[\"'`]"
)
LOCATION_RE = re.compile(
    r"(?:window\.)?location(?:\.href)?\s*=\s*[\"'`]([^\"'`]{1,300})[\"'`]"
)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
ROBOTS_SITEMAP_RE = re.compile(r"(?im)^\s*sitemap:\s*(\S+)")
ROBOTS_PATH_RE = re.compile(r"(?im)^\s*(?:allow|disallow):\s*(\S+)\s*$")

MAX_SITEMAPS = 3
MAX_SITEMAP_LOCS = 500
PROBE_MAX_BYTES = 65_536


@dataclass
class ContentRunStats:
    pages_fetched: int = 0
    scripts_fetched: int = 0
    endpoints_extracted: int = 0
    endpoints_out_of_scope: int = 0
    endpoints_stored: int = 0
    secrets_found: int = 0
    probed: int = 0
    verified: int = 0
    dead: int = 0
    errors: int = 0


@dataclass
class ContentRunResult:
    seed_url: str
    findings: list[UnifiedFinding] = field(default_factory=list)
    stats: ContentRunStats = field(default_factory=ContentRunStats)


def _trim_url(value: str) -> str:
    return value.strip().rstrip(".,;:!?)]}\"'`")


class ContentDiscoveryEngine:
    def __init__(
        self,
        transport: HttpTransport,
        policy: ScopePolicy,
        *,
        max_scripts: int = 25,
        max_probe: int = 50,
        probe: bool = True,
        robots: bool = True,
        max_concurrency: int = 8,
        timeout: float = 10.0,
        max_bytes: int = 2_000_000,
        known: set[str] | None = None,
    ):
        self._transport = transport
        self._policy = policy
        self._max_scripts = max_scripts
        self._max_probe = max_probe
        self._probe_enabled = probe
        self._robots = robots
        self._max_concurrency = max_concurrency
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._known = known or set()
        self._target = ""
        self._run_id = ""

    async def run(self, seed_url: str) -> ContentRunResult:
        seed = normalise_url(seed_url)
        target = host_of(seed)
        if not target:
            raise ValueError(f"seed URL has no host: {seed_url!r}")
        if not self._policy.allows_host(target):
            raise PermissionError(f"host {target} is out of scope")
        self._target = target
        self._run_id = f"content:{target}"

        result = ContentRunResult(seed_url=seed)
        endpoints: dict[str, UnifiedFinding] = {}
        secrets: dict[str, UnifiedFinding] = {}
        script_texts: list[tuple[str, str]] = []

        page = await self._fetch(seed, result)
        script_urls: list[str] = []
        if page is not None and page.status < 400:
            html = decode_body(page)
            self._collect_html(html, page.url, endpoints, result)
            for inline in INLINE_SCRIPT_RE.findall(html):
                script_texts.append((page.url, inline))
            script_urls = self._script_urls(html, page.url, result)

        if self._robots:
            await self._discover_robots(seed, endpoints, result)

        for url, text in await self._fetch_scripts(script_urls, result):
            script_texts.append((url, text))

        for source_url, text in script_texts:
            self._collect_js(text, source_url, endpoints, secrets, result)

        if self._probe_enabled and endpoints:
            await self._probe(endpoints, result)

        result.stats.endpoints_stored = len(endpoints)
        result.stats.secrets_found = len(secrets)
        result.findings = sorted(
            [*endpoints.values(), *secrets.values()],
            key=lambda finding: (
                -finding.confidence.value,
                finding.kind.value,
                finding.asset_value,
            ),
        )
        return result

    def _in_scope(self, url: str) -> bool:
        host = host_of(url)
        return host == self._target or host.endswith("." + self._target)

    async def _fetch(self, url: str, result: ContentRunResult, *, script: bool = False):
        try:
            response = await self._transport.get(
                url, timeout=self._timeout, max_bytes=self._max_bytes
            )
        except Exception:
            result.stats.errors += 1
            return None
        if response.status < 400:
            if script:
                result.stats.scripts_fetched += 1
            else:
                result.stats.pages_fetched += 1
        return response

    def _script_urls(
        self, html: str, base_url: str, result: ContentRunResult
    ) -> list[str]:
        urls: set[str] = set()
        for src in SCRIPT_SRC_RE.findall(html):
            url = urljoin(base_url, src.strip())
            if urlparse(url).scheme not in ("http", "https"):
                continue
            if not self._in_scope(url):
                result.stats.endpoints_out_of_scope += 1
                continue
            try:
                urls.add(normalise_url(url))
            except ValueError:
                continue
        return sorted(urls)

    async def _fetch_scripts(
        self, urls: list[str], result: ContentRunResult
    ) -> list[tuple[str, str]]:
        selected = urls[: self._max_scripts]

        async def fetch(url: str):
            response = await self._fetch(url, result, script=True)
            if response is None or response.status >= 400:
                return None
            if not self._in_scope(response.url):
                return None
            return (response.url, decode_body(response))

        outcomes = await asyncio.gather(*(fetch(url) for url in selected))
        return [outcome for outcome in outcomes if outcome is not None]

    def _collect_html(
        self,
        html: str,
        base_url: str,
        endpoints: dict[str, UnifiedFinding],
        result: ContentRunResult,
    ) -> None:
        candidates: set[str] = set(HTML_LINK_RE.findall(html))
        candidates.update(match.group(1) for match in RELATIVE_PATH_RE.finditer(html))
        for raw in sorted(candidates):
            url = urljoin(base_url, raw.strip())
            self._add_endpoint(url, base_url, "html_link", 50.0, endpoints, result)

    def _collect_js(
        self,
        text: str,
        source_url: str,
        endpoints: dict[str, UnifiedFinding],
        secrets: dict[str, UnifiedFinding],
        result: ContentRunResult,
    ) -> None:
        candidates: set[str] = set()
        candidates.update(
            _trim_url(match.group(0)) for match in ABSOLUTE_URL_RE.finditer(text)
        )
        for pattern in (RELATIVE_PATH_RE, FETCH_CALL_RE, LOCATION_RE):
            candidates.update(
                _trim_url(match.group(1)) for match in pattern.finditer(text)
            )
        for raw in sorted(candidates):
            url = urljoin(source_url, raw)
            self._add_endpoint(url, source_url, "js_extract", 60.0, endpoints, result)
        for hit in detect_secrets(text):
            self._add_secret(hit, source_url, secrets, result)

    def _add_endpoint(
        self,
        url: str,
        source_url: str,
        technique: str,
        base_confidence: float,
        endpoints: dict[str, UnifiedFinding],
        result: ContentRunResult,
    ) -> None:
        if not url or url.startswith(("data:", "javascript:", "mailto:")):
            return
        result.stats.endpoints_extracted += 1
        valid, reason = is_valid_endpoint(url, self._target)
        if not valid:
            if reason == "out_of_scope":
                result.stats.endpoints_out_of_scope += 1
            return
        try:
            normalised = normalise_url(url)
        except ValueError:
            return
        key = normalised.lower()
        if key in self._known:
            return
        params = param_names(normalised)
        score, flags = interest_score(normalised, params)
        observation = f"extracted {normalised} from {source_url}"
        evidence = Evidence(
            engine="content_crawl",
            technique=technique,
            observation=observation,
            strength=EvidenceStrength.WEAK,
            meta={
                "source_url": source_url,
                "interest_score": score,
                "interest_flags": flags,
            },
        )
        existing = endpoints.get(key)
        if existing is not None:
            if not any(
                item.engine == evidence.engine
                and item.technique == evidence.technique
                and item.observation == evidence.observation
                for item in existing.evidence
            ):
                existing.evidence.append(evidence)
            return
        confidence = round(min(100.0, 0.5 * base_confidence + 0.5 * score), 1)
        endpoints[key] = UnifiedFinding(
            run_id=self._run_id,
            kind=FindingClass.ENDPOINT,
            status=FindingStatus.CANDIDATE,
            asset_value=normalised,
            parent=self._target,
            confidence=Confidence(
                value=confidence,
                components={"interest_score": float(score)},
            ),
            evidence=[evidence],
            metadata={
                "source": technique,
                "source_url": source_url,
                "params": params,
                "interest_score": score,
                "interest_flags": flags,
            },
        )

    def _add_secret(
        self,
        hit,
        source_url: str,
        secrets: dict[str, UnifiedFinding],
        result: ContentRunResult,
    ) -> None:
        asset = secret_asset_id(hit.kind, hit.value)
        if asset in self._known:
            return
        confidence = secret_confidence(hit)
        observation = f"{hit.kind} candidate at {source_url}:{hit.line}"
        evidence = Evidence(
            engine="content_secrets",
            technique="regex_entropy",
            observation=observation,
            strength=(
                EvidenceStrength.CORROBORATED
                if confidence >= 80
                else EvidenceStrength.WEAK
            ),
            meta={
                "kind": hit.kind,
                "value_preview": mask_secret(hit.value),
                "line": hit.line,
                "entropy": hit.entropy,
            },
        )
        existing = secrets.get(asset)
        if existing is not None:
            if not any(item.observation == observation for item in existing.evidence):
                existing.evidence.append(evidence)
            return
        secrets[asset] = UnifiedFinding(
            run_id=self._run_id,
            kind=FindingClass.SECRET,
            status=FindingStatus.CANDIDATE,
            asset_value=asset,
            parent=source_url,
            confidence=Confidence(
                value=confidence,
                components={
                    "pattern": hit.base_confidence,
                    "entropy": min(100.0, round(hit.entropy * 10.0, 1)),
                },
            ),
            evidence=[evidence],
            metadata={
                "kind": hit.kind,
                "line_number": hit.line,
                "source_url": source_url,
                "entropy": hit.entropy,
            },
        )

    async def _discover_robots(
        self,
        seed: str,
        endpoints: dict[str, UnifiedFinding],
        result: ContentRunResult,
    ) -> None:
        parsed = urlparse(seed)
        root = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(root, "/robots.txt")
        response = await self._fetch(robots_url, result)
        sitemaps: list[str] = []
        if response is not None and response.status < 400:
            text = decode_body(response)
            sitemaps = [match.group(1) for match in ROBOTS_SITEMAP_RE.finditer(text)]
            for match in ROBOTS_PATH_RE.finditer(text):
                path = match.group(1).strip()
                if path and path != "/":
                    self._add_endpoint(
                        urljoin(root, path), robots_url, "robots", 45.0, endpoints, result
                    )
        if not sitemaps:
            sitemaps = [urljoin(root, "/sitemap.xml")]

        queue = sitemaps[:MAX_SITEMAPS]
        visited: set[str] = set()
        while queue:
            sitemap_url = urljoin(root, queue.pop(0))
            if sitemap_url in visited:
                continue
            visited.add(sitemap_url)
            sitemap_response = await self._fetch(sitemap_url, result)
            if sitemap_response is None or sitemap_response.status >= 400:
                continue
            locations = SITEMAP_LOC_RE.findall(decode_body(sitemap_response))[
                :MAX_SITEMAP_LOCS
            ]
            for location in locations:
                if location.lower().endswith(".xml") or "sitemap" in location.lower():
                    if len(visited) + len(queue) < MAX_SITEMAPS:
                        queue.append(location)
                    continue
                self._add_endpoint(
                    location, sitemap_url, "sitemap", 45.0, endpoints, result
                )

    async def _probe(
        self, endpoints: dict[str, UnifiedFinding], result: ContentRunResult
    ) -> None:
        ranked = sorted(
            endpoints.values(), key=lambda finding: (-finding.confidence.value, finding.asset_value)
        )[: self._max_probe]
        semaphore = asyncio.Semaphore(self._max_concurrency)

        async def probe(finding: UnifiedFinding) -> None:
            async with semaphore:
                try:
                    response = await self._transport.get(
                        finding.asset_value,
                        timeout=self._timeout,
                        max_bytes=PROBE_MAX_BYTES,
                    )
                except Exception:
                    result.stats.errors += 1
                    return
            result.stats.probed += 1
            status = response.status
            finding.evidence.append(
                Evidence(
                    engine="content_probe",
                    technique="http_probe",
                    observation=f"HTTP {status} from {finding.asset_value}",
                    strength=(
                        EvidenceStrength.STRONG
                        if 200 <= status < 400
                        else EvidenceStrength.CORROBORATED
                    ),
                    meta={
                        "status": status,
                        "server": response.headers.get("server", ""),
                    },
                )
            )
            finding.metadata["probe_status"] = status
            if 200 <= status < 400:
                finding.status = FindingStatus.VERIFIED
                result.stats.verified += 1
            elif status in (404, 410):
                finding.status = FindingStatus.DEAD
                result.stats.dead += 1

        await asyncio.gather(*(probe(finding) for finding in ranked))
