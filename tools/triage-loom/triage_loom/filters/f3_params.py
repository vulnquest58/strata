"""
Filter 3: Parameter Corroboration

Instead of relying on a single ML model or single source to predict parameters
(as ParamOracle does with its ML pipeline), this filter extracts parameters
from three independent techniques and only keeps those confirmed by ≥2 of them.

The three techniques:
1. archive_static  — direct extraction from query strings in archived URLs
                     (these are the most reliable: the parameter was actually used)
2. js_static       — regex-based extraction from JavaScript files linked to the target
                     (fetch/XHR/axios calls, URLSearchParams patterns, FormData)
3. openapi         — discovery and parsing of publicly accessible OpenAPI/Swagger specs
                     (highest quality: machine-readable contracts)

No ML, no probabilistic scoring — just three independent signals that vote.
A parameter appearing in 2+ techniques is likely real; 1/3 is speculative.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from rich.console import Console

from triage_loom.filters.base import BaseFilter, FilterResult
from triage_loom.models import CorroborationLayer, ParameterRecord, ParameterTechnique

console = Console(stderr=True)

_TIMEOUT = httpx.Timeout(4.0, connect=2.0)
_HEADERS = {"User-Agent": "Triage-Loom/1.0 (OSINT; param-discovery)"}

# Regex patterns for JS parameter extraction.
# Matches common patterns in modern JS: fetch, XHR, axios, URLSearchParams.
_JS_PARAM_PATTERNS = [
    # URLSearchParams: new URLSearchParams({param: value}) or .append('param', ...)
    re.compile(r"""['"](\w[\w\-_]*)['"][\s]*[,:]"""),
    # fetch/axios body/params objects: {key: val, key2: val2}
    re.compile(r"""[\{,]\s*['"]?(\w[\w\-_]+)['"]?\s*:"""),
    # query string building: `?key=` or `&key=` in template literals / strings
    re.compile(r"""[?&](\w[\w\-_]+)="""),
    # FormData.append('param', ...)
    re.compile(r"""\.append\s*\(\s*['"](\w[\w\-_]+)['"]"""),
]

# OpenAPI/Swagger spec locations to probe.
_OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/api-docs", "/api-docs/swagger.json",
    "/docs/openapi.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
]


class ParameterCorroborationFilter(BaseFilter):
    """Filter 3: Multi-technique parameter extraction with ≥2-technique corroboration."""

    @property
    def name(self) -> str:
        return "ParameterCorroborationFilter"

    @property
    def stage(self) -> int:
        return 3

    async def run(
        self,
        asset_id: str,
        archived_urls: list[str] | None = None,
        **_: Any,
    ) -> FilterResult:
        """
        Extract parameters from all 3 techniques and return only corroborated ones.

        Args:
            asset_id:     Subdomain being analysed (e.g., "api.target.com").
            archived_urls: URLs already retrieved from Filter 2 archives.
        """
        extracted: dict[ParameterTechnique, set[str]] = defaultdict(set)

        # Technique 1: static extraction from archived query strings.
        if archived_urls:
            extracted[ParameterTechnique.archive_static] = self._extract_from_urls(archived_urls)

        # Technique 2: JS file extraction.
        js_params = await self._extract_from_js(asset_id)
        extracted[ParameterTechnique.js_static] = js_params

        # Technique 3: OpenAPI/Swagger spec.
        openapi_params = await self._extract_from_openapi(asset_id)
        extracted[ParameterTechnique.openapi] = openapi_params

        # Corroborate: keep only params seen in ≥2 techniques.
        param_counts: dict[str, list[ParameterTechnique]] = defaultdict(list)
        for technique, params in extracted.items():
            for p in params:
                param_counts[p].append(technique)

        corroborated = [
            ParameterRecord(name=p, techniques=techs)
            for p, techs in param_counts.items()
            if len(techs) >= 2
        ]
        speculative = [
            ParameterRecord(name=p, techniques=techs)
            for p, techs in param_counts.items()
            if len(techs) < 2
        ]

        passed = len(corroborated) > 0

        return FilterResult(
            passed=passed,
            layer_tag=CorroborationLayer.param_archive_static.value if passed else None,
            evidence={
                "corroborated_params": [p.name for p in corroborated],
                "speculative_params": [p.name for p in speculative],
                "by_technique": {t.value: list(ps) for t, ps in extracted.items()},
            },
            metadata={
                "corroborated": [p.model_dump() for p in corroborated],
                "speculative": [p.model_dump() for p in speculative],
            },
        )

    # ------------------------------------------------------------------
    # Technique 1: Archive URL query string extraction
    # ------------------------------------------------------------------

    def _extract_from_urls(self, urls: list[str]) -> set[str]:
        """Extract parameter names from query strings in a list of URLs."""
        params: set[str] = set()
        for url in urls:
            try:
                qs = urlparse(url).query
                if qs:
                    for key in parse_qs(qs, keep_blank_values=True).keys():
                        if key and len(key) <= 64:  # sanity length check
                            params.add(key.lower())
            except Exception:
                continue
        return params

    # ------------------------------------------------------------------
    # Technique 2: JS file regex extraction
    # ------------------------------------------------------------------

    async def _extract_from_js(self, hostname: str) -> set[str]:
        """
        Fetch the homepage and linked JS files, extract parameter names via regex.
        Limited to first 10 JS files found to avoid excessive requests.
        """
        params: set[str] = set()

        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True, verify=False
        ) as client:
            # Step 1: fetch homepage to discover linked JS files.
            try:
                resp = await client.get(f"https://{hostname}")
                html = resp.text
            except Exception:
                return params

            js_urls = self._find_js_urls(html, hostname)[:10]

            # Step 2: fetch each JS file and apply regex patterns.
            for js_url in js_urls:
                try:
                    js_resp = await client.get(js_url)
                    content = js_resp.text[:200_000]  # cap at 200KB per file
                    for pattern in _JS_PARAM_PATTERNS:
                        for match in pattern.finditer(content):
                            param = match.group(1)
                            if 2 <= len(param) <= 64 and not param.startswith("_"):
                                params.add(param.lower())
                except Exception:
                    continue

        return params

    def _find_js_urls(self, html: str, hostname: str) -> list[str]:
        """Extract <script src="..."> URLs from HTML."""
        pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        urls = []
        for match in pattern.finditer(html):
            src = match.group(1)
            if src.startswith("http"):
                urls.append(src)
            elif src.startswith("//"):
                urls.append(f"https:{src}")
            elif src.startswith("/"):
                urls.append(f"https://{hostname}{src}")
        return urls

    # ------------------------------------------------------------------
    # Technique 3: OpenAPI/Swagger spec extraction
    # ------------------------------------------------------------------

    async def _extract_from_openapi(self, hostname: str) -> set[str]:
        """
        Probe known OpenAPI spec paths and extract parameter names.
        Handles both JSON and YAML formats (JSON only in this implementation;
        YAML support requires PyYAML which is an optional dependency).
        """
        import json as _json
        params: set[str] = set()

        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True, verify=False
        ) as client:
            for path in _OPENAPI_PATHS:
                url = f"https://{hostname}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or path.endswith(".json"):
                        spec = _json.loads(resp.text)
                        params |= self._parse_openapi_json(spec)
                        break  # found a valid spec, stop probing
                except Exception:
                    continue

        return params

    def _parse_openapi_json(self, spec: dict) -> set[str]:
        """Extract parameter names from an OpenAPI 3.x or Swagger 2.x JSON spec."""
        params: set[str] = set()
        paths = spec.get("paths", {})
        for _path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method_item in path_item.values():
                if not isinstance(method_item, dict):
                    continue
                # OpenAPI 3.x / Swagger 2.x parameters array
                for param in method_item.get("parameters", []):
                    if isinstance(param, dict) and "name" in param:
                        params.add(str(param["name"]).lower())
                # OpenAPI 3.x requestBody schema properties
                request_body = method_item.get("requestBody", {})
                content = request_body.get("content", {})
                for media_type in content.values():
                    schema = media_type.get("schema", {})
                    for prop_name in schema.get("properties", {}).keys():
                        params.add(prop_name.lower())
        return params

    def corroborate(
        self,
        endpoint: str,
        extracted: dict[ParameterTechnique, set[str]],
    ) -> set[str]:
        """
        Return only parameters that appear in ≥2 independent techniques.
        This is the canonical corroboration method for use outside the filter pipeline.
        """
        param_sources: dict[str, int] = defaultdict(int)
        for params in extracted.values():
            for p in params:
                param_sources[p] += 1
        return {p for p, count in param_sources.items() if count >= 2}
