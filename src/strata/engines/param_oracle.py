"""Parameter layer engine (P3).

Absorbs the deterministic active-probing half of ParamOracle: endpoint
parameter extraction, baseline/test requests, and UnifiedFinding output for
confirmed or candidate parameters.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from strata.core.content.fetch import FetchResponse, HttpTransport, decode_body
from strata.core.content.urls import host_of, param_names
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import (
    Confidence,
    ConfidenceMethod,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

PROBE_VALUE_PREFIX = "PARAMORACLE_PROBE_"
_BODY_COMPARE_LIMIT = 200_000
_STRUCTURAL_CHANGE_RATIO = 0.995
_STRUCTURAL_CHANGE_MIN_DELTA = 16


def _normalise_body(response: FetchResponse) -> str:
    text = decode_body(response, limit=_BODY_COMPARE_LIMIT)
    return " ".join(text.split())


def _body_similarity(baseline: str, test: str) -> float:
    if not baseline and not test:
        return 1.0
    return SequenceMatcher(None, baseline, test, autojunk=False).quick_ratio()



@dataclass
class ParamOracleRunStats:
    endpoints_scanned: int = 0
    candidates_tested: int = 0
    confirmed: int = 0
    errors: int = 0
    findings: int = 0


@dataclass
class ParamOracleRunResult:
    endpoints: list[UnifiedFinding] = field(default_factory=list)
    findings: list[UnifiedFinding] = field(default_factory=list)
    stats: ParamOracleRunStats = field(default_factory=ParamOracleRunStats)


def _inject_query(url: str, param_name: str, value: str) -> str:
    parsed = urlparse(url)
    query = [
        (key, val)
        for key, val in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() != param_name.lower()
    ]
    query.append((param_name, value))
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


class ParamOracle:
    def __init__(
        self,
        transport: HttpTransport,
        policy: ScopePolicy,
        *,
        max_candidates: int = 50,
        timeout: float = 10.0,
        max_concurrency: int = 8,
        max_bytes: int = 2_000_000,
    ):
        self._transport = transport
        self._policy = policy
        self._max_candidates = max_candidates
        self._timeout = timeout
        self._max_concurrency = max_concurrency
        self._max_bytes = max_bytes
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def run(self, endpoints: list[UnifiedFinding]) -> ParamOracleRunResult:
        result = ParamOracleRunResult()
        tasks = []
        for endpoint in endpoints:
            if endpoint.kind is not FindingClass.ENDPOINT:
                continue
            host = host_of(endpoint.asset_value)
            if not host or not self._policy.allows_host(host):
                raise PermissionError(f"host {host} is out of scope")

            result.stats.endpoints_scanned += 1
            params = self._candidate_params(endpoint)
            for param in params:
                if result.stats.candidates_tested >= self._max_candidates:
                    break
                candidate = f"{PROBE_VALUE_PREFIX}{result.stats.candidates_tested + 1}"
                result.stats.candidates_tested += 1
                tasks.append(self._probe(endpoint, param, candidate, result))

        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                result.stats.errors += 1

        result.findings = sorted(
            result.findings,
            key=lambda finding: (
                -finding.confidence.value,
                finding.kind.value,
                finding.asset_value,
            ),
        )
        result.stats.findings = len(result.findings)
        return result

    def _candidate_params(self, endpoint: UnifiedFinding) -> list[str]:
        raw = endpoint.metadata.get("params")
        names: list[str] = []
        if isinstance(raw, list):
            names = [str(name) for name in raw if str(name)]
        elif isinstance(raw, dict):
            names = sorted(str(name) for name in raw)

        if not names:
            names = param_names(endpoint.asset_value)

        seen: set[str] = set()
        params: list[str] = []
        for name in names:
            cleaned = name.strip().lower()
            if not cleaned or len(cleaned) > 100 or cleaned in seen:
                continue
            seen.add(cleaned)
            params.append(cleaned)
        return params

    async def _probe(
        self,
        endpoint: UnifiedFinding,
        param: str,
        candidate: str,
        result: ParamOracleRunResult,
    ) -> UnifiedFinding | None:
        async with self._semaphore:
            baseline = await self._fetch(endpoint.asset_value, result)
            if baseline is None:
                return None
            test_url = _inject_query(endpoint.asset_value, param, candidate)
            test = await self._fetch(test_url, result)
            if test is None:
                return None

            method, confirmed = self._analyze(baseline, test, candidate)
            finding = self._to_finding(
                endpoint, param, candidate, method, confirmed, baseline, test
            )
            result.findings.append(finding)
            if confirmed:
                result.stats.confirmed += 1
            return finding

    async def _fetch(
        self, url: str, result: ParamOracleRunResult
    ) -> FetchResponse | None:
        try:
            return await self._transport.get(
                url, timeout=self._timeout, max_bytes=self._max_bytes
            )
        except Exception:
            result.stats.errors += 1
            return None

    def _analyze(
        self, baseline: FetchResponse, test: FetchResponse, candidate: str
    ) -> tuple[str, bool]:
        reflected = candidate in decode_body(test)
        status_changed = baseline.status != test.status
        if 200 <= test.status < 400 and reflected:
            return "probe_value_reflection", True
        if status_changed and baseline.status >= 400 and test.status < 400:
            return "status_change", True
        if test.status >= 500 and baseline.status < 500:
            return "server_error_divergence", False
        if baseline.status == test.status and self._structural_change(baseline, test):
            return "content_change_candidate", False
        return "no_signal", False

    @staticmethod
    def _structural_change(baseline: FetchResponse, test: FetchResponse) -> bool:
        before = _normalise_body(baseline)
        after = _normalise_body(test)
        if abs(len(before) - len(after)) < _STRUCTURAL_CHANGE_MIN_DELTA:
            return False
        return _body_similarity(before, after) < _STRUCTURAL_CHANGE_RATIO

    def _to_finding(
        self,
        endpoint: UnifiedFinding,
        param: str,
        candidate: str,
        method: str,
        confirmed: bool,
        baseline: FetchResponse,
        test: FetchResponse,
    ) -> UnifiedFinding:
        host = host_of(endpoint.asset_value)
        confidence_value = {
            "probe_value_reflection": 90.0,
            "status_change": 80.0,
            "content_change_candidate": 55.0,
            "server_error_divergence": 50.0,
        }.get(method, 35.0)
        status = FindingStatus.VERIFIED if confirmed else FindingStatus.CANDIDATE
        similarity = (
            round(
                _body_similarity(_normalise_body(baseline), _normalise_body(test)),
                4,
            )
            if method == "content_change_candidate"
            else None
        )
        components = {
            "param_reflection": 90.0 if method == "probe_value_reflection" else 0.0,
            "status_change": 80.0 if method == "status_change" else 0.0,
            "content_change": 55.0 if method == "content_change_candidate" else 0.0,
            "server_error": 50.0 if method == "server_error_divergence" else 0.0,
            "interest_score": float(endpoint.confidence.value),
        }
        evidence_meta = {
            "endpoint": endpoint.asset_value,
            "candidate": candidate,
            "baseline_status": baseline.status,
            "test_status": test.status,
            "confirmed": confirmed,
        }
        if similarity is not None:
            evidence_meta["body_similarity"] = similarity
        return UnifiedFinding(
            run_id=f"param:{host}",
            kind=FindingClass.PARAM,
            status=status,
            asset_value=param,
            parent=endpoint.asset_value,
            confidence=Confidence(
                value=confidence_value,
                method=ConfidenceMethod.BAYESIAN,
                components=components,
            ),
            evidence=[
                Evidence(
                    engine="param_oracle",
                    technique=method,
                    observation=(
                        f"parameter '{param}' on {endpoint.asset_value} ({method})"
                    ),
                    strength=EvidenceStrength.STRONG if confirmed else EvidenceStrength.WEAK,
                    meta=evidence_meta,
                )
            ],
            metadata={
                **evidence_meta,
                "source": "param_oracle",
                "method": method,
                "body_similarity": similarity,
            },
        )
