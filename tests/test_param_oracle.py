import pytest
from conftest import StubHttpTransport

from strata.core.content.fetch import FetchResponse
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.engines.param_oracle import ParamOracle

BASE = "https://app.example.com"
ENDPOINT = f"{BASE}/api/v1/users"


def endpoint_finding(params: list[str] | None = None) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="content:app.example.com",
        kind=FindingClass.ENDPOINT,
        status=FindingStatus.CANDIDATE,
        asset_value=ENDPOINT,
        parent="app.example.com",
        confidence=Confidence(value=70.0, components={"interest_score": 70.0}),
        evidence=[
            Evidence(
                engine="content_crawl",
                technique="js_extract",
                observation=f"extracted {ENDPOINT}",
            )
        ],
        metadata={"source": "js_extract", "params": params or [], "interest_score": 70.0},
    )


async def test_confirms_parameter_by_probe_value_reflection() -> None:
    candidate_url = f"{ENDPOINT}?user_id=PARAMORACLE_PROBE_1"
    routes = {
        ENDPOINT: FetchResponse(ENDPOINT, 200, {"content-type": "text/plain"}, b"ok"),
        candidate_url: FetchResponse(
            candidate_url, 200, {"content-type": "text/plain"}, b"ok user_id=PARAMORACLE_PROBE_1"
        ),
    }
    engine = ParamOracle(StubHttpTransport(routes), ScopePolicy.from_list(["example.com"]))
    result = await engine.run([endpoint_finding(["user_id"])])

    assert result.stats.endpoints_scanned == 1
    assert result.stats.candidates_tested == 1
    assert result.stats.confirmed == 1
    assert result.stats.findings == 1
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.kind is FindingClass.PARAM
    assert finding.status is FindingStatus.VERIFIED
    assert finding.asset_value == "user_id"
    assert finding.parent == ENDPOINT
    assert finding.confidence.value == 90.0
    assert finding.evidence[0].engine == "param_oracle"
    assert finding.evidence[0].technique == "probe_value_reflection"
    assert finding.evidence[0].strength is EvidenceStrength.STRONG


async def test_marks_inconclusive_parameter_candidate() -> None:
    candidate_url = f"{ENDPOINT}?user_id=PARAMORACLE_PROBE_1"
    routes = {
        ENDPOINT: FetchResponse(ENDPOINT, 200, {"content-type": "text/plain"}, b"ok"),
        candidate_url: FetchResponse(
            candidate_url, 200, {"content-type": "text/plain"}, b"ok"
        ),
    }
    engine = ParamOracle(StubHttpTransport(routes), ScopePolicy.from_list(["example.com"]))
    result = await engine.run([endpoint_finding(["user_id"])])

    assert result.stats.candidates_tested == 1
    assert result.stats.confirmed == 0
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.confidence.value == 35.0
    assert finding.evidence[0].technique == "no_signal"
    assert finding.evidence[0].strength is EvidenceStrength.WEAK


async def test_rejects_out_of_scope_endpoint() -> None:
    engine = ParamOracle(
        StubHttpTransport({}),
        ScopePolicy.from_list(["other.example"]),
        max_candidates=5,
    )
    with pytest.raises(PermissionError):
        await engine.run([endpoint_finding(["user_id"])])


async def test_confirms_parameter_by_status_change() -> None:
    candidate_url = f"{ENDPOINT}?user_id=PARAMORACLE_PROBE_1"
    routes = {
        ENDPOINT: FetchResponse(ENDPOINT, 404, {}, b"missing"),
        candidate_url: FetchResponse(candidate_url, 200, {}, b"fine"),
    }
    engine = ParamOracle(StubHttpTransport(routes), ScopePolicy.from_list(["example.com"]))
    result = await engine.run([endpoint_finding(["user_id"])])

    finding = result.findings[0]
    assert result.stats.confirmed == 1
    assert finding.status is FindingStatus.VERIFIED
    assert finding.confidence.value == 80.0
    assert finding.evidence[0].technique == "status_change"


async def test_flags_structural_content_change_as_candidate() -> None:
    candidate_url = f"{ENDPOINT}?user_id=PARAMORACLE_PROBE_1"
    baseline_body = b"<html>" + b"alpha " * 100 + b"</html>"
    test_body = b"<html>" + b"beta " * 100 + b"</html>"
    routes = {
        ENDPOINT: FetchResponse(ENDPOINT, 200, {}, baseline_body),
        candidate_url: FetchResponse(candidate_url, 200, {}, test_body),
    }
    engine = ParamOracle(StubHttpTransport(routes), ScopePolicy.from_list(["example.com"]))
    result = await engine.run([endpoint_finding(["user_id"])])

    finding = result.findings[0]
    assert result.stats.confirmed == 0
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.confidence.value == 55.0
    assert finding.evidence[0].technique == "content_change_candidate"
    assert finding.metadata["body_similarity"] is not None
    assert finding.metadata["body_similarity"] < 0.995


async def test_flags_server_error_divergence_as_candidate() -> None:
    candidate_url = f"{ENDPOINT}?user_id=PARAMORACLE_PROBE_1"
    routes = {
        ENDPOINT: FetchResponse(ENDPOINT, 200, {}, b"ok"),
        candidate_url: FetchResponse(candidate_url, 500, {}, b"boom"),
    }
    engine = ParamOracle(StubHttpTransport(routes), ScopePolicy.from_list(["example.com"]))
    result = await engine.run([endpoint_finding(["user_id"])])

    finding = result.findings[0]
    assert result.stats.confirmed == 0
    assert finding.confidence.value == 50.0
    assert finding.evidence[0].technique == "server_error_divergence"


async def test_ignores_tiny_body_noise() -> None:
    candidate_url = f"{ENDPOINT}?user_id=PARAMORACLE_PROBE_1"
    routes = {
        ENDPOINT: FetchResponse(ENDPOINT, 200, {}, b"ok"),
        candidate_url: FetchResponse(candidate_url, 200, {}, b"ok "),
    }
    engine = ParamOracle(StubHttpTransport(routes), ScopePolicy.from_list(["example.com"]))
    result = await engine.run([endpoint_finding(["user_id"])])

    finding = result.findings[0]
    assert finding.confidence.value == 35.0
    assert finding.evidence[0].technique == "no_signal"
