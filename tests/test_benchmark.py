from pathlib import Path

from conftest import StubHttpTransport, StubTransport

from strata.core.content.fetch import FetchResponse
from strata.core.dns.resolver import Resolver
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.core.store.db import StrataDB
from strata.engines.orchestrator import Orchestrator, RunOptions
from strata.eval.benchmark import finding_key, score_findings

DOMAIN = "example.com"
USERS = f"https://{DOMAIN}/api/users?user_id=1"


def finding(kind: FindingClass, asset: str, parent: str | None = None) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="bench",
        kind=kind,
        status=FindingStatus.CANDIDATE,
        asset_value=asset,
        parent=parent,
        confidence=Confidence(value=60.0, components={"bench": 60.0}),
        evidence=[Evidence(engine="bench", technique="fixture", observation="fixture")],
    )


def test_score_reports_precision_recall_and_f1() -> None:
    findings = [
        finding(FindingClass.SUBDOMAIN, "www.example.com"),
        finding(FindingClass.ENDPOINT, USERS),
        finding(FindingClass.SUBDOMAIN, "noise.example.com"),
    ]
    expected = {
        "subdomain:www.example.com",
        f"endpoint:{USERS.lower()}",
        "subdomain:api.example.com",
    }
    score = score_findings(findings, expected)

    assert score.true_positives == 2
    assert score.false_positives == 1
    assert score.false_negatives == 1
    assert score.precision == 2 / 3
    assert score.recall == 2 / 3
    assert score.by_kind["subdomain"] == {"tp": 1, "fp": 1, "fn": 1}
    assert score.by_kind["endpoint"] == {"tp": 1, "fp": 0, "fn": 0}
    assert score.as_dict()["precision"] == 0.6667


async def test_orchestrator_golden_surface(tmp_path: Path) -> None:
    db_path = tmp_path / "strata.db"
    options = RunOptions(
        target=DOMAIN,
        db_path=db_path,
        report_out=tmp_path / "benchmark.md",
        max_scripts=5,
        max_probe=10,
        max_candidates=10,
        no_fingerprint=True,
        no_passive=True,
    )
    dns = {
        (DOMAIN, "A"): ("192.0.2.10",),
        (DOMAIN, "AAAA"): (),
        (DOMAIN, "CNAME"): (),
        ("www.example.com", "A"): ("192.0.2.11",),
        ("www.example.com", "AAAA"): (),
        ("www.example.com", "CNAME"): (),
    }
    routes = {
        f"https://{DOMAIN}/": FetchResponse(
            f"https://{DOMAIN}/",
            200,
            {"content-type": "text/html"},
            b'<script src="/static/app.js"></script>',
        ),
        f"https://{DOMAIN}/static/app.js": FetchResponse(
            f"https://{DOMAIN}/static/app.js",
            200,
            {"content-type": "application/javascript"},
            b'const url = "/api/users?user_id=1";',
        ),
        USERS: FetchResponse(USERS, 200, {}, b"ok"),
        f"{USERS}&user_id=PARAMORACLE_PROBE_1": FetchResponse(
            f"{USERS}&user_id=PARAMORACLE_PROBE_1", 200, {}, b"ok PARAMORACLE_PROBE_1"
        ),
    }
    orchestrator = Orchestrator(
        options,
        resolver=Resolver(StubTransport(dns)),
        transport=StubHttpTransport(routes),
    )
    await orchestrator.run()

    db = StrataDB(db_path)
    findings = list(db.iter_findings(target=DOMAIN))
    db.close()
    actual = {finding_key(f) for f in findings}

    expected = {
        "subdomain:www.example.com",
        f"endpoint:{USERS}",
        f"endpoint:https://{DOMAIN}/static/app.js",
        f"param:{USERS}::user_id",
    }
    score = score_findings(findings, expected)
    assert score.recall >= 0.75, (score.as_dict(), sorted(actual))
    assert score.precision >= 0.5, (score.as_dict(), sorted(actual))
