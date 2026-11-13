from pathlib import Path

from conftest import StubHttpTransport, StubTransport

from strata.core.dns.resolver import Resolver
from strata.core.schema.models import FindingClass
from strata.core.store.db import StrataDB
from strata.engines.orchestrator import Orchestrator, RunOptions


def _dns_table() -> dict[tuple[str, str], tuple[str, ...]]:
    return {
        ("example.com", "A"): ("192.0.2.10",),
        ("example.com", "AAAA"): (),
        ("example.com", "CNAME"): (),
        ("www.example.com", "A"): ("192.0.2.11",),
        ("www.example.com", "AAAA"): (),
        ("www.example.com", "CNAME"): (),
    }


def _http_routes() -> dict[str, object]:
    return {
        "https://example.com/": object(),
        "https://example.com/static/app.js": object(),
        "https://example.com/api/users?user_id=1": object(),
        "https://example.com/api/users?user_id=PARAMORACLE_PROBE_1": object(),
    }


async def test_orchestrator_runs_pipeline_and_learns(tmp_path: Path) -> None:
    db_path = tmp_path / "strata.db"
    report_path = tmp_path / "report.md"
    options = RunOptions(
        target="example.com",
        db_path=db_path,
        report_out=report_path,
        max_scripts=5,
        max_probe=10,
        max_candidates=10,
    )
    resolver = Resolver(StubTransport(_dns_table()))
    # The real test builds concrete responses in a follow-up test file.
    from strata.core.content.fetch import FetchResponse

    routes = _http_routes()
    routes["https://example.com/"] = FetchResponse(
        "https://example.com/",
        200,
        {"content-type": "text/html"},
        b'<script src="/static/app.js"></script>',
    )
    routes["https://example.com/static/app.js"] = FetchResponse(
        "https://example.com/static/app.js",
        200,
        {"content-type": "application/javascript"},
        b'const url = "/api/users?user_id=1";',
    )
    routes["https://example.com/api/users?user_id=1"] = FetchResponse(
        "https://example.com/api/users?user_id=1", 200, {}, b"ok"
    )
    routes["https://example.com/api/users?user_id=PARAMORACLE_PROBE_1"] = FetchResponse(
        "https://example.com/api/users?user_id=PARAMORACLE_PROBE_1",
        200,
        {},
        b"ok PARAMORACLE_PROBE_1",
    )
    transport = StubHttpTransport(routes)
    orchestrator = Orchestrator(options, resolver=resolver, transport=transport)
    result = await orchestrator.run()

    assert result.report_path == report_path
    assert report_path.exists()
    db = StrataDB(db_path)
    stats = db.stats()
    db.close()
    assert stats["findings"] > 0
    assert result.memory is not None
    assert result.memory.runs == 1
    assert "dns" in result.memory.stages
    assert "content" in result.memory.stages
    assert "param" in result.memory.stages
    assert "fuse" in result.memory.stages
    assert "tension" in result.memory.stages
    db = StrataDB(db_path)
    tensioned = [
        f
        for f in db.iter_findings()
        if isinstance(f.metadata.get("tension"), dict)
        and "score" in f.metadata["tension"]
    ]
    db.close()
    assert tensioned, "tension stage should stamp metadata on findings"


async def test_orchestrator_resumes_and_skips_known_assets(tmp_path: Path) -> None:
    db_path = tmp_path / "strata.db"
    options = RunOptions(
        target="example.com",
        db_path=db_path,
        no_content=True,
        no_param=True,
        no_fuse=True,
        resume=True,
    )
    resolver = Resolver(StubTransport(_dns_table()))
    transport = StubHttpTransport({})
    orchestrator = Orchestrator(options, resolver=resolver, transport=transport)
    first = await orchestrator.run()
    second = await Orchestrator(options, resolver=resolver, transport=transport).run()

    assert first.memory is not None
    assert second.memory is not None
    assert first.memory.runs == 1
    assert second.memory.runs == 2
    db = StrataDB(db_path)
    subdomains = {
        finding.asset_value
        for finding in db.iter_findings()
        if finding.kind is FindingClass.SUBDOMAIN
    }
    db.close()
    assert "www.example.com" in subdomains
    assert second.memory.stages["dns"].new_findings == 0


async def test_orchestrator_dry_run_is_non_mutating(tmp_path: Path) -> None:
    db_path = tmp_path / "strata.db"
    options = RunOptions(
        target="example.com",
        db_path=db_path,
        dry_run=True,
        no_content=True,
        no_param=True,
        no_fuse=True,
    )
    resolver = Resolver(StubTransport(_dns_table()))
    transport = StubHttpTransport({})
    orchestrator = Orchestrator(options, resolver=resolver, transport=transport)
    result = await orchestrator.run()
    assert result.stages == []
    assert result.memory is not None
    assert result.memory.runs == 0
    db = StrataDB(db_path)
    stats = db.stats()
    db.close()
    assert stats["findings"] == 0


async def test_orchestrator_imports_external_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "strata.db"
    fixture = Path(__file__).parent / "fixtures" / "aperture_sample.jsonl"
    options = RunOptions(
        target="example.com",
        db_path=db_path,
        no_dns=True,
        no_content=True,
        no_param=True,
        no_fuse=True,
        import_aperture=fixture,
    )
    resolver = Resolver(StubTransport(_dns_table()))
    transport = StubHttpTransport({})
    orchestrator = Orchestrator(options, resolver=resolver, transport=transport)
    result = await orchestrator.run()
    db = StrataDB(db_path)
    stats = db.stats()
    db.close()
    assert stats["findings"] >= 4
    assert result.stages[0].stage == "absorb"
    assert result.stages[0].new_findings >= 4


async def test_orchestrator_imports_triage_loom_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "strata.db"
    fixture = Path(__file__).parent / "fixtures" / "triage_loom_sample.jsonl"
    options = RunOptions(
        target="example.com",
        db_path=db_path,
        no_dns=True,
        no_content=True,
        no_param=True,
        no_fuse=True,
        import_triage_loom=fixture,
    )
    resolver = Resolver(StubTransport(_dns_table()))
    transport = StubHttpTransport({})
    orchestrator = Orchestrator(options, resolver=resolver, transport=transport)
    result = await orchestrator.run()
    db = StrataDB(db_path)
    stats = db.stats()
    db.close()
    assert stats["findings"] >= 2
    assert result.stages[0].stage == "absorb"
    assert result.stages[0].new_findings >= 2
