import sqlite3
from pathlib import Path

from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.core.store.db import StrataDB


def _finding(
    asset_value: str,
    *,
    run_id: str,
    status: FindingStatus = FindingStatus.CANDIDATE,
    confidence: float = 50.0,
    engines: list[str] | None = None,
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.SUBDOMAIN,
        status=status,
        asset_value=asset_value,
        confidence=Confidence(value=confidence),
        evidence=[
            Evidence(engine=engine, technique="test") for engine in engines or []
        ],
    )


def test_target_scoping_isolates_reads_and_stats(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    db.upsert_finding(_finding("a.example.com", run_id="dns:a"), target="a.example")
    db.upsert_finding(_finding("b.example.com", run_id="dns:b"), target="b.example")

    scoped = list(db.iter_findings(target="a.example"))
    assert [f.asset_value for f in scoped] == ["a.example.com"]
    assert db.stats(target="a.example")["findings"] == 1
    assert db.stats()["findings"] == 2
    assert db.targets() == {"a.example": 1, "b.example": 1}
    db.close()


def test_target_is_preserved_when_later_write_omits_it(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    finding = _finding("api.example.com", run_id="dns:example")
    db.upsert_finding(finding, target="example")

    updated = finding.model_copy(update={"metadata": {"tension": {"score": 10}}})
    db.upsert_finding(updated)

    assert [f.asset_value for f in db.iter_findings(target="example")] == [
        "api.example.com"
    ]
    db.close()


def test_candidate_to_verified_records_one_outcome(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    finding = _finding("api.example.com", run_id="dns:example", confidence=60.0)
    db.upsert_finding(finding, target="example")

    finding.status = FindingStatus.VERIFIED
    finding.evidence.append(
        Evidence(engine="dns_verify", technique="resolver_consensus")
    )
    db.upsert_finding(finding, target="example")
    db.upsert_finding(finding, target="example")

    outcomes = db.iter_outcomes(target="example")
    assert len(outcomes) == 1
    assert outcomes[0]["predicted"] == 60.0
    assert outcomes[0]["observed"] == 1
    assert outcomes[0]["previous_status"] == "candidate"
    assert outcomes[0]["new_status"] == "verified"
    db.close()


def test_candidate_to_dead_records_negative_outcome(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    finding = _finding("gone.example.com", run_id="dns:example", confidence=20.0)
    db.upsert_finding(finding, target="example")

    finding.status = FindingStatus.DEAD
    finding.evidence.append(
        Evidence(engine="dns_verify", technique="resolution_failed")
    )
    db.upsert_finding(finding, target="example")

    outcomes = db.iter_outcomes(target="example")
    assert len(outcomes) == 1
    assert outcomes[0]["predicted"] == 20.0
    assert outcomes[0]["observed"] == 0
    db.close()


def test_direct_probe_records_prior_confidence_as_outcome(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    finding = _finding(
        "api.example.com",
        run_id="content:example",
        status=FindingStatus.VERIFIED,
        confidence=85.0,
        engines=["content_probe"],
    )
    finding.metadata = {"probe_status": 200, "prior_confidence": 55.0}
    db.upsert_finding(finding, target="example")

    outcomes = db.iter_outcomes(target="example")
    assert len(outcomes) == 1
    assert outcomes[0]["predicted"] == 55.0
    assert outcomes[0]["observed"] == 1
    assert outcomes[0]["previous_status"] == "candidate"
    db.close()


def test_verified_import_without_prediction_stays_out_of_ledger(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    finding = _finding(
        "imported.example.com",
        run_id="import:example",
        status=FindingStatus.VERIFIED,
        confidence=95.0,
        engines=["aperture_import"],
    )
    db.upsert_finding(finding, target="example")

    assert db.calibration(target="example")["outcomes"] == 0
    db.close()


def test_calibration_computes_brier_and_bands(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    cases = [
        ("a.example.com", 90.0, FindingStatus.VERIFIED),
        ("b.example.com", 80.0, FindingStatus.VERIFIED),
        ("c.example.com", 20.0, FindingStatus.DEAD),
    ]
    for asset, confidence, outcome in cases:
        finding = _finding(asset, run_id="dns:example", confidence=confidence)
        db.upsert_finding(finding, target="example")
        finding.status = outcome
        finding.evidence.append(
            Evidence(engine="dns_verify", technique="resolver_consensus")
        )
        db.upsert_finding(finding, target="example")

    calibration = db.calibration(target="example")
    assert calibration["outcomes"] == 3
    assert calibration["verified"] == 2
    assert calibration["dead"] == 1
    assert calibration["brier"] == 0.03
    assert calibration["accuracy"] == 1.0
    bands = {row["band"]: row for row in calibration["bands"]}
    assert bands["80-100"]["count"] == 2
    assert bands["60-79"]["count"] == 0
    assert bands["20-39"]["observed_rate"] == 0.0
    db.close()


def test_calibration_is_target_scoped(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    for asset, run_id, target in (
        ("a.example.com", "dns:a", "a.example"),
        ("b.example.com", "dns:b", "b.example"),
    ):
        finding = _finding(asset, run_id=run_id, confidence=70.0)
        db.upsert_finding(finding, target=target)
        finding.status = FindingStatus.VERIFIED
        finding.evidence.append(
            Evidence(engine="dns_verify", technique="resolver_consensus")
        )
        db.upsert_finding(finding, target=target)

    assert db.calibration(target="a.example")["outcomes"] == 1
    assert db.calibration()["outcomes"] == 2
    db.close()


def test_old_database_is_migrated_with_target_column(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            asset_value TEXT NOT NULL,
            parent TEXT,
            confidence REAL NOT NULL,
            confidence_method TEXT NOT NULL,
            scope_ok INTEGER NOT NULL DEFAULT 1,
            discovered_at TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}',
            legacy TEXT NOT NULL DEFAULT '{}',
            UNIQUE(run_id, kind, asset_value)
        );
        """
    )
    conn.commit()
    conn.close()

    db = StrataDB(path)
    columns = {row[1] for row in db.conn.execute("PRAGMA table_info(findings)")}
    assert "target" in columns
    assert "components" in columns
    db.upsert_finding(_finding("api.example.com", run_id="dns:example"), target="example")
    assert [f.asset_value for f in db.iter_findings(target="example")] == [
        "api.example.com"
    ]
    db.close()


def test_confidence_components_survive_roundtrip(tmp_path: Path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    finding = _finding("api.example.com", run_id="dns:example", confidence=76.0)
    finding.confidence = Confidence(
        value=76.0,
        method="noisy_or",
        components={"dns_brute:dns:example": 40.0, "crtsh:aperture:abc": 60.0},
    )
    db.upsert_finding(finding, target="example")
    db.close()

    reopened = StrataDB(tmp_path / "strata.db")
    stored = list(reopened.iter_findings(target="example"))[0]
    reopened.close()
    assert stored.confidence.value == 76.0
    assert stored.confidence.method.value == "noisy_or"
    assert stored.confidence.components == {
        "dns_brute:dns:example": 40.0,
        "crtsh:aperture:abc": 60.0,
    }
