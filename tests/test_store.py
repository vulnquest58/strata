import pytest

from strata.adapters.aperture import load_aperture_jsonl
from strata.core.store.db import StrataDB

FIXTURE = None


def load_fixture():
    from pathlib import Path

    return load_aperture_jsonl(Path(__file__).parent / "fixtures" / "aperture_sample.jsonl")


class TestStore:
    def test_ingest_fixture_golden_path(self, tmp_path):
        db = StrataDB(tmp_path / "strata.db")
        findings = list(load_fixture())
        for finding in findings:
            db.upsert_finding(finding)

        stats = db.stats()
        assert stats["findings"] == 4
        assert stats["evidence"] == 7

        rows = list(db.iter_findings())
        assert len(rows) == 4
        edge = next(r for r in rows if r.asset_value == "edge.example.org")
        assert edge.run_id == "aperture:bbbb2222-3333-4444-8555-666677778888"
        assert len(edge.evidence) == 3
        assert {e.engine for e in edge.evidence} == {
            "rapiddns", "crtsh", "hackertarget",
        }
        db.close()

    def test_upsert_is_idempotent_on_dedup_key(self, tmp_path):
        db = StrataDB(tmp_path / "strata.db")
        findings = list(load_fixture())
        for finding in findings:
            db.upsert_finding(finding)
        for finding in findings:
            db.upsert_finding(finding)

        stats = db.stats()
        assert stats["findings"] == 4
        assert stats["status_candidate"] == 4
        assert stats["evidence"] == 7  # re-import must not duplicate evidence
        db.close()

    def test_engine_findings_persist_and_reupsert_updates(self, tmp_path):
        from strata.core.schema.models import (
            Confidence,
            Evidence,
            FindingClass,
            FindingStatus,
            UnifiedFinding,
        )

        db = StrataDB(tmp_path / "strata.db")
        finding = UnifiedFinding(
            run_id="dns:example.com",
            kind=FindingClass.SUBDOMAIN,
            status=FindingStatus.CANDIDATE,
            asset_value="api.example.com",
            parent="example.com",
            confidence=Confidence(value=40.0),
            evidence=[Evidence(engine="dns_brute", technique="wordlist_a_probe")],
        )
        db.upsert_finding(finding)

        # verification pass: same dedup key, new status + corroborating evidence
        finding.status = FindingStatus.VERIFIED
        finding.evidence.append(
            Evidence(engine="dns_verify", technique="resolver_consensus")
        )
        db.upsert_finding(finding)

        stats = db.stats()
        assert stats["findings"] == 1
        assert stats["status_verified"] == 1
        assert stats["evidence"] == 2
        db.close()

    def test_schema_rejects_verified_without_evidence(self, tmp_path):
        from pydantic import ValidationError

        from strata.core.schema.models import (
            Confidence,
            FindingClass,
            FindingStatus,
            UnifiedFinding,
        )

        db = StrataDB(tmp_path / "strata.db")
        with pytest.raises(ValidationError):
            db.upsert_finding(
                UnifiedFinding(
                    run_id="r1",
                    kind=FindingClass.SUBDOMAIN,
                    status=FindingStatus.VERIFIED,
                    asset_value="x.example.com",
                    confidence=Confidence(value=90.0),
                )
            )
        db.close()

    def test_stats_counts_by_status(self, tmp_path):
        from strata.core.schema.models import (
            Confidence,
            Evidence,
            FindingClass,
            FindingStatus,
            UnifiedFinding,
        )

        db = StrataDB(tmp_path / "strata.db")
        db.upsert_finding(
            UnifiedFinding(
                run_id="r1",
                kind=FindingClass.SUBDOMAIN,
                asset_value="a.example.com",
                confidence=Confidence(value=50.0),
            )
        )
        db.upsert_finding(
            UnifiedFinding(
                run_id="r1",
                kind=FindingClass.SUBDOMAIN,
                status=FindingStatus.VERIFIED,
                asset_value="b.example.com",
                confidence=Confidence(value=50.0),
                evidence=[Evidence(engine="doh", technique="resolver_consensus")],
            )
        )
        stats = db.stats()
        assert stats["status_candidate"] == 1
        assert stats["status_verified"] == 1
        assert stats["evidence"] == 1
        db.close()

    def test_iter_findings_round_trips_verified_rows(self, tmp_path):
        """Regression: verified/dead findings must rebuild with evidence
        attached (the schema forbids verified-without-evidence at
        construction time)."""
        from strata.core.schema.models import (
            Confidence,
            Evidence,
            FindingClass,
            FindingStatus,
            UnifiedFinding,
        )

        db = StrataDB(tmp_path / "strata.db")
        verified = UnifiedFinding(
            run_id="r1",
            kind=FindingClass.SUBDOMAIN,
            status=FindingStatus.VERIFIED,
            asset_value="a.example.com",
            confidence=Confidence(value=50.0),
            evidence=[Evidence(engine="dns_verify", technique="resolver_consensus")],
        )
        dead = UnifiedFinding(
            run_id="r1",
            kind=FindingClass.SUBDOMAIN,
            status=FindingStatus.DEAD,
            asset_value="b.example.com",
            confidence=Confidence(value=10.0),
            evidence=[
                Evidence(
                    engine="dns_verify",
                    technique="resolver_consensus",
                    observation="nxdomain",
                )
            ],
        )
        db.upsert_finding(verified)
        db.upsert_finding(dead)

        rows = {f.asset_value: f for f in db.iter_findings()}
        assert rows["a.example.com"].status is FindingStatus.VERIFIED
        assert len(rows["a.example.com"].evidence) == 1
        assert rows["b.example.com"].status is FindingStatus.DEAD
        db.close()
