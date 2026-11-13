from pathlib import Path

import pytest

from strata.adapters.aperture import load_aperture_jsonl, parse_aperture_record
from strata.core.schema.models import (
    EvidenceStrength,
    FindingClass,
    FindingStatus,
)

FIXTURE = Path(__file__).parent / "fixtures" / "aperture_sample.jsonl"


class TestParseRecord:
    def record(self, **overrides):
        base = {
            "id": "x1",
            "scan_id": "scan-9",
            "asset_id": "api.example.com",
            "asset_type": "subdomain",
            "parent_asset": "example.com",
            "source_plugin": "crtsh,hackertarget",
            "per_source_raw_confidence": {"crtsh": 70, "hackertarget": 70},
            "combined_confidence": 79.9,
            "adjusted_confidence": 79.9,
            "consensus_count": 2,
            "temporal_stability": 1,
            "resolved_ips": ["192.0.2.1"],
            "metadata": {"source": "ct_log"},
            "discovered_at": "2026-09-22T21:48:43.3962741Z",
        }
        base.update(overrides)
        return base

    def test_minimal_record_maps(self):
        f = parse_aperture_record(self.record())
        assert f.kind is FindingClass.SUBDOMAIN
        assert f.status is FindingStatus.CANDIDATE
        assert f.asset_value == "api.example.com"
        assert f.parent == "example.com"
        assert f.run_id == "aperture:scan-9"
        assert f.confidence.value == 79.9
        assert f.confidence.components == {"crtsh": 70.0, "hackertarget": 70.0}

    def test_sources_become_evidence_records(self):
        f = parse_aperture_record(self.record())
        assert [e.engine for e in f.evidence] == ["crtsh", "hackertarget"]
        for e in f.evidence:
            assert e.technique == "ct_log"
            assert e.strength is EvidenceStrength.CORROBORATED
            assert e.meta["resolved_ips"] == ["192.0.2.1"]
            assert e.meta["aperture_id"] == "x1"

    def test_consensus_strength_ladder(self):
        one = parse_aperture_record(self.record(consensus_count=1))
        three = parse_aperture_record(self.record(consensus_count=3))
        assert one.evidence[0].strength is EvidenceStrength.WEAK
        assert three.evidence[0].strength is EvidenceStrength.STRONG

    def test_z_suffix_timestamp_parsed(self):
        f = parse_aperture_record(self.record())
        assert f.discovered_at.isoformat().startswith("2026-09-22T21:48:43")
        assert f.discovered_at.tzinfo is not None

    def test_legacy_fields_preserved(self):
        f = parse_aperture_record(self.record())
        assert f.legacy["combined_confidence"] == 79.9
        assert f.legacy["id"] == "x1"

    def test_missing_field_raises(self):
        rec = self.record()
        del rec["consensus_count"]
        with pytest.raises(ValueError, match="missing fields"):
            parse_aperture_record(rec)

    def test_unsupported_asset_type_raises(self):
        with pytest.raises(ValueError, match="asset_type"):
            parse_aperture_record(self.record(asset_type="ip_range"))

    def test_empty_source_plugin_raises(self):
        with pytest.raises(ValueError, match="empty source_plugin"):
            parse_aperture_record(self.record(source_plugin=""))


class TestJsonlLoader:
    def test_fixture_loads_four_findings(self):
        findings = list(load_aperture_jsonl(FIXTURE))
        assert len(findings) == 4
        assets = {f.asset_value for f in findings}
        assert "edge.example.org" in assets
        assert "api.example.com" in assets

    def test_blank_lines_skipped(self, tmp_path):
        p = tmp_path / "x.jsonl"
        p.write_text("\n\n")
        assert list(load_aperture_jsonl(p)) == []

    def test_malformed_json_line_raises_with_lineno(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        p.write_text('{"asset_id": broken}\n')
        with pytest.raises(ValueError, match="bad.jsonl:1"):
            list(load_aperture_jsonl(p))
