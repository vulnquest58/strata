import re

from strata.cli.main import main
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.core.store.db import StrataDB


def seed(asset: str, status: FindingStatus) -> UnifiedFinding:
    return UnifiedFinding(
        run_id="seed:example.test",
        kind=FindingClass.SUBDOMAIN,
        status=status,
        asset_value=asset,
        parent="example.test",
        confidence=Confidence(value=75.0, components={"test": 75.0}),
        evidence=[Evidence(engine="test", technique="seed", observation="seed")],
        metadata={"source": "test"},
    )


def test_scoped_stats_list_report_tension_calibrate(tmp_path, capsys):
    db = tmp_path / "strata.db"
    store = StrataDB(db)
    store.upsert_finding(seed("a.example.test", FindingStatus.CANDIDATE), target="a.example.test")
    store.upsert_finding(seed("b.example.test", FindingStatus.CANDIDATE), target="b.example.test")
    store.upsert_finding(seed("a.example.test", FindingStatus.VERIFIED), target="a.example.test")
    store.close()

    assert main(["stats", "--db", str(db), "--target", "a.example.test"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"findings\s+1\b", out)

    assert main(["list", "--db", str(db), "--target", "b.example.test"]) == 0
    out = capsys.readouterr().out
    assert "b.example.test" in out
    assert "a.example.test" not in out

    report = tmp_path / "report.md"
    assert (
        main(
            [
                "report",
                "--db",
                str(db),
                "--target",
                "a.example.test",
                "--out",
                str(report),
            ]
        )
        == 0
    )
    text = report.read_text(encoding="utf-8")
    assert "a.example.test" in text
    assert "b.example.test" not in text

    tension = tmp_path / "tension.md"
    assert (
        main(
            [
                "tension",
                "--db",
                str(db),
                "--target",
                "a.example.test",
                "--out",
                str(tension),
            ]
        )
        == 0
    )
    text = tension.read_text(encoding="utf-8")
    assert "a.example.test" in text
    assert "b.example.test" not in text

    calibration = tmp_path / "calibration.md"
    assert (
        main(
            [
                "calibrate",
                "--db",
                str(db),
                "--target",
                "a.example.test",
                "--out",
                str(calibration),
            ]
        )
        == 0
    )
    text = calibration.read_text(encoding="utf-8")
    assert "- outcomes: 1" in text
    assert "- verified: 1" in text

    assert main(["stats", "--db", str(db)]) == 0
    assert "showing all findings" in capsys.readouterr().out


def test_calibrate_without_outcomes(tmp_path, capsys):
    db = tmp_path / "empty.db"
    report = tmp_path / "calibration.md"
    assert (
        main(["calibrate", "--db", str(db), "--out", str(report)]) == 0
    )
    assert "- outcomes: 0" in report.read_text(encoding="utf-8")
    assert "no verification outcomes yet" in capsys.readouterr().out
