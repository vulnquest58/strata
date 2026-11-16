import pytest

from strata.cli.main import main
from strata.core.calibration import CalibrationModel, isotonic_points
from strata.core.reporting import markdown_report
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)
from strata.core.store.db import StrataDB
from strata.engines.orchestrator import Orchestrator, RunOptions


def _finding(
    asset: str,
    *,
    run_id: str = "dns:example.test",
    status: FindingStatus = FindingStatus.CANDIDATE,
    confidence: float = 50.0,
) -> UnifiedFinding:
    return UnifiedFinding(
        run_id=run_id,
        kind=FindingClass.SUBDOMAIN,
        status=status,
        asset_value=asset,
        parent="example.test",
        confidence=Confidence(value=confidence),
        evidence=[Evidence(engine="dns_brute", technique="test")],
    )


def _record_outcomes(
    db: StrataDB,
    target: str,
    *,
    confidence: float,
    verified: int,
    dead: int,
    prefix: str,
) -> None:
    for index in range(verified):
        finding = _finding(f"{prefix}{index}.example.test", confidence=confidence)
        db.upsert_finding(finding, target=target)
        finding.status = FindingStatus.VERIFIED
        finding.evidence.append(Evidence(engine="dns_verify", technique="ok"))
        db.upsert_finding(finding, target=target)
    for index in range(dead):
        finding = _finding(
            f"{prefix}x{index}.example.test", confidence=confidence
        )
        db.upsert_finding(finding, target=target)
        finding.status = FindingStatus.DEAD
        finding.evidence.append(Evidence(engine="dns_verify", technique="gone"))
        db.upsert_finding(finding, target=target)


# ── isotonic math ───────────────────────────────────────────────────────────


def test_isotonic_points_are_monotone() -> None:
    pairs = [(10, 0), (20, 1), (30, 0), (40, 1), (50, 1)]
    points = isotonic_points(pairs)
    assert points
    values = [y for _, y in points]
    assert values == sorted(values)


def test_isotonic_smoothing_keeps_extremes_reachable_but_bounded() -> None:
    points = isotonic_points([(60, 1)] * 20)
    assert len(points) == 1
    _, y = points[0]
    assert 0.9 < y < 1.0  # Laplace-smoothed, never exactly 1.0


def test_isotonic_pools_small_samples_toward_middle() -> None:
    points = isotonic_points([(40, 1), (40, 0)])
    assert len(points) == 1
    _, y = points[0]
    assert y == pytest.approx(0.5)


def test_smoothing_never_inverts_block_order() -> None:
    # A large near-perfect block at low x must not outrank a small perfect
    # block at higher x: Laplace smoothing is size-dependent, so the map is
    # re-pooled after smoothing to stay monotone.
    pairs = [(30, 1)] * 100 + [(55, 1)] * 6
    points = isotonic_points(pairs)
    values = [y for _, y in points]
    assert values == sorted(values)
    outcomes = [{"predicted": x, "observed": y} for x, y in pairs]
    model = CalibrationModel.from_outcomes(outcomes)
    if model.applied:
        transformed = [model.transform(float(x)) for x in range(0, 101)]
        assert transformed == sorted(transformed)


# ── model fitting / gating ──────────────────────────────────────────────────


def test_model_identity_below_min_samples() -> None:
    outcomes = [
        {"predicted": 30.0, "observed": 1},
        {"predicted": 30.0, "observed": 1},
    ]
    model = CalibrationModel.from_outcomes(outcomes, min_samples=30)
    assert model.applied is False
    assert model.scope == "identity"
    assert "insufficient" in model.reason
    assert model.transform(30.0) == 30.0


def test_model_identity_for_empty_outcomes() -> None:
    model = CalibrationModel.from_outcomes([])
    assert model.applied is False
    assert model.samples == 0
    assert model.transform(70.0) == 70.0


def test_model_identity_when_already_calibrated() -> None:
    # Half of the 50-confident claims verify, half die: raw is calibrated.
    outcomes = [
        {"predicted": 50.0, "observed": 1 if index % 2 == 0 else 0}
        for index in range(100)
    ]
    model = CalibrationModel.from_outcomes(outcomes)
    assert model.applied is False
    assert model.reason == "no cross-validated improvement"
    assert model.transform(50.0) == 50.0


def test_model_applies_when_engine_is_underconfident() -> None:
    # Claims held at 30 confidence almost always verify; some 70s die.
    outcomes = (
        [{"predicted": 30.0, "observed": 1} for _ in range(80)]
        + [{"predicted": 70.0, "observed": 0} for _ in range(20)]
    )
    model = CalibrationModel.from_outcomes(outcomes)
    assert model.applied is True
    assert model.samples == 100
    assert model.brier_calibrated < model.brier_raw
    assert model.transform(30.0) > 30.0
    assert model.transform(30.0) <= 100.0


def test_transform_is_monotone_and_bounded() -> None:
    outcomes = (
        [{"predicted": 20.0, "observed": 1} for _ in range(60)]
        + [{"predicted": 80.0, "observed": 0} for _ in range(10)]
        + [{"predicted": 90.0, "observed": 1} for _ in range(10)]
    )
    model = CalibrationModel.from_outcomes(outcomes)
    assert model.applied is True
    values = [model.transform(x) for x in range(0, 101, 5)]
    assert values == sorted(values)
    assert all(0.0 <= value <= 100.0 for value in values)


def test_blend_weight_scales_with_sample_count() -> None:
    outcomes_100 = (
        [{"predicted": 30.0, "observed": 1} for _ in range(80)]
        + [{"predicted": 70.0, "observed": 0} for _ in range(20)]
    )
    outcomes_200 = outcomes_100 * 2
    small = CalibrationModel.from_outcomes(outcomes_100)
    large = CalibrationModel.from_outcomes(outcomes_200)
    assert small.applied and large.applied
    assert large.weight > small.weight


def test_to_dict_contains_expected_fields() -> None:
    outcomes = (
        [{"predicted": 30.0, "observed": 1} for _ in range(80)]
        + [{"predicted": 70.0, "observed": 0} for _ in range(20)]
    )
    data = CalibrationModel.from_outcomes(outcomes).to_dict()
    assert data["applied"] is True
    assert data["samples"] == 100
    assert data["scope"] == "global"
    assert isinstance(data["points"], list)


# ── database integration ────────────────────────────────────────────────────


def test_db_model_uses_target_outcomes(tmp_path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    _record_outcomes(
        db, "example.test", confidence=30.0, verified=40, dead=0, prefix="v"
    )
    model = db.calibration_model(target="example.test")
    assert model.samples == 40
    assert model.scope == "target"
    assert model.applied is True
    assert model.transform(30.0) > 30.0
    db.close()


def test_db_model_falls_back_to_global_for_small_targets(tmp_path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    _record_outcomes(
        db, "other.test", confidence=30.0, verified=40, dead=0, prefix="g"
    )
    _record_outcomes(
        db, "example.test", confidence=30.0, verified=2, dead=0, prefix="t"
    )
    model = db.calibration_model(target="example.test")
    assert model.scope == "global"
    assert model.applied is True
    assert model.samples == 42
    db.close()


def test_db_model_identity_without_outcomes(tmp_path) -> None:
    db = StrataDB(tmp_path / "strata.db")
    model = db.calibration_model(target="example.test")
    assert model.applied is False
    assert model.samples == 0
    db.close()


# ── reporting integration ───────────────────────────────────────────────────


def _applied_model() -> CalibrationModel:
    return CalibrationModel(
        scope="target",
        samples=100,
        applied=True,
        reason="cross-validated improvement",
        weight=0.75,
        brier_raw=0.4,
        brier_calibrated=0.2,
        points=((30.0, 0.9), (80.0, 0.95)),
    )


def test_markdown_report_adds_calibrated_column_when_applied() -> None:
    finding = _finding("a.example.test", confidence=40.0)
    text = markdown_report([finding], calibration=_applied_model())
    assert "| Confidence | Calibrated |" in text
    assert "recalibrated from 100 ledger outcomes" in text


def test_markdown_report_unchanged_for_identity_model() -> None:
    finding = _finding("a.example.test", confidence=40.0)
    text = markdown_report([finding], calibration=CalibrationModel())
    assert "Calibrated" not in text
    assert "| Confidence | Status |" in text


# ── orchestrator plan ───────────────────────────────────────────────────────


def test_plan_includes_calibrate_between_fuse_and_tension() -> None:
    orchestrator = Orchestrator(RunOptions(target="example.test"))
    plan = [name for name, _reason in orchestrator._build_plan({})]
    assert plan.index("calibrate") == plan.index("fuse") + 1
    assert plan.index("calibrate") == plan.index("tension") - 1


# ── CLI integration ─────────────────────────────────────────────────────────


def test_calibrate_command_reports_fitted_model(tmp_path, capsys) -> None:
    db_path = tmp_path / "strata.db"
    db = StrataDB(db_path)
    _record_outcomes(
        db, "example.test", confidence=30.0, verified=40, dead=0, prefix="c"
    )
    db.close()

    report = tmp_path / "calibration.md"
    assert (
        main(
            [
                "calibrate",
                "--db",
                str(db_path),
                "--target",
                "example.test",
                "--out",
                str(report),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "Recalibration model" in out
    text = report.read_text(encoding="utf-8")
    assert "## Recalibration model" in text
    assert "applied: yes" in text


def test_report_command_applies_calibration(tmp_path) -> None:
    db_path = tmp_path / "strata.db"
    db = StrataDB(db_path)
    _record_outcomes(
        db, "example.test", confidence=30.0, verified=40, dead=0, prefix="r"
    )
    db.upsert_finding(_finding("hold.example.test", confidence=30.0), target="example.test")
    db.close()

    report = tmp_path / "report.md"
    assert (
        main(
            [
                "report",
                "--db",
                str(db_path),
                "--target",
                "example.test",
                "--out",
                str(report),
            ]
        )
        == 0
    )
    text = report.read_text(encoding="utf-8")
    assert "| Confidence | Calibrated |" in text
