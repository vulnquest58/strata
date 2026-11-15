"""SQLite persistence for Strata findings (P0).

Findings are upserted on the (run_id, kind, asset_value) dedup key; evidence
rows are appended and never updated. Every finding belongs to a target so
multi-target databases can be read with strict isolation.

Status transitions are also recorded in ``claim_outcomes``: this is the truth
ledger used to calibrate confidence against realized verification results.
A probe that resolves an extraction candidate may be inserted already verified;
when it carries the pre-probe ``prior_confidence`` in metadata, that prediction
is recorded as a candidate-to-verified/dead outcome.
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strata.core.reliability import assess_source_reliability, claim_sources
from strata.core.schema.models import (
    Confidence,
    Evidence,
    FindingClass,
    FindingStatus,
    UnifiedFinding,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    tool TEXT NOT NULL DEFAULT 'strata',
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    asset_value TEXT NOT NULL,
    parent TEXT,
    confidence REAL NOT NULL,
    confidence_method TEXT NOT NULL,
    components TEXT NOT NULL DEFAULT '{}',
    scope_ok INTEGER NOT NULL DEFAULT 1,
    discovered_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    legacy TEXT NOT NULL DEFAULT '{}',
    target TEXT,
    UNIQUE(run_id, kind, asset_value)
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    engine TEXT NOT NULL,
    technique TEXT NOT NULL,
    observation TEXT NOT NULL DEFAULT '',
    strength TEXT NOT NULL,
    ts TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS claim_outcomes (
    outcome_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    target TEXT,
    kind TEXT NOT NULL,
    predicted REAL NOT NULL,
    observed INTEGER NOT NULL CHECK (observed IN (0, 1)),
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    sources TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS technique_stats (
    scope TEXT NOT NULL,
    technique TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    successes INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scope, technique)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_row ON
    evidence(finding_id, engine, technique, observation, ts);

CREATE TABLE IF NOT EXISTS run_memory (
    target TEXT PRIMARY KEY,
    updated_at TEXT NOT NULL,
    memory TEXT NOT NULL DEFAULT '{}'
);
"""

_RESOLVED_STATUSES = frozenset(
    {FindingStatus.CANDIDATE.value, FindingStatus.STALE.value}
)


def _normalise_target(target: str | None) -> str | None:
    if target is None:
        return None
    value = target.strip().lower()
    return value or None


def _decode_json(raw: Any, *, default: Any) -> Any:
    if not isinstance(raw, str) or not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return default


class StrataDB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(findings)")
        }
        if "target" not in columns:
            self.conn.execute("ALTER TABLE findings ADD COLUMN target TEXT")
        if "components" not in columns:
            self.conn.execute(
                "ALTER TABLE findings ADD COLUMN components TEXT NOT NULL DEFAULT '{}'"
            )
        outcome_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(claim_outcomes)")
        }
        if "sources" not in outcome_columns:
            self.conn.execute(
                "ALTER TABLE claim_outcomes ADD COLUMN sources TEXT NOT NULL DEFAULT '[]'"
            )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_value)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_outcomes_target ON claim_outcomes(target)"
        )

    def close(self) -> None:
        self.conn.close()

    def ensure_run(self, run_id: str, notes: str = "") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO runs(run_id, started_at, notes) "
            "VALUES (?, ?, ?)",
            (
                run_id,
                datetime.now(UTC).isoformat(),
                notes,
            ),
        )
        self.conn.commit()

    def _existing(self, finding: UnifiedFinding):
        return self.conn.execute(
            "SELECT finding_id, status, confidence, target FROM findings"
            " WHERE run_id=? AND kind=? AND asset_value=?",
            (finding.run_id, finding.kind.value, finding.asset_value),
        ).fetchone()

    def _record_outcome(
        self,
        *,
        finding_id: str,
        finding: UnifiedFinding,
        target: str | None,
        previous_status: str,
        previous_confidence: float,
    ) -> None:
        new_status = finding.status.value
        if previous_status == new_status:
            return
        if new_status not in (FindingStatus.VERIFIED.value, FindingStatus.DEAD.value):
            return
        if previous_status not in (
            FindingStatus.CANDIDATE.value,
            FindingStatus.STALE.value,
            FindingStatus.VERIFIED.value,
            FindingStatus.DEAD.value,
        ):
            return
        observed = 1 if new_status == FindingStatus.VERIFIED.value else 0
        sources = json.dumps(
            claim_sources(evidence.engine for evidence in finding.evidence)
        )
        self.conn.execute(
            "INSERT INTO claim_outcomes(finding_id, run_id, target, kind,"
            " predicted, observed, previous_status, new_status, observed_at, sources)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding_id,
                finding.run_id,
                target,
                finding.kind.value,
                max(0.0, min(100.0, previous_confidence)),
                observed,
                previous_status,
                new_status,
                datetime.now(UTC).isoformat(),
                sources,
            ),
        )

    def upsert_finding(
        self, finding: UnifiedFinding, *, target: str | None = None
    ) -> str:
        target = _normalise_target(target)
        self.ensure_run(finding.run_id)
        existing = self._existing(finding)
        self.conn.execute(
            "INSERT INTO findings(finding_id, run_id, kind, status, asset_value,"
            " parent, confidence, confidence_method, components, scope_ok,"
            " discovered_at, metadata, legacy, target)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(run_id, kind, asset_value) DO UPDATE SET"
            " status=excluded.status, confidence=excluded.confidence,"
            " confidence_method=excluded.confidence_method,"
            " components=excluded.components,"
            " metadata=excluded.metadata, legacy=excluded.legacy,"
            " target=COALESCE(excluded.target, target)",
            (
                finding.finding_id,
                finding.run_id,
                finding.kind.value,
                finding.status.value,
                finding.asset_value,
                finding.parent,
                finding.confidence.value,
                finding.confidence.method.value,
                json.dumps(finding.confidence.components, default=str),
                int(finding.scope_ok),
                finding.discovered_at.isoformat(),
                json.dumps(finding.metadata, default=str),
                json.dumps(finding.legacy, default=str),
                target,
            ),
        )
        row = self.conn.execute(
            "SELECT finding_id FROM findings WHERE run_id=? AND kind=? AND asset_value=?",
            (finding.run_id, finding.kind.value, finding.asset_value),
        ).fetchone()
        finding_id = row[0]
        for ev in finding.evidence:
            self.conn.execute(
                "INSERT OR IGNORE INTO evidence(finding_id, engine, technique,"
                " observation, strength, ts, meta) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    ev.engine,
                    ev.technique,
                    ev.observation,
                    ev.strength.value,
                    ev.ts.isoformat(),
                    json.dumps(ev.meta, default=str),
                ),
            )
        if existing is not None:
            previous_id, previous_status, previous_confidence, previous_target = existing
            self._record_outcome(
                finding_id=previous_id,
                finding=finding,
                target=target or previous_target,
                previous_status=previous_status,
                previous_confidence=float(previous_confidence),
            )
        elif finding.status in (FindingStatus.VERIFIED, FindingStatus.DEAD):
            prior = finding.metadata.get("prior_confidence")
            if isinstance(prior, (int, float)):
                self._record_outcome(
                    finding_id=finding_id,
                    finding=finding,
                    target=target,
                    previous_status=FindingStatus.CANDIDATE.value,
                    previous_confidence=float(prior),
                )
        self.conn.commit()
        return finding_id

    def delete_findings(self, finding_ids: Iterable[str]) -> int:
        """Delete superseded findings; evidence cascades, outcomes stay as audit."""
        ids = [str(fid) for fid in finding_ids if fid]
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        cursor = self.conn.execute(
            f"DELETE FROM findings WHERE finding_id IN ({placeholders})", ids
        )
        self.conn.commit()
        return cursor.rowcount

    def stats(self, *, target: str | None = None) -> dict[str, int]:
        target = _normalise_target(target)
        where = " WHERE target = ?" if target else ""
        params: tuple[Any, ...] = (target,) if target else ()
        by_status: dict[str, int] = {}
        for row in self.conn.execute(
            f"SELECT status, COUNT(*) FROM findings{where} GROUP BY status", params
        ):
            by_status[row[0]] = row[1]
        by_kind: dict[str, int] = {}
        for row in self.conn.execute(
            f"SELECT kind, COUNT(*) FROM findings{where} GROUP BY kind", params
        ):
            by_kind[row[0]] = row[1]
        if target:
            evidence_count = self.conn.execute(
                "SELECT COUNT(*) FROM evidence e"
                " JOIN findings f ON f.finding_id = e.finding_id"
                " WHERE f.target = ?",
                params,
            ).fetchone()[0]
        else:
            evidence_count = self.conn.execute(
                "SELECT COUNT(*) FROM evidence"
            ).fetchone()[0]
        return {
            "findings": sum(by_status.values()),
            "evidence": evidence_count,
            **{f"status_{k}": v for k, v in by_status.items()},
            **{f"kind_{k}": v for k, v in by_kind.items()},
        }

    def targets(self) -> dict[str, int]:
        """Targets present in the store with their finding counts."""
        rows = self.conn.execute(
            "SELECT target, COUNT(*) FROM findings"
            " WHERE target IS NOT NULL GROUP BY target ORDER BY target"
        )
        return {row[0]: row[1] for row in rows}

    def iter_findings(self, *, target: str | None = None):
        """Yield findings with their evidence grouped correctly.

        Rows are grouped by finding_id first and UnifiedFinding is validated
        only after its evidence list is complete: the model forbids
        verified/dead-without-evidence, so constructing mid-stream would
        reject every such row.
        """
        target = _normalise_target(target)
        where = " WHERE f.target = ?" if target else ""
        params: tuple[Any, ...] = (target,) if target else ()
        cursor = self.conn.execute(
            "SELECT f.finding_id, f.run_id, f.kind, f.status, f.asset_value,"
            " f.parent, f.confidence, f.confidence_method, f.components,"
            " f.scope_ok, f.discovered_at, f.metadata, f.legacy,"
            " e.engine, e.technique, e.observation, e.strength, e.ts, e.meta"
            " FROM findings f LEFT JOIN evidence e ON e.finding_id = f.finding_id"
            f"{where}"
            " ORDER BY f.finding_id, e.evidence_id",
            params,
        )
        groups: dict[str, dict] = {}
        order: list[str] = []
        for row in cursor:
            (
                fid, run_id, kind, status, asset_value, parent, conf, conf_method,
                components, scope_ok, discovered_at, metadata, legacy,
                ev_engine, ev_technique, ev_obs, ev_strength, ev_ts, ev_meta,
            ) = row
            if fid not in groups:
                groups[fid] = {
                    "finding_id": fid,
                    "run_id": run_id,
                    "kind": kind,
                    "status": status,
                    "asset_value": asset_value,
                    "parent": parent,
                    "confidence": conf,
                    "confidence_method": conf_method,
                    "components": components,
                    "scope_ok": bool(scope_ok),
                    "discovered_at": discovered_at,
                    "metadata": metadata,
                    "legacy": legacy,
                    "evidence": [],
                }
                order.append(fid)
            if ev_engine is not None:
                groups[fid]["evidence"].append(
                    Evidence(
                        engine=ev_engine,
                        technique=ev_technique,
                        observation=ev_obs,
                        strength=ev_strength,
                        ts=ev_ts,
                        meta=json.loads(ev_meta),
                    )
                )
        for fid in order:
            g = groups[fid]
            yield UnifiedFinding(
                finding_id=g["finding_id"],
                run_id=g["run_id"],
                kind=FindingClass(g["kind"]),
                status=FindingStatus(g["status"]),
                asset_value=g["asset_value"],
                parent=g["parent"],
                confidence=Confidence(
                    value=g["confidence"],
                    method=g["confidence_method"],
                    components=json.loads(g["components"] or "{}"),
                ),
                scope_ok=g["scope_ok"],
                discovered_at=g["discovered_at"],
                metadata=json.loads(g["metadata"]),
                legacy=json.loads(g["legacy"]),
                evidence=g["evidence"],
            )

    def iter_outcomes(self, *, target: str | None = None) -> list[dict[str, Any]]:
        target = _normalise_target(target)
        where = " WHERE target = ?" if target else ""
        params: tuple[Any, ...] = (target,) if target else ()
        rows = self.conn.execute(
            "SELECT finding_id, run_id, target, kind, predicted, observed,"
            " previous_status, new_status, observed_at, sources FROM claim_outcomes"
            f"{where} ORDER BY outcome_id",
            params,
        )
        return [
            {
                "finding_id": row[0],
                "run_id": row[1],
                "target": row[2],
                "kind": row[3],
                "predicted": row[4],
                "observed": row[5],
                "previous_status": row[6],
                "new_status": row[7],
                "observed_at": row[8],
                "sources": _decode_json(row[9], default=[]),
            }
            for row in rows
        ]

    def calibration(self, *, target: str | None = None) -> dict[str, Any]:
        """Brier score, log loss, and reliability bands from the truth ledger."""
        outcomes = self.iter_outcomes(target=target)
        if not outcomes:
            return {
                "outcomes": 0,
                "verified": 0,
                "dead": 0,
                "brier": None,
                "log_loss": None,
                "accuracy": None,
                "bands": [],
            }

        epsilon = 0.001
        probabilities: list[float] = []
        observations: list[int] = []
        bands = {
            "0-19": [],
            "20-39": [],
            "40-59": [],
            "60-79": [],
            "80-100": [],
        }
        for outcome in outcomes:
            predicted = max(0.0, min(100.0, float(outcome["predicted"])))
            probability = predicted / 100.0
            observed = int(outcome["observed"])
            probabilities.append(probability)
            observations.append(observed)
            if predicted < 20:
                bands["0-19"].append((probability, observed))
            elif predicted < 40:
                bands["20-39"].append((probability, observed))
            elif predicted < 60:
                bands["40-59"].append((probability, observed))
            elif predicted < 80:
                bands["60-79"].append((probability, observed))
            else:
                bands["80-100"].append((probability, observed))

        count = len(probabilities)
        brier = sum(
            (probability - observed) ** 2
            for probability, observed in zip(probabilities, observations, strict=True)
        ) / count
        log_loss = -sum(
            observed * math.log(max(probability, epsilon))
            + (1 - observed) * math.log(max(1 - probability, epsilon))
            for probability, observed in zip(probabilities, observations, strict=True)
        ) / count
        accuracy = sum(
            (probability >= 0.5) == bool(observed)
            for probability, observed in zip(probabilities, observations, strict=True)
        ) / count

        band_rows = []
        for label, entries in bands.items():
            if not entries:
                band_rows.append(
                    {
                        "band": label,
                        "count": 0,
                        "mean_predicted": None,
                        "observed_rate": None,
                    }
                )
                continue
            band_rows.append(
                {
                    "band": label,
                    "count": len(entries),
                    "mean_predicted": round(
                        sum(probability for probability, _ in entries)
                        / len(entries)
                        * 100,
                        1,
                    ),
                    "observed_rate": round(
                        sum(observed for _, observed in entries) / len(entries) * 100,
                        1,
                    ),
                }
            )

        return {
            "outcomes": count,
            "verified": sum(observations),
            "dead": count - sum(observations),
            "brier": round(brier, 4),
            "log_loss": round(log_loss, 4),
            "accuracy": round(accuracy, 4),
            "bands": band_rows,
        }

    def source_reliability(self, *, target: str | None = None) -> dict[str, Any]:
        """Measured verify rate per discovery source, plus poisoning flags."""
        outcomes = self.iter_outcomes(target=target)
        return assess_source_reliability(outcomes)

    def record_technique_stats(
        self, scope: str, entries: dict[str, tuple[int, int]]
    ) -> int:
        """Accumulate attempts/successes per technique (e.g. DNS words).

        ``entries`` maps a technique key to an ``(attempts, successes)`` pair
        observed in one run; counts accumulate across runs.
        """
        if not entries:
            return 0
        now = datetime.now(UTC).isoformat()
        updated = 0
        for technique, (attempts, successes) in entries.items():
            if attempts <= 0 and successes <= 0:
                continue
            self.conn.execute(
                "INSERT INTO technique_stats(scope, technique, attempts,"
                " successes, updated_at) VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(scope, technique) DO UPDATE SET"
                " attempts = attempts + excluded.attempts,"
                " successes = successes + excluded.successes,"
                " updated_at = excluded.updated_at",
                (scope, technique, max(0, attempts), max(0, successes), now),
            )
            updated += 1
        self.conn.commit()
        return updated

    def technique_stats(self, scope: str) -> dict[str, dict[str, float]]:
        """Historical attempts/successes/success-rate per technique key."""
        rows = self.conn.execute(
            "SELECT technique, attempts, successes FROM technique_stats"
            " WHERE scope = ? ORDER BY technique",
            (scope,),
        )
        return {
            row[0]: {
                "attempts": row[1],
                "successes": row[2],
                "rate": (row[2] / row[1]) if row[1] else 0.0,
            }
            for row in rows
        }

    def get_run_memory(self, target: str) -> dict[str, Any]:
        """Return the persisted orchestrator memory for one target."""
        row = self.conn.execute(
            "SELECT memory FROM run_memory WHERE target = ?", (target,)
        ).fetchone()
        if row is None:
            return {}
        try:
            data = json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def save_run_memory(self, target: str, memory: dict[str, Any]) -> None:
        """Persist orchestrator learning for one target."""
        self.conn.execute(
            "INSERT INTO run_memory(target, updated_at, memory) VALUES (?, ?, ?)"
            " ON CONFLICT(target) DO UPDATE SET updated_at = excluded.updated_at,"
            " memory = excluded.memory",
            (
                target,
                datetime.now(UTC).isoformat(),
                json.dumps(memory, default=str, sort_keys=True),
            ),
        )
        self.conn.commit()
