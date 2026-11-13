"""SQLite persistence for Strata findings (P0).

Findings are upserted on the (run_id, kind, asset_value) dedup key; evidence
rows are appended and never updated.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
    scope_ok INTEGER NOT NULL DEFAULT 1,
    discovered_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    legacy TEXT NOT NULL DEFAULT '{}',
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

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_value);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_row ON
    evidence(finding_id, engine, technique, observation, ts);

CREATE TABLE IF NOT EXISTS run_memory (
    target TEXT PRIMARY KEY,
    updated_at TEXT NOT NULL,
    memory TEXT NOT NULL DEFAULT '{}'
);
"""


class StrataDB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

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

    def upsert_finding(self, finding: UnifiedFinding) -> str:
        self.ensure_run(finding.run_id)
        self.conn.execute(
            "INSERT INTO findings(finding_id, run_id, kind, status, asset_value,"
            " parent, confidence, confidence_method, scope_ok, discovered_at,"
            " metadata, legacy)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(run_id, kind, asset_value) DO UPDATE SET"
            " status=excluded.status, confidence=excluded.confidence,"
            " confidence_method=excluded.confidence_method,"
            " metadata=excluded.metadata, legacy=excluded.legacy",
            (
                finding.finding_id,
                finding.run_id,
                finding.kind.value,
                finding.status.value,
                finding.asset_value,
                finding.parent,
                finding.confidence.value,
                finding.confidence.method.value,
                int(finding.scope_ok),
                finding.discovered_at.isoformat(),
                json.dumps(finding.metadata, default=str),
                json.dumps(finding.legacy, default=str),
            ),
        )
        finding_id = self.conn.execute(
            "SELECT finding_id FROM findings WHERE run_id=? AND kind=? AND asset_value=?",
            (finding.run_id, finding.kind.value, finding.asset_value),
        ).fetchone()[0]
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
        self.conn.commit()
        return finding_id

    def stats(self) -> dict[str, int]:
        by_status: dict[str, int] = {}
        for row in self.conn.execute(
            "SELECT status, COUNT(*) FROM findings GROUP BY status"
        ):
            by_status[row[0]] = row[1]
        evidence_count = self.conn.execute(
            "SELECT COUNT(*) FROM evidence"
        ).fetchone()[0]
        return {
            "findings": sum(by_status.values()),
            "evidence": evidence_count,
            **{f"status_{k}": v for k, v in by_status.items()},
        }

    def iter_findings(self):
        """Yield findings with their evidence grouped correctly.

        Rows are grouped by finding_id first and UnifiedFinding is validated
        only after its evidence list is complete: the model forbids
        verified/dead-without-evidence, so constructing mid-stream would
        reject every such row.
        """
        cursor = self.conn.execute(
            "SELECT f.finding_id, f.run_id, f.kind, f.status, f.asset_value,"
            " f.parent, f.confidence, f.confidence_method, f.scope_ok,"
            " f.discovered_at, f.metadata, f.legacy,"
            " e.engine, e.technique, e.observation, e.strength, e.ts, e.meta"
            " FROM findings f LEFT JOIN evidence e ON e.finding_id = f.finding_id"
            " ORDER BY f.finding_id, e.evidence_id"
        )
        groups: dict[str, dict] = {}
        order: list[str] = []
        for row in cursor:
            (
                fid, run_id, kind, status, asset_value, parent, conf, conf_method,
                scope_ok, discovered_at, metadata, legacy,
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
                    value=g["confidence"], method=g["confidence_method"]
                ),
                scope_ok=g["scope_ok"],
                discovered_at=g["discovered_at"],
                metadata=json.loads(g["metadata"]),
                legacy=json.loads(g["legacy"]),
                evidence=g["evidence"],
            )

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
