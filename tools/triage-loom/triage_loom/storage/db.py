"""
DuckDB storage backend for Triage Loom.

DuckDB is chosen over SQLite here because Triage Loom performs OLAP-style
analytical queries: aggregations over tens of thousands of archived URLs,
GROUP BY pattern queries, windowed ranking functions.
DuckDB handles these 10–100× faster than SQLite on columnar data.

The database is embedded (no server) and stored as a single .duckdb file.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import duckdb

from triage_loom.models import ApertureFinding, TriagedFinding


_SCHEMA = """
-- Raw Aperture findings loaded from JSONL
CREATE TABLE IF NOT EXISTS aperture_findings (
    id                  VARCHAR PRIMARY KEY,
    scan_id             VARCHAR NOT NULL,
    asset_id            VARCHAR NOT NULL,
    asset_type          VARCHAR NOT NULL,
    parent_asset        VARCHAR NOT NULL,
    source_plugin       VARCHAR NOT NULL,
    raw_confidence      DOUBLE  DEFAULT 0,
    adjusted_confidence DOUBLE  DEFAULT 0,
    consensus_count     INTEGER DEFAULT 1,
    temporal_stability  DOUBLE  DEFAULT 0,
    resolved_ips        JSON    DEFAULT '[]',
    metadata            JSON    DEFAULT '{}',
    tags                JSON    DEFAULT '[]',
    discovered_at       TIMESTAMPTZ NOT NULL
);

-- Triaged and ranked findings (final output)
CREATE TABLE IF NOT EXISTS triaged_findings (
    aperture_finding_id     VARCHAR NOT NULL,
    asset_id                VARCHAR NOT NULL,
    root_domain             VARCHAR NOT NULL,
    endpoint_pattern        VARCHAR NOT NULL,
    representative_url      VARCHAR NOT NULL,
    cluster_size            INTEGER DEFAULT 1,
    corroboration_layers    JSON DEFAULT '[]',
    archive_sources_failed  JSON DEFAULT '[]',
    parameters              JSON DEFAULT '[]',
    infra_context           JSON DEFAULT '{}',
    first_seen              TIMESTAMPTZ,
    last_confirmed_live     TIMESTAMPTZ,
    novelty_json            JSON,
    investigation_priority  DOUBLE DEFAULT 0,
    is_high_confidence      BOOLEAN DEFAULT FALSE,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (asset_id, endpoint_pattern)
);

-- Archived URLs from Filter 2 (Wayback / CommonCrawl / URLScan)
CREATE TABLE IF NOT EXISTS archive_urls (
    url             VARCHAR NOT NULL,
    root_domain     VARCHAR NOT NULL,
    source          VARCHAR NOT NULL,   -- 'wayback' | 'commoncrawl' | 'urlscan'
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    status_code     INTEGER,
    mime_type       VARCHAR,
    PRIMARY KEY (url, source)
);

-- Discovered parameters from Filter 3
CREATE TABLE IF NOT EXISTS endpoint_params (
    endpoint_pattern VARCHAR NOT NULL,
    param_name       VARCHAR NOT NULL,
    technique        VARCHAR NOT NULL,  -- 'archive_static' | 'js_static' | 'openapi'
    example_value    VARCHAR,
    PRIMARY KEY (endpoint_pattern, param_name, technique)
);
"""


class DB:
    """Thin wrapper around a DuckDB connection for Triage Loom."""

    def __init__(self, path: str | Path = "triage_loom.duckdb") -> None:
        self._path = str(path)
        self._conn = duckdb.connect(self._path)
        self._conn.execute(_SCHEMA)
        try:
            self._conn.execute("ALTER TABLE triaged_findings ADD COLUMN archive_sources_failed JSON DEFAULT '[]'")
        except Exception:
            pass

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "DB":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Aperture findings
    # ------------------------------------------------------------------

    def upsert_finding(self, f: ApertureFinding) -> None:
        """Insert or replace an Aperture finding."""
        import json as _json
        self._conn.execute(
            """
            INSERT OR REPLACE INTO aperture_findings
                (id, scan_id, asset_id, asset_type, parent_asset, source_plugin,
                 raw_confidence, adjusted_confidence, consensus_count, temporal_stability,
                 resolved_ips, metadata, tags, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                f.id, f.scan_id, f.asset_id, f.asset_type.value, f.parent_asset,
                f.source_plugin, f.raw_confidence, f.adjusted_confidence,
                f.consensus_count, f.temporal_stability,
                _json.dumps(f.resolved_ips),
                _json.dumps(f.metadata),
                _json.dumps(f.tags),
                f.discovered_at.isoformat(),
            ],
        )

    def count_findings(self, root_domain: str | None = None) -> int:
        if root_domain:
            return self._conn.execute(
                "SELECT COUNT(*) FROM aperture_findings WHERE parent_asset = ?", [root_domain]
            ).fetchone()[0]
        return self._conn.execute("SELECT COUNT(*) FROM aperture_findings").fetchone()[0]

    def get_findings_for_domain(self, root_domain: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM aperture_findings WHERE parent_asset = ? ORDER BY adjusted_confidence DESC",
            [root_domain],
        ).fetchdf()
        return rows.to_dict("records")

    # ------------------------------------------------------------------
    # Archive URLs
    # ------------------------------------------------------------------

    def upsert_archive_url(
        self,
        url: str,
        root_domain: str,
        source: str,
        first_seen: datetime | None,
        last_seen: datetime | None,
        status_code: int | None = None,
        mime_type: str | None = None,
    ) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO archive_urls
                (url, root_domain, source, first_seen, last_seen, status_code, mime_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                url, root_domain, source,
                first_seen.isoformat() if first_seen else None,
                last_seen.isoformat() if last_seen else None,
                status_code, mime_type,
            ],
        )

    def get_archive_urls_by_domain(self, root_domain: str) -> dict[str, list[str]]:
        """
        Returns {url: [source1, source2, ...]} grouped by URL.
        Used by Filter 2 to compute corroboration counts.
        """
        rows = self._conn.execute(
            "SELECT url, source FROM archive_urls WHERE root_domain = ?",
            [root_domain],
        ).fetchall()
        result: dict[str, list[str]] = {}
        for url, source in rows:
            result.setdefault(url, []).append(source)
        return result

    # ------------------------------------------------------------------
    # Triaged findings
    # ------------------------------------------------------------------

    def upsert_triaged(self, f: TriagedFinding) -> None:
        import json as _json
        self._conn.execute(
            """
            INSERT OR REPLACE INTO triaged_findings
                (aperture_finding_id, asset_id, root_domain, endpoint_pattern,
                 representative_url, cluster_size, corroboration_layers, archive_sources_failed,
                 parameters, infra_context, first_seen, last_confirmed_live, novelty_json,
                 investigation_priority, is_high_confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                f.aperture_finding_id, f.asset_id, f.root_domain,
                f.endpoint_pattern, f.representative_url, f.cluster_size,
                _json.dumps([l.value for l in f.corroboration_layers]),
                _json.dumps(f.archive_sources_failed),
                _json.dumps(f.parameters),
                _json.dumps(f.infra_context),
                f.first_seen.isoformat() if f.first_seen else None,
                f.last_confirmed_live.isoformat() if f.last_confirmed_live else None,
                f.novelty.model_dump_json() if f.novelty else None,
                f.investigation_priority,
                f.is_high_confidence,
            ],
        )

    def get_triaged_high_confidence(self, root_domain: str = "") -> list[dict]:
        if not root_domain:
            return self._conn.execute(
                """SELECT * FROM triaged_findings
                   WHERE is_high_confidence = TRUE
                   ORDER BY investigation_priority DESC"""
            ).fetchdf().to_dict("records")
        return self._conn.execute(
            """SELECT * FROM triaged_findings
               WHERE root_domain = ? AND is_high_confidence = TRUE
               ORDER BY investigation_priority DESC""",
            [root_domain],
        ).fetchdf().to_dict("records")

    def get_triaged_low_confidence(self, root_domain: str = "") -> list[dict]:
        if not root_domain:
            return self._conn.execute(
                """SELECT * FROM triaged_findings
                   WHERE is_high_confidence = FALSE
                   ORDER BY investigation_priority DESC"""
            ).fetchdf().to_dict("records")
        return self._conn.execute(
            """SELECT * FROM triaged_findings
               WHERE root_domain = ? AND is_high_confidence = FALSE
               ORDER BY investigation_priority DESC""",
            [root_domain],
        ).fetchdf().to_dict("records")
