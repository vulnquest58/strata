package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// schema contains all CREATE TABLE and CREATE INDEX statements for Aperture's SQLite schema.
// Applied in order via simple string execution — no ORM migrations needed.

const schema = `
-- findings: one row per (scan_id, asset_id, source_plugin) triple.
CREATE TABLE IF NOT EXISTS findings (
    id                   TEXT    PRIMARY KEY,
    scan_id              TEXT    NOT NULL,
    asset_id             TEXT    NOT NULL,
    asset_type           TEXT    NOT NULL,
    parent_asset         TEXT    NOT NULL,
    source_plugin        TEXT    NOT NULL,
    raw_confidence       REAL,
    adjusted_confidence  REAL    NOT NULL DEFAULT 0,
    consensus_count      INTEGER NOT NULL DEFAULT 1,
    temporal_stability   REAL    NOT NULL DEFAULT 0,
    resolved_ips         TEXT    NOT NULL DEFAULT '[]',   -- JSON array
    metadata             TEXT    NOT NULL DEFAULT '{}',   -- JSON object
    tags                 TEXT    NOT NULL DEFAULT '[]',   -- JSON array
    discovered_at        TEXT    NOT NULL,
    verified             INTEGER NOT NULL DEFAULT 0,      -- 0=unverified, 1=live, 2=dead
    verified_at          TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_asset_source
    ON findings(scan_id, asset_id, source_plugin);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id  ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_source    ON findings(source_plugin);
CREATE INDEX IF NOT EXISTS idx_findings_verified  ON findings(verified);

-- source_reliability: one row per (source_plugin, target_domain_pattern) pair.
CREATE TABLE IF NOT EXISTS source_reliability (
    source_plugin         TEXT NOT NULL,
    target_domain_pattern TEXT NOT NULL,
    total_findings        INTEGER NOT NULL DEFAULT 0,
    confirmed_live        INTEGER NOT NULL DEFAULT 0,
    confirmed_dead        INTEGER NOT NULL DEFAULT 0,
    reliability_score     REAL    NOT NULL DEFAULT 0.667, -- prior mean = α/(α+β) = 2/3
    sample_size           INTEGER NOT NULL DEFAULT 0,
    last_updated          TEXT    NOT NULL,

    PRIMARY KEY (source_plugin, target_domain_pattern)
);

-- asset_fingerprints: structural and network fingerprint per asset.
CREATE TABLE IF NOT EXISTS asset_fingerprints (
    asset_id      TEXT PRIMARY KEY,
    root_domain   TEXT NOT NULL,
    resolved_ips  TEXT NOT NULL DEFAULT '[]', -- JSON array
    ip_ranges_24  TEXT NOT NULL DEFAULT '[]', -- JSON array
    asn_set       TEXT NOT NULL DEFAULT '[]', -- JSON array
    cdn_providers TEXT NOT NULL DEFAULT '[]', -- JSON array
    cert_issuers  TEXT NOT NULL DEFAULT '[]', -- JSON array
    san_list      TEXT NOT NULL DEFAULT '[]', -- JSON array
    extracted_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fingerprints_root_domain ON asset_fingerprints(root_domain);

-- cross_target_correlations: relationships discovered across distinct root domains.
CREATE TABLE IF NOT EXISTS cross_target_correlations (
    id               TEXT PRIMARY KEY,
    root_domain_a    TEXT NOT NULL,
    root_domain_b    TEXT NOT NULL,
    asset_a          TEXT NOT NULL,
    asset_b          TEXT NOT NULL,
    correlation_type TEXT NOT NULL,
    shared_element   TEXT NOT NULL,
    confidence       REAL NOT NULL,
    evidence         TEXT NOT NULL DEFAULT '{}', -- JSON object
    discovered_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_correlations_domains ON cross_target_correlations(root_domain_a, root_domain_b);
CREATE INDEX IF NOT EXISTS idx_correlations_type ON cross_target_correlations(correlation_type);
`

const graphSchema = `
-- graph_nodes: nodes representing domains, assets, IPs, ASNs, certificates
CREATE TABLE IF NOT EXISTS graph_nodes (
    id         TEXT PRIMARY KEY,
    node_type  TEXT NOT NULL, -- domain | asset | ip | asn | certificate
    label      TEXT NOT NULL,
    metadata   TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

-- graph_edges: relationships connecting attack surface nodes
CREATE TABLE IF NOT EXISTS graph_edges (
    id            TEXT PRIMARY KEY,
    source_id     TEXT NOT NULL REFERENCES graph_nodes(id),
    target_id     TEXT NOT NULL REFERENCES graph_nodes(id),
    edge_type     TEXT NOT NULL, -- RESOLVES_TO | SHARES_SUBNET | SHARES_ASN | ISSUED_WITH | HOSTED_ON | SUBDOMAIN_OF
    confidence    REAL NOT NULL,
    metadata      TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id);
`

// ApplyMigrations runs initial schema and incremental migrations.
func ApplyMigrations(ctx context.Context, db *sql.DB) error {
	// 1. Base schema
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("applying base schema: %w", err)
	}

	// 2. Migration: Add asn and as_org columns to asset_fingerprints if they don't exist
	if err := migrateFingerprintASNColumns(ctx, db); err != nil {
		return fmt.Errorf("migrating asset_fingerprints asn columns: %w", err)
	}

	// 3. Graph schema
	if _, err := db.ExecContext(ctx, graphSchema); err != nil {
		return fmt.Errorf("applying graph schema: %w", err)
	}

	// 4. Migration: Add metadata column to graph_edges if it doesn't exist
	if err := migrateGraphEdgesMetadataColumn(ctx, db); err != nil {
		return fmt.Errorf("migrating graph_edges metadata column: %w", err)
	}

	return nil
}

func migrateFingerprintASNColumns(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(asset_fingerprints)")
	if err != nil {
		return err
	}
	defer rows.Close()

	hasASN := false
	hasASOrg := false

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err == nil {
			if strings.EqualFold(name, "asn") {
				hasASN = true
			}
			if strings.EqualFold(name, "as_org") {
				hasASOrg = true
			}
		}
	}

	if !hasASN {
		if _, err := db.ExecContext(ctx, "ALTER TABLE asset_fingerprints ADD COLUMN asn INTEGER DEFAULT 0"); err != nil {
			return err
		}
	}
	if !hasASOrg {
		if _, err := db.ExecContext(ctx, "ALTER TABLE asset_fingerprints ADD COLUMN as_org TEXT DEFAULT ''"); err != nil {
			return err
		}
	}

	return nil
}

func migrateGraphEdgesMetadataColumn(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(graph_edges)")
	if err != nil {
		return err
	}
	defer rows.Close()

	hasMetadata := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err == nil {
			if strings.EqualFold(name, "metadata") {
				hasMetadata = true
			}
		}
	}

	if !hasMetadata {
		if _, err := db.ExecContext(ctx, "ALTER TABLE graph_edges ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'"); err != nil {
			return err
		}
	}

	return nil
}
