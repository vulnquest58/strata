package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"aperture/internal/model"

	_ "modernc.org/sqlite" // register "sqlite" driver (pure-Go, no CGO)
)

// SQLiteStore is the SQLite-backed implementation of Store.
type SQLiteStore struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and applies the schema.
func Open(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db at %q: %w", path, err)
	}

	db.SetMaxOpenConns(1) // SQLite WAL allows concurrent readers but only one writer.

	if err := ApplyMigrations(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying migrations: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// -------------------------------------------------------------------
// Findings
// -------------------------------------------------------------------

const upsertFindingSQL = `
INSERT INTO findings (
    id, scan_id, asset_id, asset_type, parent_asset, source_plugin,
    raw_confidence, adjusted_confidence, consensus_count, temporal_stability,
    resolved_ips, metadata, tags, discovered_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(scan_id, asset_id, source_plugin) DO UPDATE SET
    raw_confidence      = excluded.raw_confidence,
    adjusted_confidence = excluded.adjusted_confidence,
    temporal_stability  = excluded.temporal_stability,
    resolved_ips        = excluded.resolved_ips,
    metadata            = excluded.metadata,
    tags                = excluded.tags
`

func (s *SQLiteStore) UpsertFinding(ctx context.Context, f *model.Finding) error {
	ips, _ := json.Marshal(f.ResolvedIPs)
	meta, _ := json.Marshal(f.Metadata)
	tags, _ := json.Marshal(f.Tags)

	_, err := s.db.ExecContext(ctx, upsertFindingSQL,
		f.ID, f.ScanID, f.AssetID, string(f.AssetType), f.ParentAsset, f.SourcePlugin,
		f.RawConfidence, f.AdjustedConfidence, f.ConsensusCount, f.TemporalStability,
		string(ips), string(meta), string(tags), f.DiscoveredAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("upsert finding %q: %w", f.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetFindingsByScanID(ctx context.Context, scanID string) ([]*model.Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,scan_id,asset_id,asset_type,parent_asset,source_plugin,
		        raw_confidence,adjusted_confidence,consensus_count,temporal_stability,
		        resolved_ips,metadata,tags,discovered_at
		 FROM findings WHERE scan_id=?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (s *SQLiteStore) IncrementConsensusCount(ctx context.Context, scanID, assetID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET consensus_count = consensus_count + 1
		 WHERE scan_id=? AND asset_id=?`, scanID, assetID)
	return err
}

func (s *SQLiteStore) MarkFindingVerified(ctx context.Context, findingID string, live bool) error {
	verdict := 2 // dead
	if live {
		verdict = 1
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET verified=?, verified_at=? WHERE id=?`,
		verdict, time.Now().UTC().Format(time.RFC3339), findingID)
	return err
}

func (s *SQLiteStore) SampleUnverifiedFindings(ctx context.Context, source string, sampleRate float64, olderThan time.Duration) ([]*model.Finding, error) {
	if sampleRate <= 0 || sampleRate > 1 {
		return nil, fmt.Errorf("sample_rate must be in (0, 1], got %f", sampleRate)
	}

	where := "verified=0"
	var args []any
	if source != "" {
		where += " AND source_plugin=?"
		args = append(args, source)
	}
	if olderThan > 0 {
		cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339)
		where += " AND discovered_at <= ?"
		args = append(args, cutoff)
	}

	// Count total unverified matching criteria.
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM findings WHERE %s", where)
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}
	limit := int(math.Ceil(float64(total) * sampleRate))
	if limit == 0 {
		return nil, nil
	}

	query := fmt.Sprintf(`SELECT id,scan_id,asset_id,asset_type,parent_asset,source_plugin,
		        raw_confidence,adjusted_confidence,consensus_count,temporal_stability,
		        resolved_ips,metadata,tags,discovered_at
		 FROM findings WHERE %s
		 ORDER BY RANDOM() LIMIT ?`, where)
	argsWithLimit := append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, argsWithLimit...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// -------------------------------------------------------------------
// Source Reliability
// -------------------------------------------------------------------

func (s *SQLiteStore) GetReliability(ctx context.Context, source, domainPattern string) (*model.SourceReliabilityRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT source_plugin,target_domain_pattern,total_findings,confirmed_live,
		        confirmed_dead,reliability_score,sample_size,last_updated
		 FROM source_reliability WHERE source_plugin=? AND target_domain_pattern=?`,
		source, domainPattern)

	r := &model.SourceReliabilityRecord{}
	var lastUpdated string
	err := row.Scan(&r.SourcePlugin, &r.TargetDomainPattern, &r.TotalFindings,
		&r.ConfirmedLive, &r.ConfirmedDead, &r.ReliabilityScore, &r.SampleSize, &lastUpdated)
	if err == sql.ErrNoRows {
		// Return a fresh record initialised with the Bayesian prior.
		return &model.SourceReliabilityRecord{
			SourcePlugin:        source,
			TargetDomainPattern: domainPattern,
			ReliabilityScore:    model.ComputeReliabilityScore(0, 0),
			LastUpdated:         time.Now().UTC(),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	r.LastUpdated, _ = time.Parse(time.RFC3339, lastUpdated)
	return r, nil
}

func (s *SQLiteStore) SaveReliability(ctx context.Context, r *model.SourceReliabilityRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO source_reliability
		        (source_plugin,target_domain_pattern,total_findings,confirmed_live,
		         confirmed_dead,reliability_score,sample_size,last_updated)
		 VALUES (?,?,?,?,?,?,?,?)
		 ON CONFLICT(source_plugin,target_domain_pattern) DO UPDATE SET
		        total_findings   = excluded.total_findings,
		        confirmed_live   = excluded.confirmed_live,
		        confirmed_dead   = excluded.confirmed_dead,
		        reliability_score= excluded.reliability_score,
		        sample_size      = excluded.sample_size,
		        last_updated     = excluded.last_updated`,
		r.SourcePlugin, r.TargetDomainPattern, r.TotalFindings, r.ConfirmedLive,
		r.ConfirmedDead, r.ReliabilityScore, r.SampleSize, r.LastUpdated.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) ListReliability(ctx context.Context, source string) ([]*model.SourceReliabilityRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT source_plugin,target_domain_pattern,total_findings,confirmed_live,
		        confirmed_dead,reliability_score,sample_size,last_updated
		 FROM source_reliability WHERE source_plugin=?
		 ORDER BY reliability_score DESC`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*model.SourceReliabilityRecord
	for rows.Next() {
		r := &model.SourceReliabilityRecord{}
		var lastUpdated string
		if err := rows.Scan(&r.SourcePlugin, &r.TargetDomainPattern, &r.TotalFindings,
			&r.ConfirmedLive, &r.ConfirmedDead, &r.ReliabilityScore, &r.SampleSize, &lastUpdated); err != nil {
			return nil, err
		}
		r.LastUpdated, _ = time.Parse(time.RFC3339, lastUpdated)
		records = append(records, r)
	}
	return records, rows.Err()
}

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

func scanFindings(rows *sql.Rows) ([]*model.Finding, error) {
	var findings []*model.Finding
	for rows.Next() {
		f := &model.Finding{}
		var ips, meta, tags, discoveredAt string
		err := rows.Scan(
			&f.ID, &f.ScanID, &f.AssetID, (*string)(&f.AssetType), &f.ParentAsset,
			&f.SourcePlugin, &f.RawConfidence, &f.AdjustedConfidence, &f.ConsensusCount,
			&f.TemporalStability, &ips, &meta, &tags, &discoveredAt,
		)
		if err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(ips), &f.ResolvedIPs)
		json.Unmarshal([]byte(meta), &f.Metadata)
		json.Unmarshal([]byte(tags), &f.Tags)
		f.DiscoveredAt, _ = time.Parse(time.RFC3339, discoveredAt)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// -------------------------------------------------------------------
// Infrastructure Fingerprints
// -------------------------------------------------------------------

const upsertFingerprintSQL = `
INSERT INTO asset_fingerprints (
    asset_id, root_domain, resolved_ips, ip_ranges_24, asn_set, asn, as_org,
    cdn_providers, cert_issuers, san_list, extracted_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(asset_id) DO UPDATE SET
    root_domain   = excluded.root_domain,
    resolved_ips  = excluded.resolved_ips,
    ip_ranges_24  = excluded.ip_ranges_24,
    asn_set       = excluded.asn_set,
    asn           = excluded.asn,
    as_org        = excluded.as_org,
    cdn_providers = excluded.cdn_providers,
    cert_issuers  = excluded.cert_issuers,
    san_list      = excluded.san_list,
    extracted_at  = excluded.extracted_at
`

func (s *SQLiteStore) SaveFingerprint(ctx context.Context, fp *model.InfrastructureFingerprint) error {
	ips, _ := json.Marshal(fp.ResolvedIPs)
	subnets, _ := json.Marshal(fp.IPRanges24)
	asns, _ := json.Marshal(fp.ASNSet)
	cdns, _ := json.Marshal(fp.CDNProviders)
	issuers, _ := json.Marshal(fp.CertIssuers)
	sans, _ := json.Marshal(fp.SANList)

	_, err := s.db.ExecContext(ctx, upsertFingerprintSQL,
		fp.AssetID, fp.RootDomain, string(ips), string(subnets), string(asns),
		fp.ASN, fp.ASOrg,
		string(cdns), string(issuers), string(sans), fp.ExtractedAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) GetFingerprints(ctx context.Context, rootDomain string) ([]*model.InfrastructureFingerprint, error) {
	query := `SELECT asset_id, root_domain, resolved_ips, ip_ranges_24, asn_set, asn, as_org, cdn_providers, cert_issuers, san_list, extracted_at FROM asset_fingerprints`
	var args []any
	if rootDomain != "" {
		query += ` WHERE root_domain = ?`
		args = append(args, rootDomain)
	}
	query += ` ORDER BY asset_id ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fps []*model.InfrastructureFingerprint
	for rows.Next() {
		fp := &model.InfrastructureFingerprint{}
		var ips, subnets, asns, cdns, issuers, sans, extractedAt string
		var asn sql.NullInt64
		var asOrg sql.NullString
		if err := rows.Scan(
			&fp.AssetID, &fp.RootDomain, &ips, &subnets, &asns,
			&asn, &asOrg,
			&cdns, &issuers, &sans, &extractedAt,
		); err != nil {
			return nil, err
		}
		if asn.Valid {
			fp.ASN = int(asn.Int64)
		}
		if asOrg.Valid {
			fp.ASOrg = asOrg.String
		}
		json.Unmarshal([]byte(ips), &fp.ResolvedIPs)
		json.Unmarshal([]byte(subnets), &fp.IPRanges24)
		json.Unmarshal([]byte(asns), &fp.ASNSet)
		json.Unmarshal([]byte(cdns), &fp.CDNProviders)
		json.Unmarshal([]byte(issuers), &fp.CertIssuers)
		json.Unmarshal([]byte(sans), &fp.SANList)
		fp.ExtractedAt, _ = time.Parse(time.RFC3339, extractedAt)
		fps = append(fps, fp)
	}
	return fps, rows.Err()
}

// -------------------------------------------------------------------
// Cross-Target Correlations
// -------------------------------------------------------------------

const upsertCorrelationSQL = `
INSERT INTO cross_target_correlations (
    id, root_domain_a, root_domain_b, asset_a, asset_b,
    correlation_type, shared_element, confidence, evidence, discovered_at
) VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
    confidence   = excluded.confidence,
    evidence     = excluded.evidence,
    discovered_at= excluded.discovered_at
`

func (s *SQLiteStore) SaveCorrelation(ctx context.Context, c *model.CrossTargetCorrelation) error {
	ev, _ := json.Marshal(c.Evidence)
	_, err := s.db.ExecContext(ctx, upsertCorrelationSQL,
		c.ID, c.RootDomainA, c.RootDomainB, c.AssetA, c.AssetB,
		c.CorrelationType, c.SharedElement, c.Confidence, string(ev),
		c.DiscoveredAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) ListCorrelations(ctx context.Context, rootDomain string) ([]*model.CrossTargetCorrelation, error) {
	query := `SELECT id, root_domain_a, root_domain_b, asset_a, asset_b, correlation_type, shared_element, confidence, evidence, discovered_at FROM cross_target_correlations`
	var args []any
	if rootDomain != "" {
		query += ` WHERE root_domain_a = ? OR root_domain_b = ?`
		args = append(args, rootDomain, rootDomain)
	}
	query += ` ORDER BY confidence DESC, discovered_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var correlations []*model.CrossTargetCorrelation
	for rows.Next() {
		c := &model.CrossTargetCorrelation{}
		var ev, discoveredAt string
		if err := rows.Scan(
			&c.ID, &c.RootDomainA, &c.RootDomainB, &c.AssetA, &c.AssetB,
			&c.CorrelationType, &c.SharedElement, &c.Confidence, &ev, &discoveredAt,
		); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(ev), &c.Evidence)
		c.DiscoveredAt, _ = time.Parse(time.RFC3339, discoveredAt)
		correlations = append(correlations, c)
	}
	return correlations, rows.Err()
}

// RawDB exposes the underlying sql.DB connection for operations like graph bulk persistence.
func (s *SQLiteStore) RawDB() *sql.DB {
	return s.db
}

