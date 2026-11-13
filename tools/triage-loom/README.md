# Triage Loom

**5-stage OSINT filter chain and investigation priority ranking for Aperture findings.**

Triage Loom is the second half of the Aperture + Triage Loom recon pipeline.
It consumes Aperture's JSONL output and applies five independent filter stages
to produce ranked, corroborated investigation targets.

## Architecture

```
Aperture JSONL
     │
     ▼
┌────────────────────────────────────────────────────┐
│  Filter 1: Liveness Verification (HTTP HEAD probe) │
│  Filter 2: Archive Cross-Reference (Wayback+CC+URLScan, 2-of-3) │
│  Filter 3: Parameter Corroboration (archive+JS+OpenAPI, ≥2 techniques) │
│  Filter 4: Dedup + Pattern Clustering ({id}/{uuid}/{hash}) │
│  Filter 5: Novelty Ranking (infra deviation + recency + uniqueness) │
└────────────────────────────────────────────────────┘
     │
     ▼
high_confidence_targets.jsonl  (≥2 corroboration layers)
low_confidence_targets.jsonl   (1 layer — optional manual review)
endpoint_clusters.json         (full reference)
```

## Usage

```bash
# Ingest Aperture findings
triage-loom ingest --aperture-file findings.jsonl --root-domain target.com

# Run all filter stages
triage-loom run --root-domain target.com --stages liveness,archive,params,cluster,novelty

# Export results
triage-loom export --root-domain target.com --output output/

# Explain a specific finding
triage-loom explain "/api/v1/{id}"
```

## Design Principles

- **No vulnerability scoring** — all output is structural/statistical (existence, freshness, corroboration)
- **Full transparency** — every finding is explainable via `triage-loom explain`
- **2-of-3 corroboration** — endpoints confirmed by ≥2 independent sources go to `high_confidence`
- **No black-box ML** — all filtering uses deterministic, auditable logic
