# Strata

Unified attack-surface intelligence engine. One pipeline from a domain or org
name to a complete, confidence-ranked map of the hidden attack surface: live
hosts, web content, JS endpoints, secrets, and predicted parameters — every
claim carrying evidence and a fused confidence score.

Status: **P6 (orchestrator)** — P0 schema/store, P1 DNS discovery, P2 content
discovery, P3 parameter probing, P4 cross-engine fusion and Triage Loom
ingestion, P5 HTML/Markdown/SARIF/JSONL reporting with resumable scans, and
a single `strata run` orchestrator with per-target memory.

## Layout

```
src/strata/
  core/schema/      UnifiedFinding contract (candidate != finding)
  core/store/       SQLite persistence, dedup key (run_id, kind, asset_value)
  core/policy/      scope allowlist gate
  core/dns/         resolver, wildcard detection, origin inference
  core/content/     URL canonicalization, secret detection, HTTP transport
  core/reporting/   HTML/Markdown/SARIF/JSONL report rendering
  engines/          dns_brute, echoforge, js_content, param_oracle, fusion, orchestrator
  adapters/         aperture JSONL, VulnHarvest JSON, jsast JSON, Triage Loom
  cli/              strata run | dns | verify | content | import-* | fuse | report | stats | list
tools/              source snapshots of companion tools (aperture, triage-loom, echoforge)
```

## Quickstart

```bash
pip install -e ".[dev]"
pytest
strata dns example.com --db strata.db
strata content https://example.com --db strata.db
strata import-vulnharvest report.json --db strata.db
strata import-jsast export.json --db strata.db
strata import-aperture ../aperture/some_output.jsonl --db strata.db
strata import-triage-loom ../triage-loom/output/high_confidence_targets.jsonl --db strata.db
strata fuse --db strata.db
strata run example.com --db strata.db --report-out report.md
strata run example.com --import-aperture ../aperture/findings.jsonl --db strata.db --report-out report.md
strata run example.com --import-triage-loom ../triage-loom/output/high_confidence_targets.jsonl --db strata.db --report-out report.md
strata report --db strata.db --format md --out report.md
strata report --db strata.db --format html --out report.html
```

`strata run` is the coordinated entry point: it plans, executes, explains, and
reports in one pass. It keeps lightweight per-target memory so the next run can
adapt instead of repeating the same plan. `strata dns` and `strata content`
also accept `--resume` to skip assets already stored in the database. In CI,
`strata report --strict` exits non-zero when any finding survives the report
filters.

Reports are organized into summary, breakdown, confidence distribution, and
findings sections so a run can be reviewed without digging through a flat
table. Generated reports are written to `reports/` inside the project by
default, with a timestamped filename.

## Evidence tension

Strata treats findings as hypotheses, not facts. `strata tension` scores how
unstable a claim is: unverified status, single-source evidence, missing
live-probe evidence, and confidence gaps are surfaced as tension. Findings are
classified as `hot`, `ghost`, `shadow`, or `stable`, and the report is written
to `reports/`.

Secrets are stored only as SHA-256 asset ids with masked previews; raw values
never enter the database.

## Design rules (frozen for P0)

1. A candidate is not a finding: `verified`/`dead` status requires evidence.
2. Every engine emits `UnifiedFinding`; legacy formats only enter through
   `adapters/`.
3. Scope gate lives in `core.policy`; engines refuse out-of-scope assets.
4. Core runs with zero API keys; keys are per-plugin config.

## Roadmap

- [x] P1 DNS layer (resolver, wildcard filter, echoforge + dns_brute engines, verifier)
- [x] P2 Content layer (js_content engine, secret scan, jsast + VulnHarvest importers)
- [x] P3 Parameter layer (ParamOracle)
- [x] P4 Fusion + triage (noisy-OR, entity resolution; triage-loom consumer)
- [x] P5 Output hardening (HTML/MD/SARIF/JSONL, resume, CI)
- [x] P6 Orchestrator (single entry point, adaptive per-target memory)

## Bundled companion tools

Source snapshots of companion tools live under `tools/`:

- `tools/aperture/` — subdomain discovery sources (Go)
- `tools/triage-loom/` — triage + investigation ranking (Python)
- `tools/echoforge/` — evolutionary subdomain mutation engine (Go)

`jsast` and `vulnharvest` are integrated directly as adapters under
`src/strata/adapters/`. You can bring their outputs into a run with
`--import-aperture`, `--import-jsast`, `--import-vulnharvest`, or
`--import-triage-loom`.
