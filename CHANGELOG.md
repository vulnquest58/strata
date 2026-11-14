# Changelog

All notable changes to Strata are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and releases use
[Semantic Versioning](https://semver.org/).

## [0.3.3] - 2026-11-14

### Added

- Evidence tension engine, `strata tension` command, and tension sections in
  Markdown/HTML reports. Findings are labelled `hot`, `ghost`, `shadow`, or
  `stable` from status, source breadth, live-probe evidence, confidence, and
  residual confidence on dead claims.
- Confidence calibration ledger: every transition into `verified` or `dead` is
  recorded as a claim outcome. `strata calibrate` reports Brier score, log
  loss, accuracy, and reliability bands.
- Target column and migration for findings; scoped `stats`, `list`, `report`,
  `tension`, `calibrate`, `fuse`, `verify`, and import commands via `--target`.
  Single-target databases are scoped automatically; multi-target databases warn
  before showing an unscoped view.
- Typed error taxonomy (`StrataError`, `ScopeViolation`, `NetworkFailure`,
  `InvalidInput`, `StageSkipped`, `StageFailed`, `BudgetExceeded`) and
  `classify_exception` for stage containment.
- Request budget (`--max-requests`, `--max-bytes`, `--max-seconds`) enforced by
  HTTP transports, with `BudgetExceeded` surfaced per stage.
- Run manifests written as report sidecars: version, target, scope, options,
  stage timings/status/findings, request and byte counts, finish time.
- `--strict-stages` to re-raise unexpected stage failures instead of recording
  them and continuing.
- Golden-surface benchmark evaluator (`strata.eval.benchmark`) with precision,
  recall, F1, and per-kind breakdowns, plus an offline orchestration benchmark
  test.
- Parameter differential analysis: `content_change_candidate` (structural body
  change) and `server_error_divergence` (5xx drift) alongside reflection and
  status-change confirmation.
- Confidence components are persisted and restored, so noisy-OR provenance
  survives database round-trips and reports.
- URL redaction in terminal output, Markdown/HTML tension sections, and SARIF.
- `scripts/check_version.py`, a tag/package version consistency check wired
  into CI on `v*` tags.
- CI workflow for Python 3.12/3.13: lint, test, and release version check.
- Test coverage for version identity, core primitives, store ledger, scoped CLI
  commands, calibration, and benchmark scoring.

### Changed

- Version identity is now single-sourced: `strata.__version__` is the only
  literal; `pyproject.toml` reads it dynamically and the CLI imports it.
- `upsert_finding` accepts an optional `target` and preserves the stored target
  when an update omits it.
- Fusion replaces superseded raw rows with one canonical entity, preserves
  engine metadata (tech stack, params, headers), and is idempotent on re-run
  instead of inflating the finding count.
- Orchestrator stages write and read target-scoped data; standalone report,
  tension, list, and stats commands resolve scope before reading.
- `decode_body` accepts an optional byte limit for differential analysis.
- Report SARIF generation consumes findings once and redacts URLs.
- Stub-driven orchestrator tests disable passive DNS and fingerprinting, cutting
  the test suite from minutes to seconds.

### Fixed

- `cmd_report` no longer contains orphaned output code.
- A single failing stage no longer aborts the remaining pipeline (unless
  `--strict-stages` is set).
- Top Findings/Summary tables are scoped to the current target instead of
  displaying unrelated findings.
- Tension bucket rendering is restored in reports.
- Repeated `strata fuse` runs no longer duplicate entities or double-count
  confidence signals.
- Help output no longer crashes on legacy Windows code pages.
- HTTP transports now inflate gzip/deflate bodies, so content discovery,
  secret scanning, fingerprinting, and parameter differential analysis see
  real HTML on compressed sites instead of binary noise.
- HTTP fingerprinting no longer fails silently on every host due to a missing
  `ConfidenceMethod.HTTP_PROBE` enum member; live fingerprint and content
  stages are now covered by offline tests.
- Probe-verified content findings now record their pre-probe confidence in the
  calibration ledger instead of being inserted as uncalibrated verified rows.
  Imported verified claims remain excluded.
- Orchestrator and benchmark tests write their reports to `tmp_path` instead of
  polluting the project `reports/` directory with timestamped artifacts.

## [0.3.2] - 2026-11-12

### Fixed

- Stage exceptions are recorded instead of crashing the run.
- Top Findings and Summary are scoped to the current target in `strata run`.
- Passive DNS failures use clearer error messages.
- Version banner and unused-variable cleanup.

## [0.3.1] - 2026-11-11

### Changed

- CLI version banner updated.

## [0.3.0] - 2026-11-10

### Added

- Unified pipeline: passive DNS, DNS brute force, HTTP fingerprinting, content
  discovery, parameter probing, fusion, tension, and report stages.
- Companion tool importers for Aperture, VulnHarvest, jsast, and Triage Loom.
- Markdown, HTML, SARIF 2.1.0, and JSONL reporting.

## [0.2.0] - 2026-11-09

### Added

- Initial public package layout, SQLite store, scope policy, and DNS/content
  engines.
