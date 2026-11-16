# Changelog

All notable changes to Strata are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and releases use
[Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-11-16

### Added

- Isotonic recalibration (`core/calibration.py`): the truth ledger now
  closes the loop. A monotone pool-adjacent-violators map from predicted
  confidence to observed verify rate is fitted per target (global ledger as
  fallback) with Laplace smoothing, identity blending (`n / (n + 40)`), and a
  k-fold cross-validated gate that activates the map only when it beats the
  identity map by at least 1% relative Brier improvement. Stored findings are
  never rewritten; calibration is applied at read time so the learning loop
  cannot feed its own output back into the ledger.
- `calibrate` pipeline stage between `fuse` and `tension`; runs carry the
  applied model in `RunResult.calibration` and in the manifest (scope,
  samples, weight, Brier before/after, reason).
- Reports gain a `Calibrated` column and a recalibration provenance line only
  when the gate accepted a model; HTML rows show the calibrated arrow.
  `strata calibrate` prints the mapping grid (10-90) and writes a
  `## Recalibration model` section; `strata report` shows a `calibrated` row.
- Live validation on the v0.5.0 kali.org ledger (153 outcomes): reliability
  bands showed under-confidence (predicted 35.2 vs observed 100% in 20-39);
  cross-validated recalibration reduced Brier from 0.384 to 0.046.

### Fixed

- Isotonic smoothing could invert block order when block sizes differed
  widely (Laplace shrinkage penalizes small samples), producing a
  non-monotone confidence map; blocks are now re-pooled after smoothing by
  effective sample size, and duplicate-x blocks collapse to one value.

## [0.5.0] - 2026-11-15

### Added

- Soft-404 discrimination: content probes now compare a response against a
  per-host baseline fetched at a random unguessable path; HTTP 200 pages
  whose token-set similarity to the not-found baseline exceeds a calibrated
  threshold are classified soft-404 and killed instead of verified. Probe
  statistics report `soft404` kills and baseline fetches separately.
- Global EIG probe scheduler (`core/schedule.py` + `ProbeEngine`): a single
  budget shared across all probeable kinds (ENDPOINT / LIVE_HOST /
  SUBDOMAIN), apportioned largest-remainder by kind with a
  one-probe-per-kind floor against starvation, then spent EIG-ranked within
  each kind. Wired into the pipeline as the `probe` stage after `param`.
- Attack-value ranking (`core/attack_value.py`): every asset gets a priority
  score from kind base value, keyword tiers (admin/login/api/auth/dev),
  fingerprint signals (tech stack, versions, missing critical headers, WAF),
  and status (verified boost, dead floor). Exposed as `strata targets`
  (Markdown export via `--out`) and used for the portfolio summary.
- Vulnerability layer (`core/vulns.py` + curated `data/cve_map.json`): HTTP
  fingerprinting now extracts disclosed versions (Server / X-Powered-By /
  generator tags) into `metadata["versions"]`; a strict, branch-aware
  advisory window match (`since <= version < fixed`, numeric) produces
  `kind=VULN` findings. Never emits a claim without a disclosed version.
- Nuclei bridge: `strata import-nuclei` ingests nuclei `-json` results as
  `kind=VULN` findings (severity-mapped confidence, matcher-status honored);
  `strata export-nuclei` writes a nuclei target URL list from the live
  surface; `--import-nuclei` runs the import at the start of `strata run`.
- Correlated-source fusion: discovery engines are grouped into evidence
  families (`core/reliability.SOURCE_FAMILIES`); fusion collapses components
  to the strongest signal per family before the noisy-OR, so two DNS
  sources no longer double-count as independent votes. `source_count` now
  counts independent families; the raw signal count is kept in
  `source_count_raw`. Unmodeled engines keep independent votes.
- Takeover verification (`engines/takeover.py` + `strata takeover`): resolves
  CNAME chains, detects dangling aliases, and fingerprints the unclaimed-
  resource error pages of 14 curated services (S3, CloudFront, GitHub Pages,
  Heroku, Azure, Shopify, Zendesk, Fastly, Ghost, Pantheon, Surge, Bitbucket,
  Webflow, Heroku SSL DNS-only). Marker match yields a verified VULN finding;
  dangling aliases without a marker are surfaced as manual-review candidates.
- DNS wordlists expanded: base 130 -> 614 words, common 254 -> 1599 words.
- Run-completion notifications: `--notify-url` posts a compact summary at
  the end of `strata run` (Slack text blocks, Discord embeds, generic JSON).
  Webhook failures are contained and never fail the run; URLs are never
  logged or written to manifests.
- Authenticated surface discovery from the CLI: `--cookie`, `--auth-bearer`,
  and repeatable `--header 'Name: value'` build session headers applied to
  every in-scope HTTP request. Values never appear in reports or manifests.
- `--scope-file` accepts a bug-bounty program scope (one domain per line,
  `#` comments) merged with the target scope.
- `--auto-snapshot` freezes a surface snapshot at the end of every run.
- `strata portfolio`: per-target survey (findings, verified, vuln findings,
  highest attack-value asset) across the whole database.
- DB stats now include `kind_*` counts for per-kind reporting.
- New fingerprint signatures: Apache Tomcat (coyote), Django X-Powered-By,
  Jetty. Version disclosure comes from headers and generator tags only —
  Coyote/1.1 is correctly treated as a protocol version, not a product one.

### Changed

- Belief model: `FindingClass` gained `VULN`. VULN findings from the CVE
  window matcher carry evidence strength `corroborated` (inference from a
  published window), while nuclei template matches carry the matcher's own
  observation strength.
- Version-disclosure metadata (`versions`) on LIVE_HOST findings flows
  through fusion metadata merging unchanged.

## [0.4.0] - 2026-11-14

### Added

- Per-source reliability scoring: every claim outcome is attributed to its
  discovery sources (verifier engines excluded). `strata calibrate` reports
  observed verify rates per source and flags possible poisoned or low-quality
  sources when their rate diverges from the rest of the pool (>= 20 outcomes,
  source rate <= 0.3 with a healthy pool baseline).
- Belief half-life decay: unverified claims lose confidence over time
  (candidate half-life 30 days, verified 90 days, dead claims never decay).
  The tension engine adds a decay reason and reports effective confidence
  and claim age per finding.
- Self-calibrating wordlists: DNS runs record per-word attempts/successes in
  `technique_stats`; later runs order the wordlist by historical success rate
  first, keeping unmeasured words in their original order.
- Information-gain probing: content probes are scheduled by expected bits of
  entropy (binary H(p)) instead of raw confidence, probing the most uncertain
  claims first.
- Surface coverage estimation via capture-recapture (Chapman estimator with
  95% interval): independent discovery sources act as capture passes; overlap
  yields an estimate of the true surface size. Exposed as `strata coverage`.
  Dead claims are excluded — a refuted observation is not a capture pass —
  and `dns_resolve` is classified as a verifier engine rather than a source.
- Contested-claim arbitration: fused entities mixing `dead` and non-dead
  members are flagged `contested`; `strata arbitrate` lists them for manual
  re-verification, and fusion can weight sources by measured reliability.
- Longitudinal surface snapshots: `strata snapshot` freezes the current belief
  state (keys, statuses, confidence, discovery date) and `strata diff`
  compares a snapshot against the live database, reporting added, removed,
  status-changed, and confidence-shifted entries.
- DNS dead-claim recording: brute-force words that provably do not exist are
  persisted as `dead` subdomain findings, closing the candidate surface so
  later runs resume past them. Timeout and wildcard hits are never recorded
  dead, and a resolver outage during wildcard detection no longer aborts runs.
- Tension reasons for contested claims and dead parents (a subdomain whose
  parent host is dead inherits doubt), plus a plain-domain host fallback.

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
