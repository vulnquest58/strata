# Strata

Unified attack-surface intelligence engine. One pipeline from a domain to a
confidence-ranked map of the hidden surface: subdomains, live hosts, JS
endpoints, secrets, confirmed parameters — every claim backed by evidence and
a fused confidence score.

Strata is designed as a calibrated belief engine, not a hit counter: it tracks
what it claimed, how confident it was, what happened when the claim was tested,
and how stable the remaining uncertainty is.

```
strata run target.com --db target.db
```

---

## How It Works

```
absorb → passive → dns → fingerprint → content → param → fuse → tension → report
```

| Stage | What it does |
|-------|-------------|
| **absorb** | Imports any companion-tool outputs before the scan begins |
| **passive** | Collects subdomains from Certificate Transparency logs and passive sources (no brute-force) |
| **dns** | Brute-force DNS enumeration with echoforge mutation passes |
| **fingerprint** | Detects tech stack, WAF, CDN, and security-header posture from HTTP responses |
| **content** | Crawls HTML/JS/robots/sitemap, extracts endpoints, scans for secrets |
| **param** | Probes endpoints for hidden parameters using baseline/test differential analysis (reflection, status, structural body change, server error) |
| **fuse** | Merges duplicate entities across engines using noisy-OR confidence |
| **tension** | Scores how unstable each claim is; labels findings as `hot`, `ghost`, `shadow`, or `stable` |
| **report** | Writes Markdown, HTML, SARIF 2.1.0, or JSONL output |

---

## Installation

```bash
pip install -e ".[dev]"
```

**Requires Python ≥ 3.12.** No API keys needed for the core pipeline.

---

## Quick Start

```bash
# Full pipeline — no config required
strata run target.com --db target.db

# Skip passive DNS collection (faster, offline brute-force only)
strata run target.com --no-passive --db target.db

# Skip fingerprinting
strata run target.com --no-fingerprint --db target.db

# DNS only
strata dns target.com --db target.db --wordlist common

# Content discovery only
strata content https://target.com --db target.db

# Tension analysis
strata tension --db target.db --target target.com

# Confidence calibration (Brier score, log loss, reliability bands)
strata calibrate --db target.db --target target.com

# Generate HTML report
strata report --db target.db --target target.com --format html --out report.html

# SARIF for CI/CD
strata report --db target.db --target target.com --format sarif --out results.sarif
```

### Target isolation

Findings are tagged with the target that produced them. Read commands accept
`--target` so a shared database never leaks one engagement's surface into
another's report:

```bash
strata stats --db all.db --target target.com
strata list  --db all.db --target target.com
strata report --db all.db --target target.com --out target.md
```

When a database contains multiple targets and no `--target` is given, Strata
prints an explicit warning and shows all targets. Use one database per
engagement for hard isolation.

### Budgets and run manifests

```bash
strata run target.com --db target.db \
  --max-requests 5000 \
  --max-bytes 50000000 \
  --max-seconds 900
```

Budgets are enforced across HTTP stages. Every run also writes a sidecar
manifest next to the report (`*.manifest.json`) containing the version, target,
scope, options, stage timings, request/byte counts, and finished-at timestamp.
`--strict-stages` re-raises unexpected stage errors instead of recording them
and continuing.

---

## Passive DNS Sources

Strata queries multiple passive sources concurrently with no API keys:

| Source | Key required | Notes |
|--------|-------------|-------|
| **crt.sh** | No | Certificate Transparency logs |
| **HackerTarget** | No | Free tier (rate-limited) |
| **RapidDNS** | No | Free subdomain search |
| **AlienVault OTX** | No | Free tier passive DNS |
| **VirusTotal** | Optional | Set `STRATA_VIRUSTOTAL_KEY` |
| **SecurityTrails** | Optional | Set `STRATA_SECURITYTRAILS_KEY` |

Sources with errors or missing keys are silently skipped — the run continues
with whatever sources are available.

---

## Configuration

No config file is required. Strata works out of the box with zero API keys.

To activate optional sources, create `.strata.toml` in your project directory
(or `~/.config/strata/config.toml` for global settings):

```toml
# .strata.toml — all fields optional

[keys]
virustotal    = "YOUR_VT_KEY"
securitytrails = "YOUR_ST_KEY"
# shodan      = "YOUR_SHODAN_KEY"   # reserved for future use
# censys_id   = "..."
# censys_secret = "..."

[transport]
per_host_delay = 0.3    # seconds between requests to the same host
proxy          = ""     # "http://127.0.0.1:8080" or "socks5://..."
timeout        = 10.0
max_retries    = 2
# user_agents = ["Mozilla/5.0 ..."]  # custom UA pool

[passive_dns]
crtsh          = true
hackertarget   = true
rapiddns       = true
alienvault     = true
virustotal     = true   # only runs if [keys].virustotal is set
securitytrails = true   # only runs if [keys].securitytrails is set
```

**Environment variables** (override config file):
```bash
export STRATA_VIRUSTOTAL_KEY="..."
export STRATA_SECURITYTRAILS_KEY="..."
export STRATA_PROXY="http://127.0.0.1:8080"
```

---

## HTTP Transport

By default, Strata uses `ThrottledTransport` for all external requests:
- **User-Agent rotation** — cycles through a pool of realistic browser UA strings
- **Per-host rate limiting** — configurable delay (default 0.3s) between requests to the same host
- **Proxy support** — HTTP and SOCKS5 proxies, set via config or `STRATA_PROXY`
- **Retry on network errors** — exponential back-off, never retries on 4xx/5xx

---

## HTTP Fingerprinting

The `fingerprint` stage probes each discovered host and detects:

- **WAF** — Cloudflare, Akamai, Imperva, F5 BIG-IP, ModSecurity, PerimeterX, Barracuda, +15 more
- **CDN** — Cloudflare, AWS CloudFront, Azure CDN, Akamai, Fastly, BunnyCDN, Varnish
- **Tech stack** — Nginx, Apache, IIS, PHP, Django, Laravel, Rails, Node.js, WordPress, Drupal, Next.js, +20 more
- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORP, COOP

Results are stored in `UnifiedFinding.metadata` and included in reports:
```json
{
  "tech_stack": ["Nginx", "PHP", "Laravel"],
  "waf": "Cloudflare",
  "cdn": "Cloudflare",
  "missing_critical_headers": ["content-security-policy"]
}
```

---

## Evidence Tension

Strata treats findings as hypotheses, not facts. The `tension` command scores
how unstable each claim is and classifies it:

| Label | Meaning | Recommended action |
|-------|---------|-------------------|
| `hot` | High-confidence, unverified — most likely real | Verify manually now |
| `ghost` | Marked dead but residual confidence remains | Re-check; may have revived |
| `shadow` | Low confidence, unsupported claim | Low priority; defer |
| `stable` | Verified or well-supported | Done |

```bash
strata tension --db target.db --target target.com
```

The scoring is intentionally transparent: candidate/stale status, single-source
evidence, absence of a live probe, high confidence without verification, and
dead findings with residual confidence all raise tension. Reports are written
to `reports/strata-tension-{target}-{timestamp}.md`.

---

## Confidence Calibration

Tension tells you what is unstable. Calibration tells you whether confidence
means anything. Every status transition into `verified` or `dead` is recorded
as an outcome in the truth ledger; a probe that resolves an extraction
candidate also records the candidate's pre-probe confidence. Imported claims
that arrive already verified stay out of the ledger because they carry no prior
prediction. `strata calibrate` then reports:

- **Brier score** — mean squared error of predicted confidence
- **Log loss** — penalty for confident mistakes
- **Accuracy** — share of outcomes that resolved as predicted
- **Reliability bands** — predicted confidence vs observed outcome rate

```bash
strata calibrate --db target.db --target target.com
```

Calibration improves as the pipeline verifies more claims. An empty ledger is
reported honestly rather than hidden. Reports are written to
`reports/strata-calibration-{target}-{timestamp}.md`.

Calibration also scores the sources themselves: each outcome is attributed to
the discovery engines behind its claim, and `strata calibrate` reports each
source's observed verify rate. A source that keeps dying on claims the rest of
the pool verifies is flagged as possibly poisoned or low quality, and fusion
can down-weight it on the next run.

### Isotonic recalibration

Band tables show a drift; recalibration corrects it. From the same ledger,
Strata fits a monotone map from predicted confidence to observed verify rate
(pool-adjacent-violators isotonic regression) and applies it at report time:

- **Per-target model** — the target's own outcomes are used when they are
  sufficient; otherwise the model falls back to the global ledger. A
  calibrated target is never overridden by the global model.
- **Cross-validated gate** — the map only activates when it beats the
  identity map on held-out folds by at least 1% relative Brier improvement.
  Otherwise confidence stays raw and the run records why.
- **Smoothing and blending** — Laplace smoothing keeps small blocks away from
  0/1, a weighted re-pooling pass keeps the map monotone, and the calibrated
  value is blended with the raw value by `n / (n + 40)` so a thin ledger
  cannot swing claims.

The model never rewrites stored findings, so the learning loop cannot feed its
own output back into the ledger. The pipeline runs a `calibrate` stage between
`fuse` and `tension`; reports show calibrated values (a `Calibrated` column in
Markdown, an inline arrow in HTML) and a provenance line only when the gate
accepted a model, and manifests record the applied model (scope, samples,
weight, cross-validated Brier before/after).

```bash
strata calibrate --db target.db --target target.com   # fit and inspect the map
strata report --db target.db --target target.com      # calibrated column
```

Live validation on the v0.5.0 kali.org experiment: 153 ledger outcomes,
reliability bands showed the engine was under-confident (predicted 35.2 vs
observed 100% in the 20-39 band), and the cross-validated recalibration cut
Brier score from 0.384 to 0.046. Calibrated confidence is best read as the
verify rate among *attempted* claims; verification is scheduled by expected
information gain, so high-EIG candidates are over-represented in the ledger.

---

## Self-Calibrating Beliefs

Three mechanisms make confidence sharper every run, without any manual tuning:

- **Belief half-life** — unverified claims decay over time (candidate claims
  halve every 30 days, verified claims every 90; dead claims never decay).
  The tension engine reports effective confidence and claim age, so a
  subdomain believed at 80% a year ago is surfaced as what it is now: a guess.
- **Self-calibrating wordlists** — DNS brute-force records per-word
  attempts/successes across runs. Later runs probe historically productive
  words first, so the same wordlist finds more per request. Data stays in the
  local database.
- **Information-gain probing** — content probes are scheduled by expected
  bits of entropy: a claim at 50% confidence resolves twice the information
  of one at 90%, so the most uncertain claims are verified first.

---

## Surface Coverage Estimation

How much of the surface are you still missing? Independent discovery sources
act as capture-recapture passes: a subdomain seen by both certificate
transparency and RapidDNS is a recapture, and the overlap estimates the true
surface size (Chapman estimator with a 95% interval).

```bash
strata coverage --db target.db --target target.com
```

Small overlaps are reported honestly as "insufficient overlap" rather than
extrapolated. Coverage estimates appear in run reports as insight notes.

---

## Contested Claims

Sources disagree sometimes: a subdomain appears in a CT log but the brute
force proves its parent dead. Fusion flags such entities as `contested`, and
`strata arbitrate` lists them for manual re-verification instead of letting
the loudest source win:

```bash
strata arbitrate --db target.db
```

---

## Surface Snapshots and Drift

Freeze the current belief state and compare it against future runs to see
exactly how the surface moved — new subdomains, dead claims, status changes,
and confidence shifts:

```bash
strata snapshot --db target.db --target target.com --out snapshot.json
strata diff --db target.db --against snapshot.json --out drift.md
```

Pass `--auto-snapshot` to `strata run` to freeze a snapshot automatically at
the end of every run.

---


## Attack-Value Ranking

Not all findings deserve equal attention. Every asset gets a priority score
from its kind, name keywords (admin / login / api / auth / dev), fingerprint
signals (technology, disclosed versions, missing security headers, WAF), and
verification status. Dead claims are never ranked:

```bash
strata targets --db target.db --target target.com --top 25 --out priorities.md
strata portfolio --db target.db        # every stored target at a glance
```

---


## Vulnerability Layer: Disclosed Versions to CVEs

Strata claims a CVE only under strict conditions: the target must *disclose*
a software version (Server / X-Powered-By / generator tags), and the
disclosed version must fall inside a published advisory window
(`since <= version < fixed`, compared numerically, branch-aware). No
version, no claim. Matches become `kind=vuln` findings with the window,
severity, and advisory summary in evidence:

```bash
strata run target.com                 # version extraction happens in the fingerprint stage
strata list --db target.db --target target.com
```

The curated map (`src/strata/data/cve_map.json`) covers high-confidence
cases (Apache traversal pair, Nginx resolver, Struts Jakarta RCE, PHP CGI
argument injection, Drupalgeddon2, Django SQLi, Spring4Shell, Tomcat partial
PUT, Next.js middleware bypass, Laravel Ignition, WordPress WP_Query SQLi).
Maintenance rule: add entries only for CVEs with a well-defined version
window.

---


## Nuclei Bridge

Strata and nuclei form a round trip: Strata maps the surface and hands it to
nuclei; nuclei detections come back as vuln findings with their provenance:

```bash
# Hand the live surface to nuclei
strata export-nuclei --db target.db --target target.com --out targets.txt
nuclei -l targets.txt -json -o results.jsonl

# Bring detections back (standalone or at the start of a run)
strata import-nuclei results.jsonl --db target.db
strata run target.com --import-nuclei results.jsonl --db target.db
```

---


## Subdomain Takeover Verification

```bash
strata takeover --db target.db --target target.com
```

Resolves CNAME chains, flags dangling aliases (third-party service records
with no A/AAAA answer), and fingerprints the unclaimed-resource error pages
of 14 curated services (S3 `NoSuchBucket`, GitHub Pages, Heroku, Azure App
Service, CloudFront, Shopify, Zendesk, Fastly, Ghost(Pro), Pantheon, Surge,
Bitbucket, Webflow, Heroku SSL DNS-only). A marker match produces a
verified `vuln` finding; a dangling alias without a marker is surfaced as a
manual-review candidate. Strata never claims exploitability without the
service fingerprint.

---


## Authenticated Surface Discovery

Session credentials extend the reachable surface to login-protected areas.
Headers are applied to every in-scope request and are never written to
reports, manifests, or logs:

```bash
strata run target.com \
  --cookie "session=..." \
  --header "X-Tenant: acme" \
  --auth-bearer "$TOKEN" \
  --scope-file program-scope.txt
```

`--scope-file` merges a bug-bounty program scope (one domain per line, `#`
comments allowed) with the target scope. `--notify-url` posts a run
summary to Slack, Discord, or any generic webhook when the run completes;
notification failures never fail the run.

---

## Benchmarking

`strata.eval.benchmark` scores findings against an explicit golden surface and
returns precision, recall, F1, and per-kind breakdowns. The test suite includes
an offline golden-surface run so changes can be compared on receipts rather
than anecdote:

```python
from strata.eval.benchmark import score_findings

score = score_findings(findings, {
    "subdomain:www.example.com",
    "endpoint:https://example.com/api/users?user_id=1",
})
print(score.as_dict())
```

---

## Companion Tool Integration

Import findings from external tools before or during a run:

```bash
# Import then run
strata run target.com \
  --import-aperture ./aperture-out.jsonl \
  --import-vulnharvest ./vulnharvest.json \
  --import-jsast ./jsast.json \
  --import-triage-loom ./triage-loom-out.jsonl \
  --db target.db

# Import only
strata import-aperture aperture-out.jsonl --db target.db
strata import-vulnharvest report.json --db target.db
```

Bundled companion tools under `tools/`:
- `tools/aperture/` — subdomain discovery from passive sources (Go)
- `tools/echoforge/` — evolutionary subdomain mutation engine (Go)
- `tools/triage-loom/` — triage and investigation ranking (Python)

---

## All Commands

```
strata run             Full pipeline on one target
strata dns             DNS brute-force only
strata verify          Re-resolve stored candidates to verified/dead
strata content         JS/robots/sitemap content discovery
strata fuse            Fuse duplicate entities across runs
strata tension         Evidence tension analysis
strata calibrate       Fit/inspect confidence recalibration from outcomes
strata coverage        Surface coverage estimation (capture-recapture)
strata arbitrate       List claims where discovery sources conflict
strata takeover        Verify dangling CNAMEs against service fingerprints
strata targets         Rank the surface by attack value
strata portfolio       Survey every stored target at a glance
strata snapshot        Freeze the current surface belief state
strata diff            Diff the live database against a snapshot
strata report          Render findings as MD/HTML/SARIF/JSONL
strata stats           Database statistics
strata list            List stored findings
strata export-nuclei         Export nuclei target URL list
strata import-nuclei         Import nuclei JSON results
strata import-aperture       Import aperture JSONL
strata import-vulnharvest    Import VulnHarvest JSON
strata import-jsast          Import jsast JSON
strata import-triage-loom    Import Triage Loom JSONL
```

---

## Output Formats

| Format | Flag | Use case |
|--------|------|---------|
| Markdown | `--format md` | Human review, GitHub reports |
| HTML | `--format html` | Browser-readable, shareable |
| SARIF 2.1.0 | `--format sarif` | GitHub Code Scanning, CI/CD |
| JSONL | `--format jsonl` | Pipe to other tools |

Reports are written to `reports/strata-{target}-{timestamp}.{ext}` by default.

---

## CI/CD Integration

```bash
# Write SARIF for GitHub Code Scanning
strata report --db target.db --target target.com --format sarif --out results.sarif

# Upload to GitHub Code Scanning
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  --input results.sarif
```

---

## Design Principles

1. **A candidate is not a finding** — `verified`/`dead` status requires at least one evidence record.
2. **Every engine emits `UnifiedFinding`** — legacy formats only enter through `adapters/`.
3. **Scope gate is mandatory** — engines reject out-of-scope assets before storing.
4. **Core runs with zero API keys** — keys unlock additional sources, never gate the pipeline.
5. **Secrets are never stored raw** — only SHA-256 asset IDs with masked previews enter the database.

---

## Project Layout

```
src/strata/
  core/config.py        API key + transport config (env or .strata.toml)
  core/schema/          UnifiedFinding data contract
  core/store/           SQLite persistence with dedup
  core/policy/          Scope allowlist gate
  core/dns/             Resolver, wildcard detection, origin inference
  core/content/         URL canonicalization, secret detection, HTTP transport
  core/reporting/       HTML/Markdown/SARIF/JSONL rendering
  core/errors.py        Typed error taxonomy and stage classification
  core/budget.py        Request/byte/time budget enforcement
  core/redact.py        URL credential and secret redaction
  core/manifest.py      Run manifest generation and sidecar paths
  eval/                 Golden-surface precision/recall scoring
  engines/
    dns_brute.py        Brute-force DNS with echoforge mutations
    http_fp.py          HTTP fingerprinting (WAF/tech/CDN/headers)
    js_content.py       Content discovery engine
    param_oracle.py     Parameter probing engine
    fusion.py           Noisy-OR entity fusion
    tension.py          Evidence tension scoring
    orchestrator.py     Full pipeline with adaptive RunMemory
  adapters/
    passive_dns.py      Passive DNS aggregator (crt.sh, HackerTarget, OTX, VT, ST)
    aperture.py         Aperture JSONL importer
    vulnharvest.py      VulnHarvest JSON importer
    jsast.py            jsast JSON importer
    triage_loom.py      Triage Loom JSONL importer
tools/
  aperture/             Subdomain discovery (Go)
  echoforge/            Mutation engine (Go)
  triage-loom/          Triage ranking (Python)
```
