# Strata

Unified attack-surface intelligence engine. One pipeline from a domain to a
confidence-ranked map of the hidden surface: subdomains, live hosts, JS
endpoints, secrets, confirmed parameters — every claim backed by evidence and
a fused confidence score.

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
| **param** | Probes endpoints for hidden parameters with baseline/test request comparison |
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
strata tension --db target.db

# Generate HTML report
strata report --db target.db --format html --out report.html

# SARIF for CI/CD
strata report --db target.db --format sarif --out results.sarif
```

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
strata tension --db target.db
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
strata verify          Re-resolve stored candidates → verified/dead
strata content         JS/robots/sitemap content discovery
strata fuse            Fuse duplicate entities across runs
strata tension         Evidence tension analysis
strata report          Render findings as MD/HTML/SARIF/JSONL
strata stats           Database statistics
strata list            List stored findings
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
# Exit non-zero if any finding survives the report
strata report --db target.db --format sarif --out results.sarif --strict

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
