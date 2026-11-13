# Aperture

**Next-generation OSINT subdomain discovery engine with Bayesian source reliability and temporal consensus.**

## What makes Aperture different

| Feature | Traditional tools (Amass, Subfinder) | Aperture |
|---|---|---|
| Source reliability | Fixed weights, hardcoded | Bayesian Beta-Binomial, learned from empirical data |
| DNS resolution | Single attempt | 3-resolver temporal consensus (DoH×2 + raw UDP×1, with jitter) |
| Trust accumulation | Per-run | Cross-scan, per-source, per-TLD |
| Architecture | Monolithic | Discovery only — no filtering decisions |

## Quick Start

```bash
# Basic scan (passive sources only)
aperture discover example.com --output findings.jsonl

# Specific sources
aperture discover example.com --sources crtsh,hackertarget,otx --output findings.jsonl

# With active bruteforce (direct DNS contact)
aperture discover example.com --active --sources crtsh,dns_bruteforce --output findings.jsonl

# Check reliability history for a source
aperture reliability --source crtsh --show

# Run verification job to update reliability scores (excludes findings < 24h old)
aperture verify --source hackertarget --sample-rate 0.15 --older-than 24h
```

## Scheduled Verification
يجب تشغيل `aperture verify` دورياً (موصى به: يومياً) لضمان أن Reliability Scores تتحدث فعلياً:

### Windows (Task Scheduler)
```powershell
schtasks /create /tn "ApertureVerify" /tr "C:\path\to\aperture.exe verify --sample-rate 0.15 --older-than 24h" /sc daily /st 03:00
```

### Linux/macOS (cron)
```bash
0 3 * * * /path/to/aperture verify --sample-rate 0.15 --older-than 24h >> /var/log/aperture-verify.log 2>&1
```

## Architecture

```
Source Plugins                     Reliability Engine         Temporal Consensus
─────────────                      ──────────────────         ──────────────────
crtsh (passive)   ─┐               Beta-Binomial Bayesian     3 resolvers:
hackertarget      ─┼─► Dedup ─────► adjusted_confidence ────► • Cloudflare DoH
rapiddns          ─┤                                          • Google DoH
otx               ─┤                                          • Raw UDP
dns_bruteforce    ─┤                                          With 5–45s jitter
markov generator  ─┘                                          TemporalStability ≥ 0.66
                                                                      │
                                                                      ▼
                                                             JSONL output stream
```

## Source Plugins

| Plugin | Category | Notes |
|---|---|---|
| `crtsh` | Passive | Certificate Transparency logs. No API key. |
| `hackertarget` | Passive | Free API. ~100 req/day limit. |
| `rapiddns` | Passive | Free CSV download. |
| `otx` | Passive | AlienVault OTX. Set `OTX_API_KEY` env var. |
| `certspotter` | Passive | SSLMate CertSpotter CT log API. 5-layer validated, rate-limited, zero IP leakage. |
| `dns_bruteforce` | Active | Requires `--active` flag. Uses embedded top-10000 wordlist. |
| `markov` | Generative | Markov chain trained on compound subdomain patterns. |

## Configuration

Edit `config.yaml` or use environment variables:

```yaml
sources:
  otx_api_key: ""   # or set OTX_API_KEY

consensus:
  temporal_stability_threshold: 0.66  # 2-of-3 resolvers must agree
  min_jitter_seconds: 5
  max_jitter_seconds: 45
```

## Output Format

Each line in the JSONL output:
```json
{
  "id": "uuid",
  "asset_id": "api.target.com",
  "asset_type": "subdomain",
  "source_plugin": "crtsh",
  "raw_confidence": 85.0,
  "adjusted_confidence": 63.7,
  "temporal_stability": 1.0,
  "resolved_ips": ["1.2.3.4"],
  "discovered_at": "2026-09-21T20:00:00Z"
}
```

## Pipeline with Triage Loom

```bash
aperture discover target.com --output findings.jsonl
triage-loom ingest --aperture-file findings.jsonl --root-domain target.com
triage-loom run --root-domain target.com
triage-loom export --root-domain target.com --output output/
```

## Multi-Target Intelligence & Attack Surface Graph

Aperture maps corporate subsidiaries and sister domains across multiple targets using autonomous systems (ASN), /24 subnets, and multi-domain TLS SAN certificates, with context-weighted confidence scoring and Jaro-Winkler brand similarity filtering.

```bash
# 1. Run cross-target correlation
aperture correlate --root github.com

# 2. View executive terminal summary of discovered organizations and topology
aperture graph --root github.com --depth 2 --summary

# 3. Strictly traverse through confirmed organizational links (suppress weak co-location)
aperture graph --root github.com --depth 2 --org-only --summary

# 4. Export attack surface graph to JSON or Graphviz DOT
aperture graph --root github.com --depth 2 --format json --output graph.json
aperture graph --root github.com --depth 2 --format dot --output graph.dot
```

### Edge Classification
- `high_confidence_org_link`: Confirmed corporate subsidiaries / acquisitions (Confidence $\ge 0.80$ or TLS SAN overlap). Rendered as bold solid lines in graph visualization.
- `weak_colocation`: Shared hosting neighbors / multi-tenant CDNs (Confidence $< 0.80$). Rendered as dashed lines.
- `structural`: Internal DNS hierarchy and IP resolution (`SUBDOMAIN_OF`, `RESOLVES_TO`).
