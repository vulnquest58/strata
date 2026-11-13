<div align="center">

```
  ███████╗ ██████╗██╗  ██╗ ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██╔════╝██║  ██║██╔═══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  █████╗  ██║     ███████║██║   ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██╔══╝  ██║     ██╔══██║██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ███████╗╚██████╗██║  ██║╚██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**Evolutionary Echo Discovery Engine**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.1-blue?style=flat)](https://github.com/vulnquest58/echoforge/releases)
[![Zero APIs](https://img.shields.io/badge/Paid%20APIs-0-brightgreen?style=flat)](https://github.com/vulnquest58/echoforge)

*Discover subdomains like an echo — start from a whisper, let it evolve.*

</div>

---

## Philosophy — الفلسفة

Most subdomain tools work like a **dictionary attack**: throw thousands of words at DNS and see what sticks. EchoForge works differently.

EchoForge uses **"Evolutionary Echo Discovery"** — it treats the target's infrastructure as a **living system** that follows patterns. Instead of brute-forcing, it:

1. **Listens** — harvests real subdomains from passive CT logs, passive DNS, and OSINT APIs
2. **Learns** — extracts N-gram patterns and trains a Markov Chain on what it hears
3. **Evolves** — generates intelligent candidates that *sound like* the target's naming conventions
4. **Verifies** — confirms every result with DoH resolution, HTTP probing, and TLS SAN validation

The result: fewer results, **100% verified**, with zero paid APIs.

---

## Why EchoForge vs Subfinder/Amass?

| Feature | Subfinder | Amass | **EchoForge** |
|---------|:---------:|:-----:|:-------------:|
| Paid API keys required | ✅ Many | ✅ Many | **❌ Zero** |
| DNS Verified results | ❌ Raw only | Partial | **✅ 100%** |
| HTTP Verified | ❌ | ❌ | **✅** |
| TLS/SAN Verified | ❌ | ❌ | **✅** |
| Wildcard DNS detection | Limited | ✅ | **✅** |
| Echo/Markov Evolution | ❌ | ❌ | **✅ Unique** |
| Confidence scoring | ❌ | ❌ | **✅ 0–100%** |
| Stealth mode (DoH) | ❌ | Partial | **✅** |
| PowerShell-clean output | ❌ | ❌ | **✅** |

### Real-World Benchmark (`netflix.com`)

```
Subfinder:  3,695 raw results  → ~35% live  → ~1,293 actually reachable
EchoForge:     62 results      →  100% live →     62 verified (DNS+HTTP+TLS)

EchoForge also found cdn-api.netflix.com — NOT in Subfinder's 3,695 results.
```

> EchoForge isn't trying to win at quantity. It wins at **signal quality**.

---

## Features

- 🌱 **9 Passive Sources** — crt.sh, HackerTarget, Anubis FDNS, RapidDNS, Wayback Machine, OTX, Certspotter (auto-fallback), Common Crawl, custom wordlists
- 🧠 **Markov Chain + N-gram mining** — learns the target's naming language
- 🌀 **Echo Evolution** — generates naming-aware candidates that resolve
- 🔮 **Stealth DoH Resolution** — DNS-over-HTTPS via Cloudflare/Google/Quad9
- 🎯 **Wildcard DNS Detection** — probes random names, filters wildcard IPs
- 📊 **Confidence Scoring** — every result rated 0–100% based on passive source + DNS + HTTP + TLS
- 🥷 **Stealth Mode** — randomized User-Agents, jitter delays, reduced threads
- 📤 **Multiple Output Formats** — table, JSON, CSV, HTML

---

## Installation

### Prerequisites
- Go 1.21+

### Build from source
```bash
git clone https://github.com/vulnquest58/echoforge.git
cd echoforge
go build -ldflags="-s -w -X main.version=1.2.1" -o echoforge ./cmd/echoforge/
```

### Windows (PowerShell)
```powershell
git clone https://github.com/vulnquest58/echoforge.git
cd echoforge
go build -ldflags="-s -w -X main.version=1.2.1" -o echoforge.exe .\cmd\echoforge\
```

---

## Usage

### Basic scan
```bash
echoforge -d example.com
```

### With Echo Evolution (depth 2, min 60% confidence)
```bash
echoforge -d example.com --depth 2 --min-confidence 60
```

### Finance industry (activates finance-specific wordlists)
```bash
echoforge -d bank.com --industry finance --stealth
```

### Full passive + custom wordlist + all output formats
```bash
echoforge -d target.com --full-passive --wordlist ./data/wordlists/tech.txt --output all
```

### No Evolution (passive harvesting only, fast)
```bash
echoforge -d target.com --no-evolve --timeout 20
```

### Quiet mode (suppress banner, useful for scripting)
```bash
echoforge -d target.com -q --output json | jq '.subdomains[].name'
```

---

## All Flags

```
  -d, --domain string          Target domain (required)
      --depth int              Echo evolution depth 1–6 (default 3)
      --min-confidence float   Minimum confidence score 0–100 (default 40)
      --timeout int            Per-request timeout in seconds (default 4)
      --threads int            Concurrent DNS goroutines (default 50)
      --industry string        Industry hint: auto|tech|finance|ecommerce|healthcare (default "auto")
      --stealth                Enable stealth mode (slower, lower footprint)
      --no-evolve              Skip Echo Evolution (passive harvesting only)
      --no-verify              Skip HTTP/TLS verification (DNS only)
      --full-passive           Include Common Crawl (slower, more complete)
      --wordlist string        Path to custom wordlist file
      --output string          Output format: json|csv|table|html|all (default "table")
      --outfile string         Output file path (default: ./output/<domain>_<timestamp>)
  -q, --quiet                  Suppress banner
  -v, --verbose                Verbose logging (debug mode)
  -h, --help                   Show help
```

---

## Passive Sources

Run `echoforge sources` to list all available sources:

| Source | Type | Notes |
|--------|------|-------|
| `crt.sh` | Certificate Transparency | Best coverage for popular domains |
| `hackertarget` | OSINT API | Free, returns hostname+IP pairs |
| `anubis` | FDNS (jldc.me) | Passive DNS from Anubis project |
| `rapiddns` | Passive DNS DB | Free, stable, CSV format |
| `wayback` | CDX API | Historical URL analysis |
| `otx` | AlienVault OTX | Threat intelligence passive DNS |
| `certspotter` | CT (fallback) | Auto-fallback when crt.sh fails |
| `commoncrawl` | Web Crawl | Opt-in via `--full-passive` |
| `wordlist` | Local file | Opt-in via `--wordlist` |

> **Zero paid API keys required for any source.**

---

## Output Example

```
  ┌ ─── 🌱 Passive Seed Harvesting (Layer 0)
  │ Seeds harvested: 676 unique subdomains

  ┌ ─── 🧠 Contextual Pattern Mining (Layer 1)
  │ Industry detected: tech
  │ Markov candidates: 155 | N-gram candidates: 1722

  ┌ ─── 🔮 Stealth DNS Resolution (DoH) (Layer 2)
  │ Wildcard DNS: not detected ✓
  │ Resolving 2418 candidates...
  │ Confirmed resolving: 57 subdomains

  ┌ ─── 🌀 Echo Evolution (Layer 3)
  │ Echo candidates generated: 1095
  │ Total confirmed after echo: 60

✓ RESOLVED  (60 subdomains)

 Subdomain                  │ Confidence │ Level  │ Source       │ HTTP │ TLS │ IPs
────────────────────────────┼────────────┼────────┼──────────────┼──────┼─────┼──────────────
 account.netflix.com        │ 100.0%     │ HIGH   │ hackertarget │ 301  │ ✓   │ 207.45.73.1
 advertising.netflix.com    │ 100.0%     │ HIGH   │ hackertarget │ 200  │ ✓   │ 54.145.90.155
 api-staging.netflix.com    │ 83.6%      │ HIGH   │ markov       │ 403  │ ✓   │ 52.207.146.139
 api.netflix.com            │ 67.5%      │ MEDIUM │ markov       │ 200  │ ✓   │ 207.45.72.1
 ...

  ┌─────────────────────── SCAN SUMMARY ───────────────────────────┐
  │  Target Domain  : netflix.com                                  │
  │  Duration       : 2m55s                                        │
  ├─────────────────────────────────────────────────────────────────┤
  │  Total Found    : 62  │  DNS Resolved: 62                      │
  │  🟢 HIGH (≥80)  : 19  │  🟡 MEDIUM (≥50): 41  │  🔵 LOW: 2   │
  └─────────────────────────────────────────────────────────────────┘
```

---

## How Echo Evolution Works

```
Seed: "api.tesla.com" (from crt.sh)
         ↓
   Extract tokens: ["api"]
   N-gram patterns: ["api", "api-v2", "api-staging"]
         ↓
   Markov Chain trains on all seed names
         ↓
   Generate: "api-staging.tesla.com", "api-v2.tesla.com",
             "api-global.tesla.com", "staging-api.tesla.com"
         ↓
   DNS Resolve → HTTP Probe → TLS Verify
         ↓
   api-staging.tesla.com → 200 OK ✓ TLS ✓  [CONFIRMED]
```

Evolution candidates that resolve DNS get a **+15 point quality bonus** — because a generated name that actually resolves is a high-confidence signal.

---

## Confidence Scoring

Each subdomain is scored 0–100% based on:

| Signal | Points |
|--------|--------|
| From passive source (crt.sh, HackerTarget, etc.) | +30 |
| DNS resolves | +25 |
| Multiple DNS resolvers agree | +10 |
| HTTP 2xx/3xx response | +20 |
| HTTP 4xx (still interesting) | +5 |
| TLS SAN match | +10 |
| Echo/Markov candidate that resolves | +15 |
| N-gram frequency bonus | up to +5 |
| Echo depth bonus | up to +8 |

```
🟢 HIGH   ≥ 80% — Confirmed, reliable
🟡 MEDIUM ≥ 50% — Likely valid
🔵 LOW    ≥ 25% — Passive only, unconfirmed
```

---

## Project Structure

```
echoforge/
├── cmd/echoforge/          # CLI entry point
│   ├── main.go
│   └── internal_helpers.go
├── internal/
│   ├── harvester/          # Passive sources
│   │   ├── crtsh.go        # crt.sh + certspotter fallback
│   │   ├── hackertarget.go # HackerTarget API
│   │   ├── anubis.go       # Anubis FDNS (jldc.me)
│   │   ├── rapiddns.go     # RapidDNS passive DB
│   │   ├── wayback.go      # Wayback Machine CDX
│   │   ├── otx.go          # AlienVault OTX
│   │   └── commoncrawl.go  # Common Crawl
│   ├── miner/              # Pattern extraction & evolution
│   │   ├── markov.go       # Markov Chain generator
│   │   ├── ngram.go        # N-gram extractor
│   │   ├── evolver.go      # Echo Evolution engine
│   │   └── industry.go     # Industry profiles
│   ├── resolver/           # DNS resolution
│   │   ├── doh.go          # DNS-over-HTTPS client
│   │   └── pool.go         # Worker pool + wildcard detection
│   ├── scorer/             # Confidence scoring
│   │   └── scorer.go
│   ├── verifier/           # HTTP + TLS verification
│   │   ├── http.go
│   │   └── tls.go
│   ├── output/             # Output formatters
│   │   ├── table.go
│   │   ├── json.go
│   │   ├── csv.go
│   │   └── html.go
│   ├── model/              # Data models
│   └── utils/              # Jitter, retry, User-Agent rotation
├── data/wordlists/         # Industry-specific wordlists
│   ├── common.txt
│   ├── tech.txt
│   ├── finance.txt
│   ├── ecommerce.txt
│   └── healthcare.txt
└── config.yaml             # Optional config file
```

---

## Roadmap

- [ ] `--resume` — resume interrupted scans
- [ ] Shodan/Censys passive integration (free tier)
- [ ] DNS zone transfer detection
- [ ] ASN-based expansion
- [ ] Web UI (`echoforge serve`)
- [ ] Export to Burp Suite XML

---

## Legal & Ethics

EchoForge is designed for **authorized security assessments** only.

- ✅ Bug bounty programs (in-scope domains)
- ✅ Your own infrastructure
- ✅ Authorized penetration testing
- ❌ Unauthorized targets

All sources used are **public passive data** — no active scanning of targets beyond DNS resolution and HTTP HEAD probes. The tool respects rate limits and uses random delays in stealth mode.

---

## License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">

Built with ❤️ and zero paid APIs.

*"The Shadow Approach — Discover without a trace."*

</div>
