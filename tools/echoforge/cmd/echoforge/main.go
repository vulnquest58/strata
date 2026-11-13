package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/echoforge/echoforge/internal/harvester"
	"github.com/echoforge/echoforge/internal/miner"
	"github.com/echoforge/echoforge/internal/model"
	"github.com/echoforge/echoforge/internal/output"
	"github.com/echoforge/echoforge/internal/resolver"
	"github.com/echoforge/echoforge/internal/scorer"
	"github.com/echoforge/echoforge/internal/verifier"
)

// version info injected at build time
var version = "1.0.0"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var cfg model.ScanConfig

var rootCmd = &cobra.Command{
	Use:   "echoforge",
	Short: "EchoForge — Evolutionary Echo Discovery Engine",
	Long: `⚡ EchoForge v` + version + `
Evolutionary subdomain discovery using Markov Chains, N-gram analysis,
and stealth DNS-over-HTTPS resolution. Zero paid APIs.`,
	Example: `  echoforge -d example.com
  echoforge -d bank.com --industry finance --stealth --depth 3
  echoforge -d target.com --output all --min-confidence 50`,
	RunE: runScan,
}

func init() {
	f := rootCmd.Flags()
	f.StringVarP(&cfg.Domain, "domain", "d", "", "Target domain (required)")
	f.BoolVar(&cfg.StealthMode, "stealth", false, "Enable maximum stealth mode (slower, lower footprint)")
	f.IntVar(&cfg.EchoDepth, "depth", 3, "Echo evolution depth (1-6)")
	f.IntVar(&cfg.Threads, "threads", 50, "Concurrent goroutines for resolution")
	f.IntVar(&cfg.TimeoutSecs, "timeout", 4, "Per-request timeout in seconds")
	f.StringVar(&cfg.OutputFormat, "output", "table", "Output format: json|csv|table|html|all")
	f.StringVar(&cfg.OutputFile, "outfile", "", "Output file path (default: ./output/<domain>_<ts>)")
	f.Float64Var(&cfg.MinConfidence, "min-confidence", 40, "Minimum confidence score (0-100)")
	f.StringVar(&cfg.Industry, "industry", "auto", "Industry hint: auto|tech|finance|ecommerce|healthcare")
	f.BoolVar(&cfg.NoVerify, "no-verify", false, "Skip HTTP/TLS verification (DNS only)")
	f.BoolVar(&cfg.NoEvolve, "no-evolve", false, "Disable echo evolution (passive harvesting only)")
	f.StringVar(&cfg.WordlistPath, "wordlist", "", "Path to custom wordlist file")
	f.BoolVar(&cfg.FullPassive, "full-passive", false, "Include Common Crawl (slower, more complete)")
	f.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose logging")
	f.BoolVarP(&cfg.Quiet, "quiet", "q", false, "Suppress banner")

	_ = rootCmd.MarkFlagRequired("domain")
}

// initSubCommands registers the version and sources subcommands.
func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print EchoForge version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("EchoForge v%s\n", version)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "sources",
		Short: "List all passive harvesting sources",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("\n  EchoForge Passive Sources (all free, no API key):\n")
			rows := []struct{ name, desc string }{
				{"crt.sh",       "Certificate Transparency logs  — best coverage"},
				{"hackertarget", "HackerTarget OSINT API         — hostname+IP pairs"},
				{"anubis",       "Anubis FDNS via jldc.me        — passive DNS data"},
				{"wayback",      "Wayback Machine CDX API        — historical URLs"},
				{"otx",          "AlienVault OTX passive DNS     — threat intel"},
				{"commoncrawl",  "Common Crawl index             — opt-in (--full-passive)"},
				{"wordlist",     "Custom wordlist                 — opt-in (--wordlist)"},
			{"certspotter",  "Cert Spotter API (fallback)    — auto-fallback for crt.sh"},
			{"rapiddns",     "RapidDNS passive database      — new in v1.2"},
			}
			for _, r := range rows {
				fmt.Printf("  %-15s %s\n", r.name, r.desc)
			}
			fmt.Println()
		},
	})
}
func runScan(cmd *cobra.Command, args []string) error {
	// Configure logging
	// In non-verbose mode: discard all zerolog output to avoid PowerShell NativeCommandError.
	// Harvester warnings are surfaced via printWarning() to stdout instead.
	if cfg.Verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})
	} else {
		zerolog.SetGlobalLevel(zerolog.Disabled)
		log.Logger = zerolog.Nop()
	}

	// Validate domain
	cfg.Domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(cfg.Domain)), "www.")
	if cfg.Domain == "" {
		return fmt.Errorf("invalid domain")
	}

	// Clamp depth
	if cfg.EchoDepth < 1 {
		cfg.EchoDepth = 1
	}
	if cfg.EchoDepth > 6 {
		cfg.EchoDepth = 6
	}

	// In stealth mode, reduce threads automatically
	if cfg.StealthMode && cfg.Threads > 10 {
		cfg.Threads = 10
	}

	// Setup output path
	if cfg.OutputFile == "" {
		ts := time.Now().Format("20060102-150405")
		_ = os.MkdirAll("output", 0755)
		cfg.OutputFile = filepath.Join("output", fmt.Sprintf("%s_%s", cfg.Domain, ts))
	}

	// Print banner
	if !cfg.Quiet {
		output.PrintBanner()
		fmt.Printf("  🎯 Target    : %s\n", cfg.Domain)
		fmt.Printf("  🥷 Stealth   : %v\n", cfg.StealthMode)
		fmt.Printf("  🔁 Depth     : %d\n", cfg.EchoDepth)
		fmt.Printf("  🏭 Industry  : %s\n", cfg.Industry)
		fmt.Printf("  📤 Output    : %s\n", cfg.OutputFormat)
		fmt.Println()
	}

	scanID := fmt.Sprintf("echo-%s", time.Now().Format("20060102-150405"))
	startTime := time.Now()
	ctx := context.Background()

	// ─────────────────────────────────────────────────────────────────
	// LAYER 0: Passive Seed Harvesting
	// ─────────────────────────────────────────────────────────────────
	printPhase("Layer 0", "Passive Seed Harvesting", "🌱")
	h := harvester.New(cfg.Domain, cfg.StealthMode, cfg.FullPassive, cfg.WordlistPath)
	seeds, summaries := h.HarvestAllWithSummary(ctx)

	// Print per-source results to stdout (no stderr = no PowerShell NativeCommandError)
	for _, s := range summaries {
		if s.Warning != "" {
			printWarning(s.Source, s.Warning)
		} else if cfg.Verbose {
			printResult(fmt.Sprintf("  %s -> %d subdomains", s.Source, s.Count))
		}
	}
	printResult(fmt.Sprintf("Seeds harvested: %d unique subdomains", len(seeds)))

	// Collect seed hostnames as strings
	seedNames := make([]string, len(seeds))
	for i, s := range seeds {
		seedNames[i] = s.Subdomain
	}

	// ─────────────────────────────────────────────────────────────────
	// LAYER 1: Contextual Pattern Mining
	// ─────────────────────────────────────────────────────────────────
	printPhase("Layer 1", "Contextual Pattern Mining", "🧠")

	// Train Markov Chain on seeds
	mc := miner.NewMarkovChain(miner.MarkovOrder)
	mc.Train(seedNames)

	// N-gram analysis
	ngramExtractor := miner.NewNGramExtractor(3)
	freqMap := ngramExtractor.ExtractFrequency(seedNames)
	topGrams := miner.TopN(freqMap, 20)

	// Industry detection / profile
	var industryProfile *miner.IndustryProfile
	if cfg.Industry == "auto" {
		industryProfile = miner.AutoDetect(seedNames)
	} else {
		industryProfile = miner.GetProfile(cfg.Industry)
	}
	industryKeywords := []string{}
	if industryProfile != nil {
		industryKeywords = industryProfile.Keywords
		printResult(fmt.Sprintf("Industry detected: %s", industryProfile.Name))
	}

	// N-gram combinations
	ngramCandidates := miner.GenerateCombinations(cfg.Domain, topGrams, industryKeywords)

	// Markov candidates
	markovCandidates := mc.GenerateFromRandom(cfg.Domain, 200, 4)

	printResult(fmt.Sprintf("Markov candidates: %d | N-gram candidates: %d",
		len(markovCandidates), len(ngramCandidates)))

	// ─────────────────────────────────────────────────────────────────
	// WILDCARD DETECTION — before resolving candidates
	// ─────────────────────────────────────────────────────────────────
	pool := resolver.NewPool(cfg.TimeoutSecs, cfg.StealthMode)
	sc := scorer.New()

	printPhase("Layer 2", "Stealth DNS Resolution (DoH)", "🔮")

	wildcardIPs := pool.DetectWildcard(ctx, cfg.Domain)
	if wildcardIPs != nil {
		printResult(fmt.Sprintf("⚠ Wildcard DNS detected! Filtering %d wildcard IP(s)", len(wildcardIPs)))
	} else {
		printResult("Wildcard DNS: not detected ✓")
	}

	// Aggregate all candidates for first resolution pass
	allInitial := deduplicate(append(seedNames, append(ngramCandidates, markovCandidates...)...))
	printResult(fmt.Sprintf("Resolving %d candidates...", len(allInitial)))

	resResults := pool.ResolveMany(ctx, allInitial, cfg.Threads)
	resResults = resolver.FilterWildcard(resResults, wildcardIPs)

	// Build initial confirmed set
	confirmed := make(map[string]resolver.ResolutionResult)
	for _, r := range resResults {
		if r.Resolves {
			confirmed[r.Hostname] = r
		}
	}
	printResult(fmt.Sprintf("Confirmed resolving: %d subdomains", len(confirmed)))

	// ─────────────────────────────────────────────────────────────────
	// LAYER 3: Echo Evolution
	// ─────────────────────────────────────────────────────────────────
	var echoCandidates []string
	if !cfg.NoEvolve && len(confirmed) > 0 {
		printPhase("Layer 3", "Echo Evolution", "🌀")

		confirmedList := make([]string, 0, len(confirmed))
		for k := range confirmed {
			confirmedList = append(confirmedList, k)
		}

		// Retrain Markov with confirmed subdomains before evolving
		mc.Train(confirmedList)

		echoCandidates = miner.RunEvolution(
			cfg.Domain, confirmedList, mc, ngramExtractor, industryProfile, cfg.EchoDepth, freqMap,
		)

		printResult(fmt.Sprintf("Echo candidates generated: %d", len(echoCandidates)))

		// Resolve echo candidates + filter wildcard
		echoRes := pool.ResolveMany(ctx, echoCandidates, cfg.Threads)
		echoRes = resolver.FilterWildcard(echoRes, wildcardIPs)
		for _, r := range echoRes {
			if r.Resolves {
				confirmed[r.Hostname] = r
			}
		}
		printResult(fmt.Sprintf("Total confirmed after echo: %d", len(confirmed)))
	}

	// ─────────────────────────────────────────────────────────────────
	// LAYER 4: Silent Verification
	// ─────────────────────────────────────────────────────────────────
	httpVerifier := verifier.NewHTTPVerifier(cfg.TimeoutSecs)
	tlsVerifier := verifier.NewTLSVerifier(cfg.TimeoutSecs)

	if !cfg.NoVerify && !cfg.Quiet {
		printPhase("Layer 4", "Silent Verification (HEAD + TLS)", "🔍")
	}

	// ─────────────────────────────────────────────────────────────────
	// Build Final Results
	// ─────────────────────────────────────────────────────────────────
	allSubdomains := buildResults(
		seeds, allInitial, echoCandidates,
		confirmed, freqMap, httpVerifier, tlsVerifier,
		cfg, sc, ctx,
	)

	// Filter by minimum confidence
	filtered := make([]model.Subdomain, 0, len(allSubdomains))
	for _, s := range allSubdomains {
		if s.Confidence >= cfg.MinConfidence {
			filtered = append(filtered, s)
		}
	}

	// Sort by confidence
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Confidence > filtered[j].Confidence
	})

	// Count stats
	totalRes := 0
	highConf := 0
	wcCount := 0
	for _, s := range filtered {
		if s.Resolves {
			totalRes++
		}
		if s.Wildcard {
			wcCount++
		}
		if scorer.Category(s.Confidence) == "HIGH" {
			highConf++
		}
	}

	elapsed := time.Since(startTime)
	result := &model.ScanResult{
		Domain:           cfg.Domain,
		ScanID:           scanID,
		StartTime:        startTime,
		EndTime:          time.Now(),
		Duration:         elapsed.Round(time.Second).String(),
		TotalDiscovered:  len(filtered),
		TotalResolved:    totalRes,
		HighConfidence:   highConf,
		WildcardFiltered: wcCount,
		WildcardDetected: wildcardIPs != nil,
		Subdomains:       filtered,
	}

	// ─────────────────────────────────────────────────────────────────
	// Output
	// ─────────────────────────────────────────────────────────────────
	fmt.Println()
	outputFormats := strings.Split(strings.ToLower(cfg.OutputFormat), ",")
	for _, fmt_ := range outputFormats {
		fmt_ = strings.TrimSpace(fmt_)
		if fmt_ == "table" || fmt_ == "all" {
			output.PrintTable(result)
		}
	}

	output.PrintSummary(result)

	for _, fmt_ := range outputFormats {
		fmt_ = strings.TrimSpace(fmt_)
		writeAll := fmt_ == "all"
		if fmt_ == "json" || writeAll {
			path := cfg.OutputFile + ".json"
			if err := output.WriteJSON(result, path); err != nil {
				log.Error().Err(err).Msg("JSON write failed")
			} else {
				fmt.Printf("  📄 JSON  → %s\n", path)
			}
		}
		if fmt_ == "csv" || writeAll {
			path := cfg.OutputFile + ".csv"
			if err := output.WriteCSV(result, path); err != nil {
				log.Error().Err(err).Msg("CSV write failed")
			} else {
				fmt.Printf("  📊 CSV   → %s\n", path)
			}
		}
		if fmt_ == "html" || writeAll {
			path := cfg.OutputFile + ".html"
			if err := output.WriteHTML(result, path); err != nil {
				log.Error().Err(err).Msg("HTML write failed")
			} else {
				fmt.Printf("  🌐 HTML  → %s\n", path)
			}
		}
	}

	fmt.Println()
	return nil
}

// buildResults assembles the final model.Subdomain list from all pipeline stages.
func buildResults(
	seeds []harvester.Result,
	allInitial, echoCandidates []string,
	confirmed map[string]resolver.ResolutionResult,
	freqMap map[string]int,
	httpVerif *verifier.HTTPVerifier,
	tlsVerif *verifier.TLSVerifier,
	cfg model.ScanConfig,
	sc *scorer.Scorer,
	ctx context.Context,
) []model.Subdomain {
	// Build source map from seeds
	sourceMap := make(map[string]string)
	for _, s := range seeds {
		sourceMap[s.Subdomain] = s.Source
	}

	seen := make(map[string]bool)
	var results []model.Subdomain
	var mu sync.Mutex
	var wg sync.WaitGroup

	maxThreads := cfg.Threads
	if maxThreads < 1 {
		maxThreads = 10
	}
	sem := make(chan struct{}, maxThreads)

	process := func(name, src string, depth int, echoFrom []string) {
		defer wg.Done()
		defer func() { <-sem }()

		mu.Lock()
		if seen[name] {
			mu.Unlock()
			return
		}
		seen[name] = true
		mu.Unlock()

		resResult, resolves := confirmed[name]

		// Compute n-gram frequency score for this subdomain based on its tokens
		ngramScore := 0.0
		maxFreq := 1
		for _, v := range freqMap {
			if v > maxFreq {
				maxFreq = v
			}
		}
		// Score based on how frequent the subdomain's prefix token appears
		if idx := strings.Index(name, "."); idx > 0 {
			prefixPart := name[:idx]
			if freq, ok := freqMap[prefixPart]; ok && maxFreq > 0 {
				ngramScore = float64(freq) / float64(maxFreq)
			}
		}

		sub := model.Subdomain{
			Name:        name,
			Source:      src,
			Resolves:    resolves,
			IPAddresses: resResult.IPAddresses,
			EchoDepth:   depth,
			EchoFrom:    echoFrom,
			FirstSeen:   time.Now(),
		}

		// HTTP + TLS verification for resolved hosts
		httpStatus := 0
		tlsMatch := false
		if resolves && !cfg.NoVerify {
			httpRes := httpVerif.Probe(ctx, name)
			httpStatus = httpRes.StatusCode
			sub.HTTPStatus = httpStatus
			sub.ServerHeader = httpRes.ServerHeader

			tlsRes := tlsVerif.Check(ctx, name)
			tlsMatch = tlsRes.SANMatch
			sub.TLSSANMatch = tlsMatch
		}

		sub.Confidence = sc.ScoreFull(&sub, resResult, httpStatus, tlsMatch, ngramScore)

		mu.Lock()
		results = append(results, sub)
		mu.Unlock()
	}

	// Process all initial candidates
	for _, name := range allInitial {
		src, ok := sourceMap[name]
		if !ok {
			src = model.SourceMarkov
		}
		wg.Add(1)
		sem <- struct{}{}
		go process(name, src, 0, nil)
	}

	// Process echo candidates
	for _, name := range echoCandidates {
		wg.Add(1)
		sem <- struct{}{}
		go process(name, model.SourceEcho, 1, nil)
	}

	wg.Wait()
	return results
}

// deduplicate returns a new slice with duplicates removed, preserving order.
func deduplicate(items []string) []string {
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
