package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"aperture/config"
	"aperture/internal/consensus"
	"aperture/internal/output"
	"aperture/internal/pipeline"
	"aperture/internal/registry"
	"aperture/internal/reliability"
	"aperture/internal/resolver"
	"aperture/internal/sources"
	"aperture/internal/store"
)

var (
	flagSources     []string
	flagOutputFile  string
	flagActive      bool
	flagConcurrency int
)

var discoverCmd = &cobra.Command{
	Use:   "discover <target>",
	Short: "Discover assets for a target domain",
	Long: `Runs all configured (or specified) source plugins against the target domain,
applies temporal consensus resolution, adjusts confidence by source reliability,
and exports findings as JSONL.

Examples:
  aperture discover example.com
  aperture discover example.com --sources crtsh,hackertarget --output findings.jsonl
  aperture discover example.com --active --sources crtsh,dns_bruteforce`,
	Args: cobra.ExactArgs(1),
	RunE: runDiscover,
}

func init() {
	discoverCmd.Flags().StringSliceVar(&flagSources, "sources", []string{"crtsh", "hackertarget"},
		"Comma-separated list of source plugins to use")
	discoverCmd.Flags().StringVarP(&flagOutputFile, "output", "o", "-",
		"Output file path for JSONL findings (use '-' for stdout)")
	discoverCmd.Flags().BoolVar(&flagActive, "active", false,
		"Enable active sources (e.g. dns_bruteforce). Default: passive only")
	discoverCmd.Flags().IntVar(&flagConcurrency, "concurrency", 0,
		"Concurrent consensus workers (0 = use config default)")
}

func runDiscover(cmd *cobra.Command, args []string) error {
	target := strings.ToLower(strings.TrimSpace(args[0]))
	if target == "" {
		return fmt.Errorf("target domain must not be empty")
	}

	// Load configuration.
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if dbPath != "" {
		cfg.Storage.DatabasePath = dbPath
	}
	concurrency := cfg.Scan.DefaultConcurrency
	if flagConcurrency > 0 {
		concurrency = flagConcurrency
	}

	// Set up context with signal handling for clean shutdown (Ctrl+C).
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Open store.
	db, err := store.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer db.Close()

	// Open JSONL writer.
	writer, err := output.NewJSONLWriter(flagOutputFile)
	if err != nil {
		return fmt.Errorf("opening output: %w", err)
	}
	defer func() {
		writer.Close()
		log.Info().Int("total", writer.Count()).Msg("findings written")
	}()

	// Build source plugins.
	plugins, err := buildPlugins(flagSources, flagActive, cfg)
	if err != nil {
		return fmt.Errorf("building plugins: %w", err)
	}
	if len(plugins) == 0 {
		return fmt.Errorf("no plugins selected — check --sources flag")
	}

	// Build resolvers for temporal consensus.
	resolvers := buildResolvers(cfg)
	minJitter := time.Duration(cfg.Consensus.MinJitterSeconds) * time.Second
	maxJitter := time.Duration(cfg.Consensus.MaxJitterSeconds) * time.Second
	consensusEngine := consensus.NewEngine(resolvers, minJitter, maxJitter, cfg.Consensus.TemporalStabilityThreshold)

	// Build reliability engine.
	relEngine := reliability.NewEngine(db)
	for _, p := range plugins {
		relEngine.RegisterPrior(p.Name(), p.DefaultPriorReliability())
	}

	// Run the pipeline.
	scanID := uuid.NewString()
	log.Info().
		Str("target", target).
		Str("scan_id", scanID).
		Strs("sources", flagSources).
		Msg("starting discovery")

	start := time.Now()
	if err := pipeline.Run(ctx, pipeline.RunConfig{
		Target:      target,
		ScanID:      scanID,
		Plugins:     plugins,
		Consensus:   consensusEngine,
		Reliability: relEngine,
		Store:       db,
		Writer:      writer,
		Concurrency: concurrency,
	}); err != nil {
		return fmt.Errorf("pipeline error: %w", err)
	}

	log.Info().
		Dur("elapsed", time.Since(start)).
		Int("findings", writer.Count()).
		Msg("discovery complete")

	return nil
}

// buildPlugins instantiates the requested source plugins via the central registry.
func buildPlugins(names []string, activeEnabled bool, cfg *config.Config) ([]sources.SourcePlugin, error) {
	cleanNames := make([]string, 0, len(names))
	for _, n := range names {
		cleanNames = append(cleanNames, strings.TrimSpace(strings.ToLower(n)))
	}
	return registry.Build(cleanNames, registry.Config{
		TimeoutSecs:   cfg.Scan.DefaultTimeout,
		OTXAPIKey:     cfg.Sources.OTXAPIKey,
		ActiveEnabled: activeEnabled,
		RawDNSServers: cfg.Resolvers.RawDNSServers,
	})
}

// buildResolvers creates the three-resolver pool for temporal consensus.
// Order: DoH-Cloudflare, DoH-Google, raw UDP-Google.
func buildResolvers(cfg *config.Config) []resolver.Resolver {
	timeout := cfg.Scan.DefaultTimeout
	resolvers := []resolver.Resolver{
		resolver.NewDoHResolver("Cloudflare-DoH", "https://cloudflare-dns.com/dns-query", timeout),
		resolver.NewDoHResolver("Google-DoH", "https://dns.google/resolve", timeout),
		resolver.NewRawResolver("Google-Raw-UDP", "8.8.8.8:53", timeout),
	}

	// Override with config if provided.
	if len(cfg.Resolvers.DoHProviders) >= 2 {
		resolvers[0] = resolver.NewDoHResolver(
			cfg.Resolvers.DoHProviders[0].Name,
			cfg.Resolvers.DoHProviders[0].URL, timeout)
		resolvers[1] = resolver.NewDoHResolver(
			cfg.Resolvers.DoHProviders[1].Name,
			cfg.Resolvers.DoHProviders[1].URL, timeout)
	}
	if len(cfg.Resolvers.RawDNSServers) >= 1 {
		resolvers[2] = resolver.NewRawResolver("Raw-UDP-0", cfg.Resolvers.RawDNSServers[0], timeout)
	}

	return resolvers
}
