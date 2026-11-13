package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"aperture/config"
	"aperture/internal/reliability"
	"aperture/internal/store"
)

var (
	verifySource     string
	verifySampleRate float64
	verifyOlderThan  time.Duration
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run the reliability verification job for one or more sources",
	Long: `Samples a fraction of unverified findings from the specified sources,
probes each one with DNS + HTTP, and updates the Bayesian reliability record accordingly.
Findings discovered more recently than --older-than are excluded from verification.

Example:
  aperture verify --source hackertarget --sample-rate 0.15 --older-than 24h`,
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifySource, "source", "", "Source plugin to verify (optional, verifies all sources if omitted)")
	verifyCmd.Flags().Float64Var(&verifySampleRate, "sample-rate", 0.15, "Fraction of unverified findings to sample (0.0–1.0)")
	verifyCmd.Flags().DurationVar(&verifyOlderThan, "older-than", 24*time.Hour, "Exclude findings discovered more recently than this duration")
}

func runVerify(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if dbPath != "" {
		cfg.Storage.DatabasePath = dbPath
	}

	db, err := store.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer db.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	relEngine := reliability.NewEngine(db)
	verifier := reliability.NewVerifier(relEngine, db, cfg.Scan.DefaultTimeout)

	log.Info().
		Str("source", verifySource).
		Float64("sample_rate", verifySampleRate).
		Dur("older_than", verifyOlderThan).
		Msg("running scheduled verification job")

	results, err := verifier.Run(ctx, verifySource, verifySampleRate, verifyOlderThan)
	if err != nil {
		return fmt.Errorf("verification job failed: %w", err)
	}

	fmt.Printf("\n=== Aperture Verification Job Summary ===\n")
	fmt.Printf("Criteria: sample_rate=%.2f, older_than=%s, source_filter=%q\n",
		verifySampleRate, verifyOlderThan, verifySource)
	fmt.Printf("Sampled findings probed: %d\n", len(results))

	liveCount := 0
	for _, r := range results {
		verdict := "DEAD"
		if r.Live {
			verdict = "LIVE"
			liveCount++
		}
		fmt.Printf("  [%s] %-35s (source: %s)\n", verdict, r.AssetID, r.SourcePlugin)
	}
	fmt.Printf("Confirmed Live: %d | Confirmed Dead: %d\n", liveCount, len(results)-liveCount)

	return nil
}
