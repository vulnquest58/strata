package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	verbose    bool
	configFile string
	dbPath     string
)

var rootCmd = &cobra.Command{
	Use:   "aperture",
	Short: "Aperture — Next-gen OSINT discovery engine with Bayesian source reliability",
	Long: `Aperture discovers network assets (subdomains, IPs, DNS records) from multiple
independent OSINT sources. It applies Bayesian source reliability scoring and
validates all findings via temporal consensus across multiple resolvers and protocols.

Outputs raw JSONL for consumption by Triage Loom or any JSONL-compatible pipeline.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		level := zerolog.InfoLevel
		if verbose {
			level = zerolog.DebugLevel
		}
		zerolog.SetGlobalLevel(level)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})
		return nil
	},
}

// Execute is the main entry point called by main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "config.yaml", "Config file path")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "SQLite database path (overrides config)")

	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(reliabilityCmd)
	rootCmd.AddCommand(correlateCmd)
	rootCmd.AddCommand(graphCmd)
	rootCmd.AddCommand(orgintelCmd)
}
