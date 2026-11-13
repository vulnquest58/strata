package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"aperture/config"
	"aperture/internal/store"
)

var relSource string

var reliabilityCmd = &cobra.Command{
	Use:   "reliability",
	Short: "Show the accumulated reliability record for a source plugin",
	Long: `Displays the Bayesian reliability history for the specified source,
including total findings, confirmed live/dead, reliability score, and sample size.

Example:
  aperture reliability --source crtsh --show`,
	RunE: runReliability,
}

func init() {
	reliabilityCmd.Flags().StringVar(&relSource, "source", "", "Source plugin name to inspect (required)")
	reliabilityCmd.Flags().Bool("show", true, "Show reliability records (currently the only action)")
	reliabilityCmd.MarkFlagRequired("source")
}

func runReliability(cmd *cobra.Command, args []string) error {
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

	records, err := db.ListReliability(context.Background(), relSource)
	if err != nil {
		return fmt.Errorf("querying reliability records: %w", err)
	}

	if len(records) == 0 {
		fmt.Printf("No reliability data yet for source %q.\n", relSource)
		fmt.Println("Run a scan first, then 'aperture verify' to populate reliability data.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PATTERN\tTOTAL\tLIVE\tDEAD\tSAMPLE\tSCORE\tLAST UPDATED")
	fmt.Fprintln(w, "-------\t-----\t----\t----\t------\t-----\t------------")
	for _, r := range records {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%.3f\t%s\n",
			r.TargetDomainPattern,
			r.TotalFindings,
			r.ConfirmedLive,
			r.ConfirmedDead,
			r.SampleSize,
			r.ReliabilityScore,
			r.LastUpdated.Format(time.RFC3339),
		)
	}
	return w.Flush()
}
