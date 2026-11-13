package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"aperture/config"
	"aperture/internal/correlate"
	"aperture/internal/model"
	"aperture/internal/store"
)

var (
	correlateDomain string
	showFingerprints bool
)

var correlateCmd = &cobra.Command{
	Use:   "correlate",
	Short: "Detect and display cross-target infrastructure correlations",
	Long: `Discovers and displays implicit organizational links across distinct root domains,
such as shared TLS certificate SANs, shared /24 hosting subnets, and CDN infrastructure.

Examples:
  aperture correlate
  aperture correlate --domain github.com
  aperture correlate --fingerprints`,
	RunE: runCorrelate,
}

func init() {
	correlateCmd.Flags().StringVarP(&correlateDomain, "domain", "d", "", "Filter correlations by root domain (optional)")
	correlateCmd.Flags().BoolVar(&showFingerprints, "fingerprints", false, "Display extracted infrastructure fingerprints")
}

func runCorrelate(cmd *cobra.Command, args []string) error {
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eng := correlate.NewEngine(db)

	if showFingerprints {
		fps, err := db.GetFingerprints(ctx, correlateDomain)
		if err != nil {
			return fmt.Errorf("querying fingerprints: %w", err)
		}
		if len(fps) == 0 {
			fmt.Println("No infrastructure fingerprints stored yet. Run 'aperture discover' first.")
			return nil
		}

		// Auto-enrich any fingerprints missing ASN
		for _, fp := range fps {
			if fp.ASN == 0 && len(fp.ResolvedIPs) > 0 {
				for _, ip := range fp.ResolvedIPs {
					asnNum, asOrg, err := model.LookupASN(ip)
					if err == nil && asnNum > 0 {
						fp.ASN = asnNum
						fp.ASOrg = asOrg
						_ = db.SaveFingerprint(ctx, fp)
						break
					}
				}
			}
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
		fmt.Fprintln(w, "ASSET ID\tROOT DOMAIN\tASN\tAS ORG\tSUBNET /24\tCDN\tSAN COUNT\tEXTRACTED AT")
		for _, fp := range fps {
			subnets := strings.Join(fp.IPRanges24, ",")
			if subnets == "" {
				subnets = "-"
			}
			cdns := strings.Join(fp.CDNProviders, ",")
			if cdns == "" {
				cdns = "-"
			}
			asnStr := "-"
			if fp.ASN > 0 {
				asnStr = fmt.Sprintf("AS%d", fp.ASN)
			}
			asOrg := fp.ASOrg
			if asOrg == "" {
				asOrg = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
				fp.AssetID,
				fp.RootDomain,
				asnStr,
				asOrg,
				subnets,
				cdns,
				len(fp.SANList),
				fp.ExtractedAt.Format("2006-01-02 15:04"),
			)
		}
		return w.Flush()
	}

	// 1. Run live correlation calculation across all stored fingerprints
	_, err = eng.Correlate(ctx, correlateDomain)
	if err != nil {
		return fmt.Errorf("running correlation engine: %w", err)
	}

	// 2. Query and display all stored correlations
	corrs, err := db.ListCorrelations(ctx, correlateDomain)
	if err != nil {
		return fmt.Errorf("listing correlations: %w", err)
	}

	if len(corrs) == 0 {
		fmt.Println("No cross-target infrastructure correlations detected yet.")
		fmt.Println("Run 'aperture discover' across multiple domains (e.g. github.com and github.io) to detect shared TLS certificates and hosting infrastructure.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
	fmt.Fprintln(w, "DOMAIN A\tDOMAIN B\tCORRELATION TYPE\tSHARED ELEMENT\tCONFIDENCE\tDISCOVERED")
	for _, c := range corrs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%.2f\t%s\n",
			c.RootDomainA,
			c.RootDomainB,
			c.CorrelationType,
			c.SharedElement,
			c.Confidence,
			c.DiscoveredAt.Format("2006-01-02 15:04"),
		)
	}
	return w.Flush()
}
