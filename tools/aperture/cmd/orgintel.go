package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"aperture/config"
	"aperture/internal/model"
	"aperture/internal/orgintel"
	"aperture/internal/store"

	"github.com/spf13/cobra"
)

var (
	orgintelDomain  string
	orgintelCompare string
	orgintelOutput  string
)

var orgintelCmd = &cobra.Command{
	Use:   "orgintel",
	Short: "Discover organizational identity and corporate affiliations via WHOIS/RDAP",
	Long: `orgintel queries domain registration identity (RDAP/WHOIS) to discover corporate
affiliations and legal ownership links that do not share physical infrastructure.
Includes noise-floor filtering to eliminate False Positives from privacy proxies.`,
	RunE: runOrgintel,
}

func init() {
	orgintelCmd.Flags().StringVarP(&orgintelDomain, "domain", "d", "", "Target domain to look up (required)")
	orgintelCmd.Flags().StringVar(&orgintelCompare, "compare", "", "Comma-separated list of additional domains to compare for corporate affiliation")
	orgintelCmd.Flags().StringVarP(&orgintelOutput, "output", "o", "", "Path to output JSON file")
	_ = orgintelCmd.MarkFlagRequired("domain")
}

func runOrgintel(cmd *cobra.Command, args []string) error {
	domainsToQuery := []string{orgintelDomain}
	if orgintelCompare != "" {
		parts := strings.Split(orgintelCompare, ",")
		for _, p := range parts {
			clean := strings.TrimSpace(p)
			if clean != "" && !contains(domainsToQuery, clean) {
				domainsToQuery = append(domainsToQuery, clean)
			}
		}
	}

	var identities []orgintel.OrgIdentity
	fmt.Fprintf(os.Stderr, "[*] Querying RDAP organizational identity for %d domain(s)...\n", len(domainsToQuery))

	for _, d := range domainsToQuery {
		id, err := orgintel.LookupOrgIdentity(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error querying %s: %v\n", d, err)
			identities = append(identities, orgintel.OrgIdentity{
				Domain:         d,
				IsPrivacyProxy: true,
				Source:         "icann_rdap_whois",
			})
			continue
		}
		identities = append(identities, *id)
	}

	affiliations := orgintel.CorrelateOrganizations(identities)

	// Render Table
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tREGISTRANT ORG\tREGISTRAR\tPROXY/PRIVACY\tCONFIDENCE")
	fmt.Fprintln(w, "------\t--------------\t---------\t-------------\t----------")

	for _, id := range identities {
		proxyStr := "No (Genuine Org)"
		if id.IsPrivacyProxy {
			proxyStr = "YES (Proxy/Redacted)"
		}
		org := id.RegistrantOrg
		if org == "" {
			org = "<redacted / not published>"
		}
		reg := id.RegistrarWHOIS
		if reg == "" {
			reg = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%.2f\n", id.Domain, org, reg, proxyStr, id.Confidence)
	}
	w.Flush()
	fmt.Println()

	if len(affiliations) > 0 {
		fmt.Println("================================================================================")
		fmt.Println("       CONFIRMED CORPORATE AFFILIATIONS (Non-Infrastructure Registry Identity)")
		fmt.Println("================================================================================")
		for _, aff := range affiliations {
			fmt.Printf("[+] %s <---> %s\n", aff.DomainA, aff.DomainB)
			fmt.Printf("    * Matched Organization: %s\n", aff.MatchedOrg)
			fmt.Printf("    * Confidence:           %.2f\n", aff.Confidence)
			if aff.RegistrarA != "" || aff.RegistrarB != "" {
				fmt.Printf("    * Registrars:           %s / %s\n", aff.RegistrarA, aff.RegistrarB)
			}
			fmt.Println()
		}

		// Persist discovered affiliations to database for graph correlation
		cfg, err := config.Load(configFile)
		if err == nil {
			if dbPath != "" {
				cfg.Storage.DatabasePath = dbPath
			}
			if db, err := store.Open(cfg.Storage.DatabasePath); err == nil {
				defer db.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				for _, aff := range affiliations {
					a, b := aff.DomainA, aff.DomainB
					if a > b {
						a, b = b, a
					}
					corr := &model.CrossTargetCorrelation{
						ID:              fmt.Sprintf("corp_aff_%s_%s", a, b),
						RootDomainA:     a,
						RootDomainB:     b,
						AssetA:          a,
						AssetB:          b,
						CorrelationType: "corporate_affiliation",
						SharedElement:   aff.MatchedOrg,
						Confidence:      aff.Confidence,
						Evidence: map[string]any{
							"matched_org": aff.MatchedOrg,
							"registrar_a": aff.RegistrarA,
							"registrar_b": aff.RegistrarB,
							"source":      "icann_rdap_whois",
						},
						DiscoveredAt: time.Now(),
					}
					_ = db.SaveCorrelation(ctx, corr)
				}
			}
		}
	} else if len(domainsToQuery) > 1 {
		fmt.Println("[*] No corporate affiliations discovered between specified domains.")
	}

	if orgintelOutput != "" {
		outData := map[string]any{
			"identities":   identities,
			"affiliations": affiliations,
		}
		bytes, err := json.MarshalIndent(outData, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling json: %w", err)
		}
		if err := os.WriteFile(orgintelOutput, bytes, 0644); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Results successfully exported to %s\n", orgintelOutput)
	}

	return nil
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
