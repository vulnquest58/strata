package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"aperture/config"
	"aperture/internal/graph"
	"aperture/internal/store"
)

var (
	graphRoot           string
	graphDepth          int
	graphFormat         string
	graphOutput         string
	graphMinConfidence  float64
	graphClassification string
	graphOrgOnly        bool
	graphSummary        bool
)

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Build and query the unified attack surface graph",
	Long: `Builds a multi-target attack surface graph from discovered infrastructure fingerprints,
ASNs, CIDRs, and cross-target correlations. Supports BFS traversal to find all connected domains
and exports in JSON, Graphviz DOT, or terminal executive summary formats.`,
	RunE: runGraph,
}

func init() {
	graphCmd.Flags().StringVar(&graphRoot, "root", "github.com", "Seed root domain or asset ID to traverse from")
	graphCmd.Flags().IntVar(&graphDepth, "depth", 2, "Maximum traversal depth (hops)")
	graphCmd.Flags().StringVar(&graphFormat, "format", "dot", "Output format: dot, json, or text")
	graphCmd.Flags().StringVar(&graphOutput, "output", "", "Optional output file path (default stdout)")
	graphCmd.Flags().Float64Var(&graphMinConfidence, "min-confidence", 0.60, "Minimum confidence threshold to include cross-target correlation edges (default 0.60)")
	graphCmd.Flags().StringVar(&graphClassification, "classification", "", "Filter edges by classification: all, high_confidence_org_link, weak_colocation")
	graphCmd.Flags().BoolVar(&graphOrgOnly, "org-only", false, "Strictly traverse through confirmed organizational links (drops weak co-location)")
	graphCmd.Flags().BoolVar(&graphSummary, "summary", false, "Print executive terminal summary table of discovered organizations and topology")
}

func runGraph(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

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

	builder := graph.NewBuilder(db)
	builder.SetMinConfidence(graphMinConfidence)
	g, err := builder.Build(ctx)
	if err != nil {
		return fmt.Errorf("building graph: %w", err)
	}

	// Persist nodes and edges to SQLite graph tables
	if err := builder.PersistToDB(ctx, db.RawDB(), g); err != nil {
		fmt.Fprintf(os.Stderr, "Warning persisting graph to db: %v\n", err)
	}

	// Perform BFS traversal with options
	opts := graph.TraversalOptions{
		MaxDepth:       graphDepth,
		MinConfidence:  graphMinConfidence,
		OnlyOrgLinks:   graphOrgOnly,
		Classification: graph.EdgeClassification(graphClassification),
	}

	sub, err := graph.TraverseBFSOpt(g, graphRoot, opts)
	if err != nil {
		return fmt.Errorf("graph traversal: %w", err)
	}

	if graphSummary || graphFormat == "text" {
		renderGraphSummary(os.Stdout, sub, graphRoot)
		if graphOutput == "" {
			return nil
		}
	}

	var outputBytes []byte
	switch graphFormat {
	case "json":
		data, err := sub.ExportJSON()
		if err != nil {
			return fmt.Errorf("exporting graph json: %w", err)
		}
		outputBytes = data
	case "dot", "text":
		outputBytes = []byte(sub.ExportDOT())
	default:
		return fmt.Errorf("unsupported format %q, use 'dot', 'json', or 'text'", graphFormat)
	}

	if graphOutput != "" {
		if err := os.WriteFile(graphOutput, outputBytes, 0644); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Graph exported to %s (nodes: %d, edges: %d)\n",
			graphOutput, len(sub.Nodes), len(sub.Edges))
		return nil
	}

	if !graphSummary && graphFormat != "text" {
		_, err = os.Stdout.Write(outputBytes)
		return err
	}
	return nil
}

func renderGraphSummary(w io.Writer, sub *graph.SubGraph, seed string) {
	nodeTypes := make(map[graph.NodeType]int)
	for _, n := range sub.Nodes {
		nodeTypes[n.Type]++
	}

	edgeTypes := make(map[graph.EdgeType]int)
	classifications := make(map[graph.EdgeClassification]int)
	var orgLinks []*graph.Edge
	var corpLinks []*graph.Edge

	for _, e := range sub.Edges {
		edgeTypes[e.Type]++
		class := e.Classify()
		classifications[class]++
		if class == graph.ClassHighConfidenceOrgLink && strings.HasPrefix(e.SourceID, "domain:") && strings.HasPrefix(e.TargetID, "domain:") {
			orgLinks = append(orgLinks, e)
		}
		if class == graph.ClassCorporateAffiliation && strings.HasPrefix(e.SourceID, "domain:") && strings.HasPrefix(e.TargetID, "domain:") {
			corpLinks = append(corpLinks, e)
		}
	}

	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "                    APERTURE ATTACK SURFACE INTELLIGENCE")
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "Seed Target:           %s (%s)\n", seed, sub.RootNodeID)
	fmt.Fprintf(w, "Traversal Depth:       %d hops\n", sub.MaxDepth)
	fmt.Fprintf(w, "Total Nodes:           %d\n", len(sub.Nodes))
	fmt.Fprintf(w, "  - Domains:           %d\n", nodeTypes[graph.NodeDomain])
	fmt.Fprintf(w, "  - Assets / Subdomains:%d\n", nodeTypes[graph.NodeAsset])
	fmt.Fprintf(w, "  - Resolved IPs:      %d\n", nodeTypes[graph.NodeIP])
	fmt.Fprintf(w, "  - ASNs / Subnets:    %d ASNs, %d Subnets\n", nodeTypes[graph.NodeASN], nodeTypes[graph.NodeSubnet])
	fmt.Fprintf(w, "Total Edges:           %d\n", len(sub.Edges))
	fmt.Fprintf(w, "  - Structural:        %d (Resolves: %d, Subdomains: %d)\n",
		classifications[graph.ClassStructural], edgeTypes[graph.EdgeResolvesTo], edgeTypes[graph.EdgeSubdomainOf])
	fmt.Fprintf(w, "  - Org Links:         %d (High Confidence Organizational Links)\n", classifications[graph.ClassHighConfidenceOrgLink])
	fmt.Fprintf(w, "  - Corporate Affils:  %d (WHOIS/Registry Corporate Links)\n", classifications[graph.ClassCorporateAffiliation])
	fmt.Fprintf(w, "  - Co-Location:       %d (Weak Infrastructure Overlap)\n", classifications[graph.ClassWeakColocation])
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")

	if len(orgLinks) > 0 {
		fmt.Fprintln(w, "[+] CONFIRMED CORRELATED ORGANIZATIONS (High Confidence Org Links):")
		seenTargets := make(map[string]bool)
		for _, e := range orgLinks {
			target := strings.TrimPrefix(e.TargetID, "domain:")
			if target == seed {
				target = strings.TrimPrefix(e.SourceID, "domain:")
			}
			if !seenTargets[target] {
				seenTargets[target] = true
				corrType := "infrastructure"
				if e.Metadata != nil {
					if ct, ok := e.Metadata["correlation_type"].(string); ok {
						corrType = ct
					}
				}
				fmt.Fprintf(w, "  * %-25s | Conf: %.2f | Type: %-16s | Classification: %s\n",
					target, e.Confidence, e.Type, corrType)
			}
		}
	}

	if len(corpLinks) > 0 {
		fmt.Fprintln(w, "[+] CONFIRMED CORPORATE AFFILIATIONS (Non-Infrastructure Registry Identity):")
		seenCorp := make(map[string]bool)
		for _, e := range corpLinks {
			target := strings.TrimPrefix(e.TargetID, "domain:")
			if target == seed {
				target = strings.TrimPrefix(e.SourceID, "domain:")
			}
			if !seenCorp[target] {
				seenCorp[target] = true
				matchedOrg := ""
				if e.Metadata != nil {
					if mo, ok := e.Metadata["matched_org"].(string); ok {
						matchedOrg = mo
					}
				}
				fmt.Fprintf(w, "  * %-25s | Conf: %.2f | Matched Org: %s\n",
					target, e.Confidence, matchedOrg)
			}
		}
	}

	if len(orgLinks) == 0 && len(corpLinks) == 0 {
		fmt.Fprintln(w, "[*] No external organizational links discovered within current traversal scope.")
	}
	fmt.Fprintln(w, "================================================================================")
}
