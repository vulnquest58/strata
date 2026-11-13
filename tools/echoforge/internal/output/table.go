package output

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/echoforge/echoforge/internal/model"
	"github.com/echoforge/echoforge/internal/scorer"
)

// PrintTable renders a premium terminal table: resolved section first, then unresolved.
func PrintTable(result *model.ScanResult) {
	// Split into resolved and unresolved
	var resolved, unresolved []model.Subdomain
	for _, s := range result.Subdomains {
		if s.Resolves {
			resolved = append(resolved, s)
		} else {
			unresolved = append(unresolved, s)
		}
	}

	// Sort each group by confidence descending
	sortByConf := func(subs []model.Subdomain) {
		sort.Slice(subs, func(i, j int) bool {
			return subs[i].Confidence > subs[j].Confidence
		})
	}
	sortByConf(resolved)
	sortByConf(unresolved)

	if len(resolved) > 0 {
		fmt.Printf("\n  \033[1m\033[32m✓ RESOLVED  (%d subdomains)\033[0m\n\n", len(resolved))
		renderSection(resolved)
	}

	if len(unresolved) > 0 {
		fmt.Printf("\n  \033[2m✗ UNRESOLVED / PASSIVE  (%d subdomains)\033[0m\n\n", len(unresolved))
		renderSectionDim(unresolved)
	}
}

// renderSection renders a full-color table row for resolved results.
func renderSection(subs []model.Subdomain) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Subdomain", "Confidence", "Level", "Source", "HTTP", "TLS", "IPs"})
	table.SetBorder(false)
	table.SetColumnSeparator("│")
	table.SetCenterSeparator("┼")
	table.SetRowSeparator("─")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(true)
	table.SetAutoWrapText(false)

	for _, sub := range subs {
		cat := scorer.Category(sub.Confidence)
		httpStr := "-"
		if sub.HTTPStatus > 0 {
			httpStr = fmt.Sprintf("%d", sub.HTTPStatus)
		}
		tls := "✗"
		if sub.TLSSANMatch {
			tls = "✓"
		}
		ips := "-"
		if len(sub.IPAddresses) > 0 {
			ips = sub.IPAddresses[0]
			if len(sub.IPAddresses) > 1 {
				ips += fmt.Sprintf(" +%d", len(sub.IPAddresses)-1)
			}
		}
		confStr := fmt.Sprintf("%.1f%%", sub.Confidence)

		row := []string{sub.Name, confStr, cat, sub.Source, httpStr, tls, ips}
		colors := make([]tablewriter.Colors, 7)
		for i := range colors {
			colors[i] = tablewriter.Colors{}
		}
		switch cat {
		case "HIGH":
			colors[0] = tablewriter.Colors{tablewriter.FgGreenColor}
			colors[1] = tablewriter.Colors{tablewriter.FgGreenColor, tablewriter.Bold}
			colors[2] = tablewriter.Colors{tablewriter.FgGreenColor, tablewriter.Bold}
		case "MEDIUM":
			colors[0] = tablewriter.Colors{tablewriter.FgYellowColor}
			colors[1] = tablewriter.Colors{tablewriter.FgYellowColor}
			colors[2] = tablewriter.Colors{tablewriter.FgYellowColor}
		case "LOW":
			colors[0] = tablewriter.Colors{tablewriter.FgCyanColor}
			colors[1] = tablewriter.Colors{tablewriter.FgCyanColor}
		}
		table.Rich(row, colors)
	}
	table.Render()
}

// renderSectionDim renders a compact, dim table for unresolved candidates.
func renderSectionDim(subs []model.Subdomain) {
	// Limit display to top 30 unresolved to avoid wall-of-text
	limit := len(subs)
	if limit > 30 {
		limit = 30
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Subdomain", "Confidence", "Source"})
	table.SetBorder(false)
	table.SetColumnSeparator("│")
	table.SetCenterSeparator("┼")
	table.SetRowSeparator("─")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(true)
	table.SetAutoWrapText(false)

	for _, sub := range subs[:limit] {
		confStr := fmt.Sprintf("%.1f%%", sub.Confidence)
		row := []string{sub.Name, confStr, sub.Source}
		table.Rich(row, []tablewriter.Colors{
			{tablewriter.FgHiBlackColor},
			{tablewriter.FgHiBlackColor},
			{tablewriter.FgHiBlackColor},
		})
	}
	table.Render()

	if len(subs) > 30 {
		fmt.Printf("\n  \033[2m… %d more unresolved (use --output json/csv to see all)\033[0m\n", len(subs)-30)
	}
}

// PrintBanner prints the EchoForge ASCII art banner.
func PrintBanner() {
	banner := `
  ███████╗ ██████╗██╗  ██╗ ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██╔════╝██║  ██║██╔═══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  █████╗  ██║     ███████║██║   ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
  ██╔══╝  ██║     ██╔══██║██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
  ███████╗╚██████╗██║  ██║╚██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

  ⚡ Evolutionary Echo Discovery Engine  │  v1.0.0
  🔮 Philosophy: "The Shadow Approach" — Discover without a trace
  ────────────────────────────────────────────────────────────────────────────
`
	fmt.Print(banner)
}

// PrintSummary prints a formatted scan summary box.
func PrintSummary(result *model.ScanResult) {
	high, medium, low := 0, 0, 0
	resolved := 0
	wildcard := 0
	for _, s := range result.Subdomains {
		if s.Resolves {
			resolved++
		}
		if s.Wildcard {
			wildcard++
		}
		switch scorer.Category(s.Confidence) {
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	wildcardLine := ""
	if wildcard > 0 {
		wildcardLine = fmt.Sprintf("  │  ⚠  Wildcard filtered: %-38d│\n", wildcard)
	}

	lines := []string{
		"",
		"  ┌─────────────────────── SCAN SUMMARY ───────────────────────────┐",
		fmt.Sprintf("  │  Target Domain  : %-45s│", result.Domain),
		fmt.Sprintf("  │  Scan ID        : %-45s│", result.ScanID),
		fmt.Sprintf("  │  Duration       : %-45s│", result.Duration),
		"  ├─────────────────────────────────────────────────────────────────┤",
		fmt.Sprintf("  │  Total Found    : %-45d│", result.TotalDiscovered),
		fmt.Sprintf("  │  DNS Resolved   : %-45d│", resolved),
		wildcardLine + "  ├─────────────────────────────────────────────────────────────────┤",
		fmt.Sprintf("  │  🟢 HIGH (≥80)  : %-45d│", high),
		fmt.Sprintf("  │  🟡 MEDIUM (≥50): %-45d│", medium),
		fmt.Sprintf("  │  🔵 LOW (≥25)   : %-45d│", low),
		"  └─────────────────────────────────────────────────────────────────┘",
		"",
	}

	fmt.Println(strings.Join(lines, "\n"))
}
