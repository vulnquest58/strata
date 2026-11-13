package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/echoforge/echoforge/internal/model"
	"github.com/echoforge/echoforge/internal/scorer"
)

// WriteJSON writes the full scan result as a formatted JSON file.
func WriteJSON(result *model.ScanResult, path string) error {
	// Sort by confidence descending
	sort.Slice(result.Subdomains, func(i, j int) bool {
		return result.Subdomains[i].Confidence > result.Subdomains[j].Confidence
	})

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("json: marshal: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("json: write: %w", err)
	}
	return nil
}

// PrintJSONLive streams discovered subdomains to stdout as newline-delimited JSON.
func PrintJSONLive(sub model.Subdomain) {
	data, err := json.Marshal(sub)
	if err != nil {
		return
	}
	fmt.Println(string(data))
}

// SummaryJSON prints a brief summary after the scan.
func SummaryJSON(result *model.ScanResult) {
	high := 0
	for _, s := range result.Subdomains {
		if scorer.Category(s.Confidence) == "HIGH" {
			high++
		}
	}
	fmt.Printf(`
{
  "scan_summary": {
    "domain": "%s",
    "total": %d,
    "resolved": %d,
    "high_confidence": %d,
    "duration": "%s"
  }
}
`, result.Domain, result.TotalDiscovered, result.TotalResolved, high, result.Duration)
}
