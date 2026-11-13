package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/echoforge/echoforge/internal/model"
)

// WriteCSV writes the scan result as a CSV file with headers.
func WriteCSV(result *model.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("csv: create: %w", err)
	}
	defer f.Close()

	// Sort by confidence descending
	sort.Slice(result.Subdomains, func(i, j int) bool {
		return result.Subdomains[i].Confidence > result.Subdomains[j].Confidence
	})

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	if err := w.Write([]string{
		"subdomain", "confidence", "source", "resolves",
		"ip_addresses", "http_status", "server",
		"tls_san_match", "echo_depth", "echo_from",
	}); err != nil {
		return err
	}

	for _, sub := range result.Subdomains {
		row := []string{
			sub.Name,
			strconv.FormatFloat(sub.Confidence, 'f', 1, 64),
			sub.Source,
			strconv.FormatBool(sub.Resolves),
			strings.Join(sub.IPAddresses, ";"),
			strconv.Itoa(sub.HTTPStatus),
			sub.ServerHeader,
			strconv.FormatBool(sub.TLSSANMatch),
			strconv.Itoa(sub.EchoDepth),
			strings.Join(sub.EchoFrom, ";"),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	return nil
}
