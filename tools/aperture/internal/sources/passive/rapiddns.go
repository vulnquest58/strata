package passive

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"aperture/internal/model"
	"aperture/internal/sources"
)

// RapidDNS queries rapiddns.io for subdomain enumeration.
// Uses the web endpoint with a plain-text style response.
type RapidDNS struct {
	client *http.Client
}

func NewRapidDNS(timeoutSecs int) *RapidDNS {
	return &RapidDNS{
		client: &http.Client{Timeout: time.Duration(timeoutSecs) * time.Second},
	}
}

func (r *RapidDNS) Name() string                    { return "rapiddns" }
func (r *RapidDNS) Category() model.SourceCategory  { return model.SourcePassive }
func (r *RapidDNS) DefaultPriorReliability() float64 { return 0.55 }

func (r *RapidDNS) Discover(ctx context.Context, target string) (<-chan sources.RawCandidate, error) {
	out := make(chan sources.RawCandidate, 128)

	go func() {
		defer close(out)

		// RapidDNS provides a free search endpoint — we use the CSV-like output variant.
		url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", target)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("rapiddns: building request: %w", err)}
			return
		}
		req.Header.Set("User-Agent", "Aperture/1.0 (OSINT; bug-bounty-recon)")

		resp, err := r.client.Do(req)
		if err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("rapiddns: HTTP request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			out <- sources.RawCandidate{Error: fmt.Errorf("rapiddns: status %d", resp.StatusCode)}
			return
		}

		seen := make(map[string]bool)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// CSV format: subdomain,type,value,ttl
			parts := strings.SplitN(line, ",", 4)
			if len(parts) < 1 {
				continue
			}
			hostname, ok := SanitizeHostname(parts[0], target)
			if !ok || seen[hostname] {
				continue
			}
			seen[hostname] = true

			evidence := map[string]any{"source": "rapiddns"}
			if len(parts) >= 2 {
				recType := strings.ToUpper(strings.TrimSpace(parts[1]))
				evidence["record_type"] = recType
				// Layer 3: Omit IPs from evidence to prevent conflict with consensus engine
				if len(parts) >= 3 && recType != "A" && recType != "AAAA" {
					evidence["record_value"] = strings.TrimSpace(parts[2])
				}
			}

			select {
			case <-ctx.Done():
				return
			case out <- sources.RawCandidate{
				AssetID:      hostname,
				SourcePlugin: r.Name(),
				AssetType:    model.AssetSubdomain,
				RawScore:     65.0,
				Evidence:     evidence,
			}:
			}
		}
	}()

	return out, nil
}
