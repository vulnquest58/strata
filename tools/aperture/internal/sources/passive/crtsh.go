package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"aperture/internal/model"
	"aperture/internal/sources"
)

// CrtSh is the crt.sh Certificate Transparency log source plugin.
// It queries the public JSON API which aggregates certificates from all major CT logs.
// No API key required. Rate limit: be polite — single request per scan.
type CrtSh struct {
	client *http.Client
}

// NewCrtSh creates a new crt.sh plugin with the given HTTP timeout.
func NewCrtSh(timeoutSecs int) *CrtSh {
	return &CrtSh{
		client: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
		},
	}
}

func (c *CrtSh) Name() string                    { return "crtsh" }
func (c *CrtSh) Category() model.SourceCategory  { return model.SourcePassive }
func (c *CrtSh) DefaultPriorReliability() float64 { return 0.75 } // CT logs have excellent coverage

// Discover queries crt.sh for certificate transparency records for the given domain,
// emitting one RawCandidate per unique subdomain discovered.
func (c *CrtSh) Discover(ctx context.Context, target string) (<-chan sources.RawCandidate, error) {
	out := make(chan sources.RawCandidate, 256)

	go func() {
		defer close(out)

		url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("crtsh: building request: %w", err)}
			return
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Aperture/1.0 (OSINT; bug-bounty-recon)")

		resp, err := c.client.Do(req)
		if err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("crtsh: HTTP request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			out <- sources.RawCandidate{Error: fmt.Errorf("crtsh: unexpected status %d", resp.StatusCode)}
			return
		}

		var entries []crtShEntry
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("crtsh: decoding JSON: %w", err)}
			return
		}

		seen := make(map[string]bool)
		for _, entry := range entries {
			// name_value may contain multiple names separated by newlines.
			for _, rawName := range strings.Split(entry.NameValue, "\n") {
				name, ok := SanitizeHostname(rawName, target)
				if !ok || seen[name] {
					continue
				}
				seen[name] = true

				select {
				case <-ctx.Done():
					return
				case out <- sources.RawCandidate{
					AssetID:      name,
					SourcePlugin: c.Name(),
					AssetType:    model.AssetSubdomain,
					RawScore:     85.0,
					Evidence: map[string]any{
						"issuer_name":  entry.IssuerName,
						"not_before":   entry.NotBefore,
						"not_after":    entry.NotAfter,
						"crtsh_id":     entry.ID,
						"logged_at":    entry.LoggedAt,
					},
				}:
				}
			}
		}
	}()

	return out, nil
}

// crtShEntry mirrors the JSON structure returned by crt.sh/?output=json
type crtShEntry struct {
	ID         int64  `json:"id"`
	LoggedAt   string `json:"logged_at"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
}
