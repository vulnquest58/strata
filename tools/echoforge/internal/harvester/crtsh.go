package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// crtshEntry represents a single entry from crt.sh JSON API.
type crtshEntry struct {
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
}

// CRTSHHarvester fetches subdomains from Certificate Transparency logs.
// Primary endpoint: crt.sh
// Fallback endpoint: certspotter.com (alternative CT log aggregator)
type CRTSHHarvester struct {
	client *http.Client
	jitter *utils.Jitter
}

func NewCRTSHHarvester(stealth bool) *CRTSHHarvester {
	return &CRTSHHarvester{
		client: &http.Client{Timeout: 30 * time.Second},
		jitter: utils.NewJitter(2000, 0.5, stealth),
	}
}

// parseCRTSHEntries extracts subdomains from crt.sh JSON entries.
func parseCRTSHEntries(entries []crtshEntry, domain string) []string {
	seen := make(map[string]bool)
	var results []string
	for _, e := range entries {
		names := strings.Split(e.NameValue, "\n")
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || seen[name] {
				continue
			}
			if strings.HasSuffix(name, "."+domain) || name == domain {
				seen[name] = true
				results = append(results, name)
			}
		}
	}
	return results
}

// Fetch queries CT logs for all certificate SANs matching the domain.
// Tries crt.sh first (3 retries), then falls back to certspotter.com.
func (h *CRTSHHarvester) Fetch(ctx context.Context, domain string) ([]string, error) {
	h.jitter.Sleep()

	var results []string
	var primaryErr error

	// ── PRIMARY: crt.sh ──────────────────────────────────────────────
	primaryErr = utils.RetryWithBackoff(3, 1000, func() error {
		url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("crt.sh: build request: %w", err)
		}
		req.Header.Set("User-Agent", utils.RandomUA())
		req.Header.Set("Accept", "application/json")

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("crt.sh: request: %w", err)
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			return fmt.Errorf("crt.sh: rate limited (429) — try again later")
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return fmt.Errorf("crt.sh: upstream error (%d) — server overloaded", resp.StatusCode)
		case http.StatusNotFound:
			// 404 from crt.sh means domain not found (no certs) — not a real error
			results = nil
			return nil
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("crt.sh: HTTP %d", resp.StatusCode)
		}

		var entries []crtshEntry
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			return fmt.Errorf("crt.sh: decode: %w", err)
		}
		results = parseCRTSHEntries(entries, domain)
		return nil
	})

	if primaryErr == nil {
		return results, nil
	}

	// ── FALLBACK: certspotter.com (Cert Spotter CT API) ──────────────
	// Only attempt if the primary truly failed (not just 404/empty)
	fallbackErr := utils.RetryWithBackoff(2, 1500, func() error {
		url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("certspotter: build request: %w", err)
		}
		req.Header.Set("User-Agent", utils.RandomUA())
		req.Header.Set("Accept", "application/json")

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("certspotter: request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("certspotter: rate limited (429)")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("certspotter: HTTP %d", resp.StatusCode)
		}

		// Certspotter returns: [{"dns_names": ["a.domain.com", "b.domain.com"]}, ...]
		var issuances []struct {
			DNSNames []string `json:"dns_names"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&issuances); err != nil {
			return fmt.Errorf("certspotter: decode: %w", err)
		}

		seen := make(map[string]bool)
		for _, iss := range issuances {
			for _, name := range iss.DNSNames {
				name = strings.ToLower(strings.TrimSpace(name))
				name = strings.TrimPrefix(name, "*.")
				if name == "" || seen[name] {
					continue
				}
				if strings.HasSuffix(name, "."+domain) || name == domain {
					seen[name] = true
					results = append(results, name)
				}
			}
		}
		return nil
	})

	if fallbackErr != nil {
		// Both failed — return the primary error with fallback info
		return nil, fmt.Errorf("crt.sh unavailable (%w); certspotter also failed: %v",
			primaryErr, fallbackErr)
	}

	// Fallback succeeded
	return results, nil
}
