package harvester

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// RapidDNSHarvester queries RapidDNS.io for subdomains.
// RapidDNS is a free passive DNS database — no API key required.
// Endpoint: https://rapiddns.io/subdomain/<domain>?full=1&down=1
// The ?down=1 format returns plain-text results (one per line).
type RapidDNSHarvester struct {
	client *http.Client
	jitter *utils.Jitter
}

func NewRapidDNSHarvester(stealth bool) *RapidDNSHarvester {
	return &RapidDNSHarvester{
		client: &http.Client{Timeout: 25 * time.Second},
		jitter: utils.NewJitter(1500, 0.4, stealth),
	}
}

// Fetch queries RapidDNS for all known subdomains of the domain.
func (h *RapidDNSHarvester) Fetch(ctx context.Context, domain string) ([]string, error) {
	h.jitter.Sleep()

	var results []string
	err := utils.RetryWithBackoff(2, 1500, func() error {
		// Use the CSV-style download endpoint — most stable format
		url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("rapiddns: build request: %w", err)
		}
		req.Header.Set("User-Agent", utils.RandomUA())
		req.Header.Set("Accept", "text/plain,text/html,*/*")
		req.Header.Set("Referer", "https://rapiddns.io/")

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("rapiddns: request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("rapiddns: rate limited (429)")
		}
		if resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("rapiddns: access denied (403)")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("rapiddns: HTTP %d", resp.StatusCode)
		}

		seen := make(map[string]bool)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// RapidDNS ?down=1 format: "subdomain,type,value,date"
			// or plain subdomain per line
			parts := strings.SplitN(line, ",", 2)
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || seen[name] {
				continue
			}
			if strings.HasSuffix(name, "."+domain) || name == domain {
				seen[name] = true
				results = append(results, name)
			}
		}
		return scanner.Err()
	})
	return results, err
}
