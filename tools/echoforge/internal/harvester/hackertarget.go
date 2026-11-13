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

// HackerTargetHarvester queries the HackerTarget free API for subdomains.
// No API key required. Limit: 100 queries/day per IP on the free tier.
// Endpoint: https://api.hackertarget.com/hostsearch/?q=<domain>
// Response: plain text, one "hostname,ip" pair per line.
type HackerTargetHarvester struct {
	client *http.Client
	jitter *utils.Jitter
}

func NewHackerTargetHarvester(stealth bool) *HackerTargetHarvester {
	return &HackerTargetHarvester{
		client: &http.Client{Timeout: 20 * time.Second},
		jitter: utils.NewJitter(1500, 0.4, stealth),
	}
}

// Fetch queries HackerTarget API for hostname→IP records of the domain.
func (h *HackerTargetHarvester) Fetch(ctx context.Context, domain string) ([]string, error) {
	h.jitter.Sleep()

	var results []string
	err := utils.RetryWithBackoff(2, 1500, func() error {
		url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("hackertarget: build request: %w", err)
		}
		req.Header.Set("User-Agent", utils.RandomUA())

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("hackertarget: request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("hackertarget: rate limited (429)")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("hackertarget: HTTP %d", resp.StatusCode)
		}

		seen := make(map[string]bool)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "error") || strings.HasPrefix(line, "API") {
				// HackerTarget returns "error check your search term" or "API count exceeded"
				if strings.Contains(line, "exceeded") || strings.Contains(line, "limit") {
					return fmt.Errorf("hackertarget: %s", line)
				}
				continue
			}
			// Format: "subdomain.example.com,1.2.3.4"
			parts := strings.SplitN(line, ",", 2)
			if len(parts) == 0 {
				continue
			}
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
