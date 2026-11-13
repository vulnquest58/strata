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

// HackerTarget queries the HackerTarget.com free API for host search results.
// Returns a CSV list of hostname,IP pairs. No API key required (rate-limited to ~100 req/day).
type HackerTarget struct {
	client *http.Client
}

func NewHackerTarget(timeoutSecs int) *HackerTarget {
	return &HackerTarget{
		client: &http.Client{Timeout: time.Duration(timeoutSecs) * time.Second},
	}
}

func (h *HackerTarget) Name() string                    { return "hackertarget" }
func (h *HackerTarget) Category() model.SourceCategory  { return model.SourcePassive }
func (h *HackerTarget) DefaultPriorReliability() float64 { return 0.60 }

func (h *HackerTarget) Discover(ctx context.Context, target string) (<-chan sources.RawCandidate, error) {
	out := make(chan sources.RawCandidate, 128)

	go func() {
		defer close(out)

		url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", target)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("hackertarget: building request: %w", err)}
			return
		}
		req.Header.Set("User-Agent", "Aperture/1.0 (OSINT; bug-bounty-recon)")

		resp, err := h.client.Do(req)
		if err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("hackertarget: HTTP request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			out <- sources.RawCandidate{Error: fmt.Errorf("hackertarget: status %d", resp.StatusCode)}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		seen := make(map[string]bool)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "API") {
				// HackerTarget returns "API count exceeded" or similar error strings.
				if strings.Contains(strings.ToLower(line), "error") || strings.Contains(line, "exceeded") {
					out <- sources.RawCandidate{Error: fmt.Errorf("hackertarget: API limit: %s", line)}
					return
				}
				continue
			}

			parts := strings.SplitN(line, ",", 2)
			if len(parts) < 1 {
				continue
			}
			hostname, ok := SanitizeHostname(parts[0], target)
			if !ok || seen[hostname] {
				continue
			}
			seen[hostname] = true

			// Layer 3: No IP leakage at plugin level — IP resolution belongs solely to consensus engine
			evidence := map[string]any{"source": "hackertarget_hostsearch"}

			select {
			case <-ctx.Done():
				return
			case out <- sources.RawCandidate{
				AssetID:      hostname,
				SourcePlugin: h.Name(),
				AssetType:    model.AssetSubdomain,
				RawScore:     70.0,
				Evidence:     evidence,
			}:
			}
		}

		if err := scanner.Err(); err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("hackertarget: reading response: %w", err)}
		}
	}()

	return out, nil
}
