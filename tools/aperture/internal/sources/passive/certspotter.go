package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aperture/internal/model"
	"aperture/internal/sources"
)

// CertSpotter queries the SSLMate CertSpotter CT log API for certificate issuances.
// It complies strictly with all 5 source plugin architectural layers:
// 1. Strict response struct contract.
// 2. Mandatory hostname sanitization (RFC 1035 / wildcard strip / malformation check).
// 3. Absolute zero IP leakage at the plugin level (IP resolution left solely to consensus engine).
// 4. Proactive rate limiting and graceful 429 backoff handling.
// 5. Objective evaluation and standard prior reliability.
type CertSpotter struct {
	client  *http.Client
	baseURL string
	apiKey  string
	limiter *RateLimiter
}

// NewCertSpotter creates a new CertSpotter plugin instance.
func NewCertSpotter(timeoutSecs int, apiKey string) *CertSpotter {
	if timeoutSecs <= 0 {
		timeoutSecs = 15
	}
	return &CertSpotter{
		client:  &http.Client{Timeout: time.Duration(timeoutSecs) * time.Second},
		baseURL: "https://api.certspotter.com/v1/issuances",
		apiKey:  apiKey,
		limiter: NewRateLimiter(2 * time.Second), // Proactively pace requests
	}
}

// SetBaseURL overrides the base URL (primarily for testing with mock HTTP servers).
func (c *CertSpotter) SetBaseURL(url string) {
	c.baseURL = url
}

func (c *CertSpotter) Name() string                    { return "certspotter" }
func (c *CertSpotter) Category() model.SourceCategory  { return model.SourcePassive }
func (c *CertSpotter) DefaultPriorReliability() float64 { return 0.50 }

// certSpotterIssuance is the strict response contract for CertSpotter CT records.
type certSpotterIssuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Revoked   bool     `json:"revoked"`
}

// Discover executes passive discovery of subdomains for the target via CertSpotter.
func (c *CertSpotter) Discover(ctx context.Context, target string) (<-chan sources.RawCandidate, error) {
	out := make(chan sources.RawCandidate, 128)

	go func() {
		defer close(out)

		target = strings.TrimSpace(strings.ToLower(target))
		if target == "" {
			return
		}

		// Layer 4: Proactive throttling before making request
		if err := c.limiter.Throttle(ctx); err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("certspotter: throttling cancelled: %w", err)}
			return
		}

		endpoint := fmt.Sprintf("%s?domain=%s&include_subdomains=true&expand=dns_names", c.baseURL, target)

		var resp *http.Response
		var err error

		maxAttempts := 3
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if reqErr != nil {
				out <- sources.RawCandidate{Error: fmt.Errorf("certspotter: building request: %w", reqErr)}
				return
			}

			req.Header.Set("Accept", "application/json")
			req.Header.Set("User-Agent", "Aperture/1.0 (OSINT; bug-bounty-recon)")
			if c.apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+c.apiKey)
			}

			resp, err = c.client.Do(req)
			if err != nil {
				out <- sources.RawCandidate{Error: fmt.Errorf("certspotter: HTTP request: %w", err)}
				return
			}

			if resp.StatusCode == http.StatusTooManyRequests {
				resp.Body.Close()
				if attempt == maxAttempts {
					out <- sources.RawCandidate{Error: fmt.Errorf("certspotter: rate limit exceeded (429), unavailable this run")}
					return
				}

				retryAfter := 3 * time.Second
				if ra := resp.Header.Get("Retry-After"); ra != "" {
					if secs, parseErr := strconv.Atoi(ra); parseErr == nil && secs > 0 {
						retryAfter = time.Duration(secs) * time.Second
					}
				}

				select {
				case <-time.After(retryAfter):
					continue
				case <-ctx.Done():
					out <- sources.RawCandidate{Error: ctx.Err()}
					return
				}
			}

			break
		}

		if resp == nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("certspotter: nil response")}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			out <- sources.RawCandidate{Error: fmt.Errorf("certspotter: unexpected status %d", resp.StatusCode)}
			return
		}

		// Layer 1: Strict unmarshaling into typed slice
		var issuances []certSpotterIssuance
		if err := json.NewDecoder(resp.Body).Decode(&issuances); err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("certspotter: decoding JSON response: %w", err)}
			return
		}

		seen := make(map[string]bool)
		for _, entry := range issuances {
			for _, rawDNS := range entry.DNSNames {
				// Layer 2: Strict sanitization and RFC 1035 validation
				hostname, ok := SanitizeHostname(rawDNS, target)
				if !ok || seen[hostname] {
					continue
				}
				seen[hostname] = true

				// Layer 3: No IP leakage in candidate metadata/evidence
				candidate := sources.RawCandidate{
					AssetID:      hostname,
					SourcePlugin: c.Name(),
					AssetType:    model.AssetSubdomain,
					RawScore:     70.0,
					Evidence: map[string]any{
						"source":     "certspotter",
						"cert_id":   entry.ID,
						"not_before": entry.NotBefore,
						"not_after":  entry.NotAfter,
					},
				}

				select {
				case <-ctx.Done():
					return
				case out <- candidate:
				}
			}
		}
	}()

	return out, nil
}
