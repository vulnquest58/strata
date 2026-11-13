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

// OTXSource queries AlienVault Open Threat Exchange for domain intelligence.
// Default prior reliability is 0.5 (conservative, no special treatment).
type OTXSource struct {
	client  *http.Client
	apiKey  string
	baseURL string
}

// OTX is an alias for backward compatibility.
type OTX = OTXSource

// NewOTX constructs a new OTXSource.
func NewOTX(timeoutSecs int, apiKey string) *OTXSource {
	if timeoutSecs <= 0 {
		timeoutSecs = 15
	}
	return &OTXSource{
		client:  &http.Client{Timeout: time.Duration(timeoutSecs) * time.Second},
		apiKey:  apiKey,
		baseURL: "https://otx.alienvault.com/api/v1/indicators/domain",
	}
}

func (s *OTXSource) Name() string                     { return "otx" }
func (s *OTXSource) Category() model.SourceCategory   { return model.SourcePassive }
func (s *OTXSource) DefaultPriorReliability() float64 { return 0.5 } // محافظ، لا استثناء

func (s *OTXSource) Discover(ctx context.Context, target string) (<-chan sources.RawCandidate, error) {
	out := make(chan sources.RawCandidate, 128)

	go func() {
		defer close(out)

		client := s.client
		if client == nil {
			client = &http.Client{Timeout: 15 * time.Second}
		}

		baseURL := s.baseURL
		if baseURL == "" {
			baseURL = "https://otx.alienvault.com/api/v1/indicators/domain"
		}

		seen := make(map[string]bool)

		// 1. Try passive_dns first (primary OTX passive DNS endpoint)
		passiveURL := fmt.Sprintf("%s/%s/passive_dns", baseURL, target)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, passiveURL, nil)
		if err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("otx: building request: %w", err)}
			return
		}
		if s.apiKey != "" {
			req.Header.Set("X-OTX-API-KEY", s.apiKey)
		}
		req.Header.Set("User-Agent", "Aperture/1.0 (OSINT; bug-bounty-recon)")

		resp, err := client.Do(req)
		var lastErr error
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var result otxPassiveDNSResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && len(result.PassiveDNS) > 0 {
				for _, record := range result.PassiveDNS {
					hostname := strings.ToLower(strings.TrimSpace(record.Hostname))
					if hostname == "" || seen[hostname] {
						continue
					}
					if !strings.HasSuffix(hostname, "."+target) && hostname != target {
						continue
					}
					seen[hostname] = true

					assetType := model.AssetSubdomain
					if record.RecordType == "CNAME" {
						assetType = model.AssetCNAME
					} else if record.RecordType == "MX" {
						assetType = model.AssetMX
					}

					select {
					case <-ctx.Done():
						return
					case out <- sources.RawCandidate{
						AssetID:      hostname,
						SourcePlugin: s.Name(),
						AssetType:    assetType,
						RawScore:     60.0,
						Evidence: map[string]any{
							"record_type": record.RecordType,
							"address":     record.Address,
							"first":       record.First,
							"last":        record.Last,
							"source":      "otx_passive_dns",
						},
					}:
					}
				}
				if len(seen) > 0 {
					return
				}
			}
		} else if resp != nil {
			lastErr = fmt.Errorf("otx: status %d", resp.StatusCode)
			resp.Body.Close()
		} else if err != nil {
			lastErr = fmt.Errorf("otx: HTTP request: %w", err)
		}

		// 2. Fallback to url_list endpoint (publicly accessible on OTX without API key)
		urlListURL := fmt.Sprintf("%s/%s/url_list?limit=500", baseURL, target)
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, urlListURL, nil)
		if err != nil {
			if lastErr != nil {
				out <- sources.RawCandidate{Error: lastErr}
			}
			return
		}
		if s.apiKey != "" {
			req2.Header.Set("X-OTX-API-KEY", s.apiKey)
		}
		req2.Header.Set("User-Agent", "Aperture/1.0 (OSINT; bug-bounty-recon)")

		resp2, err := client.Do(req2)
		if err != nil {
			if lastErr != nil {
				out <- sources.RawCandidate{Error: lastErr}
			} else {
				out <- sources.RawCandidate{Error: fmt.Errorf("otx: HTTP request: %w", err)}
			}
			return
		}
		defer resp2.Body.Close()

		if resp2.StatusCode != http.StatusOK {
			if lastErr != nil {
				out <- sources.RawCandidate{Error: lastErr}
			} else {
				out <- sources.RawCandidate{Error: fmt.Errorf("otx: status %d", resp2.StatusCode)}
			}
			return
		}

		var urlListResult otxURLListResponse
		if err := json.NewDecoder(resp2.Body).Decode(&urlListResult); err != nil {
			out <- sources.RawCandidate{Error: fmt.Errorf("otx: decoding JSON: %w", err)}
			return
		}

		for _, record := range urlListResult.URLList {
			hostname := strings.ToLower(strings.TrimSpace(record.Hostname))
			if hostname == "" || seen[hostname] {
				continue
			}
			if !strings.HasSuffix(hostname, "."+target) && hostname != target {
				continue
			}
			seen[hostname] = true

			evidence := map[string]any{
				"url":    record.URL,
				"source": "otx_url_list",
			}
			if record.Result.URLWorker.IP != "" {
				evidence["resolved_ip"] = record.Result.URLWorker.IP
			}

			select {
			case <-ctx.Done():
				return
			case out <- sources.RawCandidate{
				AssetID:      hostname,
				SourcePlugin: s.Name(),
				AssetType:    model.AssetSubdomain,
				RawScore:     60.0,
				Evidence:     evidence,
			}:
			}
		}
	}()

	return out, nil
}

type otxPassiveDNSResponse struct {
	PassiveDNS []struct {
		Hostname   string `json:"hostname"`
		RecordType string `json:"record_type"`
		Address    string `json:"address"`
		First      string `json:"first"`
		Last       string `json:"last"`
	} `json:"passive_dns"`
}

type otxURLListResponse struct {
	URLList []struct {
		URL      string `json:"url"`
		Hostname string `json:"hostname"`
		Date     string `json:"date"`
		Result   struct {
			URLWorker struct {
				IP       string `json:"ip"`
				HTTPCode int    `json:"http_code"`
			} `json:"urlworker"`
		} `json:"result"`
	} `json:"url_list"`
}
