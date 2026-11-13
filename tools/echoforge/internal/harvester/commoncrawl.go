package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// CommonCrawlHarvester fetches subdomains from the Common Crawl index API.
// This is an opt-in source (--full-passive) as it can be slow.
type CommonCrawlHarvester struct {
	client *http.Client
	jitter *utils.Jitter
}

func NewCommonCrawlHarvester(stealth bool) *CommonCrawlHarvester {
	return &CommonCrawlHarvester{
		client: &http.Client{Timeout: 45 * time.Second},
		jitter: utils.NewJitter(5000, 0.4, stealth),
	}
}

// latestCCIndex fetches the URL for the most recent Common Crawl index.
func (h *CommonCrawlHarvester) latestCCIndex(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", utils.RandomUA())

	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var colls []struct {
		ID     string `json:"id"`
		APIURL string `json:"cdx-api"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&colls); err != nil {
		return "", err
	}
	if len(colls) == 0 {
		return "", fmt.Errorf("commoncrawl: no collections found")
	}
	// First entry is usually the most recent
	return colls[0].APIURL, nil
}

// Fetch queries the Common Crawl CDX index for URLs containing the target domain.
func (h *CommonCrawlHarvester) Fetch(ctx context.Context, domain string) ([]string, error) {
	h.jitter.Sleep()

	apiURL, err := h.latestCCIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl: get index: %w", err)
	}

	params := url.Values{}
	params.Set("url", fmt.Sprintf("*.%s/*", domain))
	params.Set("output", "json")
	params.Set("fl", "url")
	params.Set("collapse", "urlkey")
	params.Set("limit", "5000")
	params.Set("filter", "statuscode:200")

	endpoint := apiURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl: build request: %w", err)
	}
	req.Header.Set("User-Agent", utils.RandomUA())

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("commoncrawl: HTTP %d", resp.StatusCode)
	}

	// Response is NDJSON: one JSON object per line
	seen := make(map[string]bool)
	var results []string

	decoder := json.NewDecoder(resp.Body)
	for decoder.More() {
		var row map[string]string
		if err := decoder.Decode(&row); err != nil {
			continue
		}
		raw := row["url"]
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(strings.Split(u.Host, ":")[0])
		if strings.HasSuffix(host, "."+domain) && !seen[host] {
			seen[host] = true
			results = append(results, host)
		}
	}

	return results, nil
}
