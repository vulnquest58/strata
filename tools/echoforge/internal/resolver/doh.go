package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// DoHProvider represents a DNS-over-HTTPS resolver endpoint.
type DoHProvider struct {
	Name string
	URL  string
}

// BuiltInProviders is the default pool of public DoH resolvers.
var BuiltInProviders = []DoHProvider{
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query"},
	{Name: "Google", URL: "https://dns.google/dns-query"},
	{Name: "Quad9", URL: "https://dns.quad9.net/dns-query"},
	{Name: "OpenDNS", URL: "https://doh.opendns.com/dns-query"},
	{Name: "AdGuard", URL: "https://dns.adguard-dns.com/dns-query"},
	{Name: "NextDNS", URL: "https://dns.nextdns.io/dns-query"},
	{Name: "CleanBrowsing", URL: "https://doh.cleanbrowsing.org/doh/security-filter/"},
}

// dohResponse mirrors the JSON-format DNS-over-HTTPS response.
type dohResponse struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	RD       bool `json:"RD"`
	RA       bool `json:"RA"`
	AD       bool `json:"AD"`
	CD       bool `json:"CD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// DoHClient performs DNS lookups via DNS-over-HTTPS.
type DoHClient struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewDoHClient creates a DoHClient with the given timeout.
func NewDoHClient(timeoutSecs int) *DoHClient {
	return &DoHClient{
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
		},
		timeout: time.Duration(timeoutSecs) * time.Second,
	}
}

// Resolve queries a single DoH provider for A and AAAA records for the given hostname.
// Returns a list of IP addresses and true if the host resolves.
func (c *DoHClient) Resolve(ctx context.Context, provider DoHProvider, hostname string) ([]string, bool) {
	ips := make([]string, 0, 4)

	for _, qtype := range []string{"A", "AAAA"} {
		answers, err := c.query(ctx, provider, hostname, qtype)
		if err == nil {
			ips = append(ips, answers...)
		}
	}

	return ips, len(ips) > 0
}

// query performs a single DoH DNS query for a given type (A, AAAA, CNAME, etc.)
func (c *DoHClient) query(ctx context.Context, provider DoHProvider, name, qtype string) ([]string, error) {
	url := fmt.Sprintf("%s?name=%s&type=%s", provider.URL, name, qtype)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", utils.RandomUA())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}

	var dnsResp dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return nil, err
	}

	// DNS status 0 = NOERROR
	if dnsResp.Status != 0 {
		return nil, fmt.Errorf("DNS NXDOMAIN or error (status=%d)", dnsResp.Status)
	}

	var results []string
	for _, ans := range dnsResp.Answer {
		// Type 1 = A, Type 28 = AAAA, Type 5 = CNAME
		if ans.Type == 1 || ans.Type == 28 {
			ip := strings.TrimSpace(ans.Data)
			if ip != "" {
				results = append(results, ip)
			}
		}
	}
	return results, nil
}
