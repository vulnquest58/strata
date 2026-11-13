package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DoHResolver resolves DNS via DNS-over-HTTPS (JSON API format).
// Compatible with Cloudflare, Google, Quad9, and any RFC 8484 compliant endpoint.
type DoHResolver struct {
	name     string
	endpoint string
	client   *http.Client
}

// NewDoHResolver creates a DoH resolver for the given endpoint.
// endpointURL must be the JSON-format DNS API URL (e.g., "https://cloudflare-dns.com/dns-query" or "https://dns.google/resolve").
func NewDoHResolver(name, endpointURL string, timeoutSecs int) *DoHResolver {
	// Normalize Google DoH endpoint: Google's JSON API is at /resolve, while /dns-query is RFC 8484 binary.
	if strings.Contains(endpointURL, "dns.google") && strings.HasSuffix(endpointURL, "/dns-query") {
		endpointURL = strings.TrimSuffix(endpointURL, "/dns-query") + "/resolve"
	}
	return &DoHResolver{
		name:     name,
		endpoint: endpointURL,
		client: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
		},
	}
}

func (d *DoHResolver) Protocol() string { return "doh" }
func (d *DoHResolver) Name() string     { return d.name }

// Resolve queries the DoH endpoint for A and AAAA records.
func (d *DoHResolver) Resolve(ctx context.Context, hostname string) Result {
	result := Result{
		Hostname:     hostname,
		Protocol:     "doh",
		ProviderName: d.name,
	}

	ips, cname := d.queryBoth(ctx, hostname)
	result.IPs = ips
	result.CNAME = cname
	result.Resolves = len(ips) > 0
	return result
}

// queryBoth fetches A and AAAA records and returns the merged list of IPs plus any CNAME.
func (d *DoHResolver) queryBoth(ctx context.Context, hostname string) ([]string, string) {
	var allIPs []string
	var cname string

	for _, qtype := range []string{"A", "AAAA"} {
		ips, cn, err := d.query(ctx, hostname, qtype)
		if err == nil {
			allIPs = append(allIPs, ips...)
			if cn != "" && cname == "" {
				cname = cn
			}
		}
	}
	return allIPs, cname
}

func (d *DoHResolver) query(ctx context.Context, name, qtype string) ([]string, string, error) {
	url := fmt.Sprintf("%s?name=%s&type=%s", d.endpoint, name, qtype)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("DoH %s returned %d", d.name, resp.StatusCode)
	}

	var dnsResp dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return nil, "", err
	}
	if dnsResp.Status != 0 {
		return nil, "", fmt.Errorf("DNS NXDOMAIN/error (status=%d)", dnsResp.Status)
	}

	var ips []string
	var cname string
	for _, ans := range dnsResp.Answer {
		data := strings.TrimSpace(ans.Data)
		switch ans.Type {
		case 1, 28: // A, AAAA
			if data != "" {
				ips = append(ips, data)
			}
		case 5: // CNAME
			if cname == "" {
				cname = strings.TrimSuffix(data, ".")
			}
		}
	}
	return ips, cname, nil
}

// dohResponse mirrors the JSON DNS-over-HTTPS response format (RFC 8484 / Google style).
type dohResponse struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
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
