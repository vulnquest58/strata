package verifier

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// HTTPVerifier performs silent HTTP HEAD verification on discovered subdomains.
// It never does a full GET or crawls — just a lightweight probe.
type HTTPVerifier struct {
	client *http.Client
}

// HTTPResult holds the result of a single HEAD probe.
type HTTPResult struct {
	Hostname     string
	StatusCode   int
	ServerHeader string
	Reachable    bool
	Scheme       string // "https" or "http"
}

// NewHTTPVerifier creates a verifier with the given timeout in seconds.
func NewHTTPVerifier(timeoutSecs int) *HTTPVerifier {
	return &HTTPVerifier{
		client: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
			// Do not follow redirects automatically — we just want the status
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Probe performs a HEAD request against the given hostname, trying HTTPS first then HTTP.
func (v *HTTPVerifier) Probe(ctx context.Context, hostname string) HTTPResult {
	// Try HTTPS first
	if r := v.probe(ctx, "https", hostname); r.Reachable {
		return r
	}
	// Fall back to HTTP
	return v.probe(ctx, "http", hostname)
}

func (v *HTTPVerifier) probe(ctx context.Context, scheme, hostname string) HTTPResult {
	url := fmt.Sprintf("%s://%s/", scheme, hostname)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return HTTPResult{Hostname: hostname, Scheme: scheme}
	}

	req.Header.Set("User-Agent", utils.RandomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	resp, err := v.client.Do(req)
	if err != nil {
		return HTTPResult{Hostname: hostname, Scheme: scheme}
	}
	defer resp.Body.Close()

	return HTTPResult{
		Hostname:     hostname,
		StatusCode:   resp.StatusCode,
		ServerHeader: resp.Header.Get("Server"),
		Reachable:    true,
		Scheme:       scheme,
	}
}
