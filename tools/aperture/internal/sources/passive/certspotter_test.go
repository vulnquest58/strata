package passive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSanitizeURL tests layer 2 URL sanitization:
// Rejects format-string residues (%s, %d), URLs without host or scheme, and non-HTTP schemes.
func TestSanitizeURL(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		valid   bool
		expected string
	}{
		{
			name:    "valid https url",
			input:   "https://api.github.com/repos/owner/repo",
			valid:   true,
			expected: "https://api.github.com/repos/owner/repo",
		},
		{
			name:    "valid http url with port and query",
			input:   "http://sub.example.com:8080/path?key=val",
			valid:   true,
			expected: "http://sub.example.com:8080/path?key=val",
		},
		{
			name:    "rejects format-string residue (%s)",
			input:   "https://api.github.com/repos/%s/%s/releases/latestX.509",
			valid:   false,
			expected: "",
		},
		{
			name:    "rejects format-string residue (%d)",
			input:   "https://api.github.com/users/%d/profile",
			valid:   false,
			expected: "",
		},
		{
			name:    "rejects missing scheme",
			input:   "api.github.com/repos/owner",
			valid:   false,
			expected: "",
		},
		{
			name:    "rejects relative path",
			input:   "/repos/owner/repo",
			valid:   false,
			expected: "",
		},
		{
			name:    "rejects non-http scheme",
			input:   "javascript:alert(1)",
			valid:   false,
			expected: "",
		},
		{
			name:    "rejects empty string",
			input:   "",
			valid:   false,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SanitizeURL(tc.input)
			if ok != tc.valid {
				t.Fatalf("expected valid=%v, got %v for input %q", tc.valid, ok, tc.input)
			}
			if tc.valid && got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

// TestSanitizeHostname tests layer 2 hostname sanitization:
// Rejects RFC 1035 violations, bad characters, unreplaced format strings, out-of-scope targets.
func TestSanitizeHostname(t *testing.T) {
	testCases := []struct {
		name    string
		raw     string
		target  string
		valid   bool
		expected string
	}{
		{
			name:     "valid apex domain",
			raw:      "github.com",
			target:   "github.com",
			valid:    true,
			expected: "github.com",
		},
		{
			name:     "valid subdomain with mixed casing",
			raw:      "API.GitHub.Com",
			target:   "github.com",
			valid:    true,
			expected: "api.github.com",
		},
		{
			name:     "strips leading wildcard prefix (*.)",
			raw:      "*.octocaptcha.review-lab.github.com",
			target:   "github.com",
			valid:    true,
			expected: "octocaptcha.review-lab.github.com",
		},
		{
			name:     "rejects format specifier in hostname",
			raw:      "api.%s.github.com",
			target:   "github.com",
			valid:    false,
			expected: "",
		},
		{
			name:     "rejects latestX.509 style mangled domain",
			raw:      "api.github.com/repos/%s/%s/releases/latestx.509",
			target:   "github.com",
			valid:    false,
			expected: "",
		},
		{
			name:     "rejects invalid characters (spaces, slashes, colons)",
			raw:      "api github.com",
			target:   "github.com",
			valid:    false,
			expected: "",
		},
		{
			name:     "rejects domain out of target scope",
			raw:      "attacker.evil.com",
			target:   "github.com",
			valid:    false,
			expected: "",
		},
		{
			name:     "rejects suffix trick (not a real subdomain)",
			raw:      "notgithub.com",
			target:   "github.com",
			valid:    false,
			expected: "",
		},
		{
			name:     "rejects single label without TLD",
			raw:      "localhost",
			target:   "localhost",
			valid:    false,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SanitizeHostname(tc.raw, tc.target)
			if ok != tc.valid {
				t.Fatalf("expected valid=%v, got %v for input %q", tc.valid, ok, tc.raw)
			}
			if tc.valid && got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

// TestNoIPLeakageInCandidate tests layer 3:
// Ensures that candidates emitted by CertSpotter have NO IP fields in Evidence or Metadata.
func TestNoIPLeakageInCandidate(t *testing.T) {
	mockResponse := []certSpotterIssuance{
		{
			ID:        "12345678",
			DNSNames:  []string{"api.github.com", "cdn.github.com", "raw.github.com"},
			NotBefore: "2026-01-01T00:00:00Z",
			NotAfter:  "2026-12-31T23:59:59Z",
			Revoked:   false,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	cs := NewCertSpotter(5, "")
	cs.SetBaseURL(server.URL)
	// Disable rate limit delay for unit test
	cs.limiter = NewRateLimiter(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := cs.Discover(ctx, "github.com")
	if err != nil {
		t.Fatalf("unexpected Discover error: %v", err)
	}

	count := 0
	forbiddenKeys := []string{"ip", "resolved_ip", "address", "url_worker_ip", "ip_address"}

	for cand := range ch {
		if cand.Error != nil {
			t.Fatalf("unexpected candidate error: %v", cand.Error)
		}
		count++

		// Verify AssetID is a valid hostname
		if strings.Contains(cand.AssetID, " ") || strings.Contains(cand.AssetID, "/") {
			t.Errorf("candidate AssetID contains invalid characters: %q", cand.AssetID)
		}

		// Layer 3 Verification: Evidence must NOT contain any IP keys
		for _, key := range forbiddenKeys {
			if _, exists := cand.Evidence[key]; exists {
				t.Errorf("architectural violation: candidate Evidence contains forbidden IP key %q: %v", key, cand.Evidence[key])
			}
		}
	}

	if count != 3 {
		t.Fatalf("expected 3 candidates, got %d", count)
	}
}

// TestThrottling tests layer 4:
// Ensures that consecutive requests through RateLimiter are spaced by at least minInterval.
func TestThrottling(t *testing.T) {
	interval := 50 * time.Millisecond
	limiter := NewRateLimiter(interval)

	ctx := context.Background()

	start := time.Now()
	// First request: immediate
	if err := limiter.Throttle(ctx); err != nil {
		t.Fatalf("unexpected error on first throttle: %v", err)
	}

	// Second request: must pause for ~50ms
	if err := limiter.Throttle(ctx); err != nil {
		t.Fatalf("unexpected error on second throttle: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < interval {
		t.Fatalf("expected throttling elapsed time >= %v, got %v", interval, elapsed)
	}
}

// TestCertSpotterRateLimit429Handling tests layer 4:
// Verifies graceful backoff and clean termination on persistent 429 without hanging or panic.
func TestCertSpotterRateLimit429Handling(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	cs := NewCertSpotter(5, "")
	cs.SetBaseURL(server.URL)
	cs.limiter = NewRateLimiter(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := cs.Discover(ctx, "github.com")
	if err != nil {
		t.Fatalf("unexpected Discover error: %v", err)
	}

	var lastErr error
	for cand := range ch {
		if cand.Error != nil {
			lastErr = cand.Error
		}
	}

	if lastErr == nil {
		t.Fatal("expected 429 rate limit error candidate, got nil")
	}
	if !strings.Contains(lastErr.Error(), "429") {
		t.Fatalf("expected error mentioning 429, got %v", lastErr)
	}
	if attempts < 2 {
		t.Fatalf("expected at least 2 retry attempts, got %d", attempts)
	}
}
