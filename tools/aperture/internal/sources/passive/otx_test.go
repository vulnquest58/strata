package passive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aperture/internal/model"
	"aperture/internal/sources"
)

func TestOTXSourceMetadata(t *testing.T) {
	s := &OTXSource{}
	if s.Name() != "otx" {
		t.Fatalf("expected Name() == 'otx', got %q", s.Name())
	}
	if s.Category() != model.SourcePassive {
		t.Fatalf("expected Category() == SourcePassive, got %v", s.Category())
	}
	if s.DefaultPriorReliability() != 0.5 {
		t.Fatalf("expected DefaultPriorReliability() == 0.5, got %f", s.DefaultPriorReliability())
	}
}

func TestOTXSourceDiscoverPassiveDNS(t *testing.T) {
	mockData := otxPassiveDNSResponse{
		PassiveDNS: []struct {
			Hostname   string `json:"hostname"`
			RecordType string `json:"record_type"`
			Address    string `json:"address"`
			First      string `json:"first"`
			Last       string `json:"last"`
		}{
			{Hostname: "api.example.com", RecordType: "A", Address: "1.2.3.4", First: "2020", Last: "2024"},
			{Hostname: "docs.example.com", RecordType: "CNAME", Address: "cdn.fastly.net", First: "2021", Last: "2024"},
			{Hostname: "mail.example.com", RecordType: "MX", Address: "10 mail.example.com", First: "2022", Last: "2024"},
			{Hostname: "api.example.com", RecordType: "A", Address: "1.2.3.4", First: "2020", Last: "2024"}, // duplicate
			{Hostname: "evil.otherdomain.com", RecordType: "A", Address: "5.6.7.8", First: "2023", Last: "2024"}, // out of scope
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "test-api-key" {
			t.Errorf("missing or incorrect X-OTX-API-KEY header: %s", r.Header.Get("X-OTX-API-KEY"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockData)
	}))
	defer server.Close()

	otx := &OTXSource{
		client:  server.Client(),
		apiKey:  "test-api-key",
		baseURL: server.URL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := otx.Discover(ctx, "example.com")
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}

	var candidates []sources.RawCandidate
	for c := range ch {
		if c.Error != nil {
			t.Fatalf("unexpected error candidate: %v", c.Error)
		}
		candidates = append(candidates, c)
	}

	if len(candidates) != 3 {
		t.Fatalf("expected 3 candidates (excluding duplicate and out-of-scope), got %d", len(candidates))
	}

	foundMap := make(map[string]sources.RawCandidate)
	for _, c := range candidates {
		foundMap[c.AssetID] = c
		if c.RawScore != 60.0 {
			t.Errorf("expected RawScore 60.0, got %f for %s", c.RawScore, c.AssetID)
		}
		if c.SourcePlugin != "otx" {
			t.Errorf("expected SourcePlugin 'otx', got %s", c.SourcePlugin)
		}
	}

	if c, ok := foundMap["api.example.com"]; !ok || c.AssetType != model.AssetSubdomain {
		t.Errorf("expected api.example.com as AssetSubdomain")
	}
	if c, ok := foundMap["docs.example.com"]; !ok || c.AssetType != model.AssetCNAME {
		t.Errorf("expected docs.example.com as AssetCNAME")
	}
	if c, ok := foundMap["mail.example.com"]; !ok || c.AssetType != model.AssetMX {
		t.Errorf("expected mail.example.com as AssetMX")
	}
}

func TestOTXSourceURLListFallback(t *testing.T) {
	urlListData := otxURLListResponse{
		URLList: []struct {
			URL      string `json:"url"`
			Hostname string `json:"hostname"`
			Date     string `json:"date"`
			Result   struct {
				URLWorker struct {
					IP       string `json:"ip"`
					HTTPCode int    `json:"http_code"`
				} `json:"urlworker"`
			} `json:"result"`
		}{
			{URL: "https://api.example.com/v1", Hostname: "api.example.com", Date: "2026-01-01"},
			{URL: "https://admin.example.com/login", Hostname: "admin.example.com", Date: "2026-01-02"},
			{URL: "https://other.com/test", Hostname: "other.com", Date: "2026-01-03"}, // out of scope
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/example.com/passive_dns" {
			// Simulate 429 anonymous access limited
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"detail":"Anonymous access to this endpoint is limited."}`))
			return
		}
		if r.URL.Path == "/example.com/url_list" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(urlListData)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	otx := &OTXSource{
		client:  server.Client(),
		baseURL: server.URL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := otx.Discover(ctx, "example.com")
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}

	var candidates []sources.RawCandidate
	for c := range ch {
		if c.Error != nil {
			t.Fatalf("unexpected error candidate during fallback: %v", c.Error)
		}
		candidates = append(candidates, c)
	}

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates from url_list fallback, got %d", len(candidates))
	}

	if candidates[0].AssetID != "api.example.com" && candidates[1].AssetID != "api.example.com" {
		t.Errorf("expected api.example.com to be discovered via fallback")
	}
	if candidates[0].RawScore != 60.0 {
		t.Errorf("expected RawScore 60.0, got %f", candidates[0].RawScore)
	}
}

func TestOTXSourceHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	otx := &OTXSource{
		client:  server.Client(),
		baseURL: server.URL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := otx.Discover(ctx, "example.com")
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}

	var errCandidates []sources.RawCandidate
	for c := range ch {
		if c.Error != nil {
			errCandidates = append(errCandidates, c)
		}
	}

	if len(errCandidates) != 1 {
		t.Fatalf("expected 1 error candidate for HTTP error, got %d", len(errCandidates))
	}
}
