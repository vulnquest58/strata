package model

import (
	"testing"
	"time"
)

func TestCalculateDecayFactor(t *testing.T) {
	testCases := []struct {
		name     string
		ageDays  float64
		expected float64
	}{
		{"day 0 (fresh scan)", 0, 1.0},
		{"negative age treated as 0", -5, 1.0},
		{"day 30", 30, 0.9167},
		{"day 90", 90, 0.75},
		{"day 180 (decay floor reached)", 180, 0.50},
		{"day 365 (decay stays at floor 0.50)", 365, 0.50},
		{"day 1000 (never reaches zero)", 1000, 0.50},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := CalculateDecayFactor(tc.ageDays)
			if got != tc.expected {
				t.Errorf("ageDays=%.1f: expected %.4f, got %.4f", tc.ageDays, tc.expected, got)
			}
		})
	}
}

func TestCalculateDecayFactorExponential(t *testing.T) {
	testCases := []struct {
		name     string
		ageDays  float64
		expected float64
	}{
		{"day 0 (fresh scan)", 0, 1.0},
		{"day 30", 30, 0.8583},
		{"day 90 (half-life)", 90, 0.6839},
		{"day 180", 180, 0.5677},
		{"day 365", 365, 0.5087},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := CalculateDecayFactorWithModel(tc.ageDays, DecayModelExponential)
			if got != tc.expected {
				t.Errorf("ageDays=%.1f: expected %.4f, got %.4f", tc.ageDays, tc.expected, got)
			}
		})
	}
}

func TestCalculateEffectiveConfidence(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	adjConf := 80.0

	// 1. Fresh finding (0 days)
	eff0, factor0 := CalculateEffectiveConfidence(adjConf, now, nil, now)
	if eff0 != 80.0 || factor0 != 1.0 {
		t.Errorf("fresh finding: expected eff=80, factor=1.0, got eff=%v, factor=%v", eff0, factor0)
	}

	// 2. 90-day old finding (factor = 0.75)
	past90 := now.AddDate(0, 0, -90)
	eff90, factor90 := CalculateEffectiveConfidence(adjConf, past90, nil, now)
	if factor90 != 0.75 || eff90 != 60.0 {
		t.Errorf("90-day finding: expected eff=60, factor=0.75, got eff=%v, factor=%v", eff90, factor90)
	}

	// 3. 90-day old finding re-verified yesterday (reset age to 1 day)
	yesterday := now.AddDate(0, 0, -1)
	effReset, factorReset := CalculateEffectiveConfidence(adjConf, past90, &yesterday, now)
	if factorReset <= 0.99 || effReset < 79.0 {
		t.Errorf("re-verified finding: expected near 80, got eff=%v, factor=%v", effReset, factorReset)
	}
}

func TestCalculateSubnet24(t *testing.T) {
	testCases := []struct {
		ip       string
		expected string
	}{
		{"140.82.121.6", "140.82.121.0/24"},
		{"185.199.108.153", "185.199.108.0/24"},
		{"127.0.0.1", "127.0.0.0/24"},
		{"invalid-ip", ""},
		{"2606:50c0:8000::153", ""}, // IPv6 is ignored for /24 IPv4 subnets
	}

	for _, tc := range testCases {
		got := CalculateSubnet24(tc.ip)
		if got != tc.expected {
			t.Errorf("ip=%s: expected %q, got %q", tc.ip, tc.expected, got)
		}
	}
}

func TestDetectCDN(t *testing.T) {
	// Fastly IP
	cdns1 := DetectCDN([]string{"151.101.65.140"}, nil)
	if len(cdns1) == 0 || cdns1[0] != "Fastly" {
		t.Errorf("expected Fastly, got %v", cdns1)
	}

	// GitHub Pages IP
	cdns2 := DetectCDN([]string{"185.199.108.153"}, nil)
	if len(cdns2) == 0 || cdns2[0] != "GitHub Pages" {
		t.Errorf("expected GitHub Pages, got %v", cdns2)
	}

	// Cloudflare CNAME
	cdns3 := DetectCDN(nil, map[string]any{"cname": "sub.cloudflare.com."})
	if len(cdns3) == 0 || cdns3[0] != "Cloudflare" {
		t.Errorf("expected Cloudflare, got %v", cdns3)
	}
}

func TestASNMatchForGitHubAndGitHubAssets(t *testing.T) {
	// action.github.com and analytics.githubassets.com both resolve to 185.199.108.153 (Fastly AS54113)
	ipGitHub := "185.199.108.153"
	ipGitHubAssets := "185.199.109.153"

	asn1, org1, err1 := LookupASN(ipGitHub)
	if err1 != nil {
		t.Fatalf("LookupASN for github failed: %v", err1)
	}

	asn2, org2, err2 := LookupASN(ipGitHubAssets)
	if err2 != nil {
		t.Fatalf("LookupASN for githubassets failed: %v", err2)
	}

	if asn1 != 54113 || asn2 != 54113 {
		t.Errorf("expected both ASNs to be 54113, got %d and %d", asn1, asn2)
	}

	if asn1 != asn2 {
		t.Errorf("expected identical ASN for github and githubassets, got %d != %d", asn1, asn2)
	}

	if org1 == "" || org2 == "" {
		t.Errorf("expected non-empty org names, got org1=%q, org2=%q", org1, org2)
	}
}

