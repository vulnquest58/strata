package consensus

import (
	"context"
	"math"
	"net"
	"testing"

	"aperture/internal/resolver"
)

type mockResolver struct {
	name    string
	results map[string]resolver.Result
}

func (m *mockResolver) Protocol() string { return "mock" }
func (m *mockResolver) Name() string     { return m.name }

func (m *mockResolver) Resolve(ctx context.Context, hostname string) resolver.Result {
	if res, ok := m.results[hostname]; ok {
		return res
	}
	return resolver.Result{
		Hostname:     hostname,
		Resolves:     false,
		ProviderName: m.name,
	}
}

func TestIsLiveIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"93.184.216.34", true},
		{"140.82.121.4", true},
		{"2606:4700:20::681a:8ed", true},
		{"0.0.0.0", false},
		{"::", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"172.16.5.10", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
	}

	for _, tc := range tests {
		parsed := net.ParseIP(tc.ip)
		if got := isLiveIP(parsed); got != tc.expected {
			t.Errorf("isLiveIP(%q) = %v; want %v", tc.ip, got, tc.expected)
		}
	}

	if isLiveIP(nil) {
		t.Error("isLiveIP(nil) should be false")
	}
}

func TestTemporalStabilityVariation(t *testing.T) {
	// Setup 3 mock resolvers
	res1 := &mockResolver{
		name: "Mock-1",
		results: map[string]resolver.Result{
			"stable.example.com":   {Hostname: "stable.example.com", Resolves: true, IPs: []string{"93.184.216.34"}},
			"flaky.example.com":    {Hostname: "flaky.example.com", Resolves: true, IPs: []string{"93.184.216.34"}},
			"unstable.example.com": {Hostname: "unstable.example.com", Resolves: true, IPs: []string{"93.184.216.34"}},
			"jobs.github.com":      {Hostname: "jobs.github.com", Resolves: true, IPs: []string{"0.0.0.0"}},
			"private.corp":         {Hostname: "private.corp", Resolves: true, IPs: []string{"192.168.1.5"}},
		},
	}

	res2 := &mockResolver{
		name: "Mock-2",
		results: map[string]resolver.Result{
			"stable.example.com":   {Hostname: "stable.example.com", Resolves: true, IPs: []string{"93.184.216.34"}},
			"flaky.example.com":    {Hostname: "flaky.example.com", Resolves: true, IPs: []string{"93.184.216.34"}},
			"unstable.example.com": {Hostname: "unstable.example.com", Resolves: false},
			"jobs.github.com":      {Hostname: "jobs.github.com", Resolves: true, IPs: []string{"0.0.0.0"}},
			"private.corp":         {Hostname: "private.corp", Resolves: true, IPs: []string{"10.0.0.1"}},
		},
	}

	res3 := &mockResolver{
		name: "Mock-3",
		results: map[string]resolver.Result{
			"stable.example.com":   {Hostname: "stable.example.com", Resolves: true, IPs: []string{"93.184.216.34"}},
			"flaky.example.com":    {Hostname: "flaky.example.com", Resolves: false},
			"unstable.example.com": {Hostname: "unstable.example.com", Resolves: false},
			"jobs.github.com":      {Hostname: "jobs.github.com", Resolves: true, IPs: []string{"0.0.0.0"}},
			"private.corp":         {Hostname: "private.corp", Resolves: true, IPs: []string{"172.16.0.1"}},
		},
	}

	resolvers := []resolver.Resolver{res1, res2, res3}
	engine := NewEngine(resolvers, 0, 0, 0.66)
	ctx := context.Background()

	// Case 1: 3 successes out of 3 attempts
	stableRes := engine.Check(ctx, "stable.example.com")
	if math.Abs(stableRes.TemporalStability-1.0) > 0.001 {
		t.Errorf("stable.example.com stability = %f; want 1.0", stableRes.TemporalStability)
	}
	if !stableRes.Passes {
		t.Errorf("stable.example.com should pass consensus")
	}

	// Case 2: 2 successes out of 3 attempts
	flakyRes := engine.Check(ctx, "flaky.example.com")
	expectedFlaky := 2.0 / 3.0
	if math.Abs(flakyRes.TemporalStability-expectedFlaky) > 0.001 {
		t.Errorf("flaky.example.com stability = %f; want %f", flakyRes.TemporalStability, expectedFlaky)
	}
	if !flakyRes.Passes {
		t.Errorf("flaky.example.com should pass consensus threshold 0.66")
	}

	// Case 3: Explicit assertion that TemporalStability is different between 3/3 and 2/3
	if stableRes.TemporalStability == flakyRes.TemporalStability {
		t.Fatalf("CRITICAL BUG: stable (%f) and flaky (%f) have identical stability scores!",
			stableRes.TemporalStability, flakyRes.TemporalStability)
	}

	// Case 4: 1 success out of 3 attempts (fails threshold 0.66)
	unstableRes := engine.Check(ctx, "unstable.example.com")
	expectedUnstable := 1.0 / 3.0
	if math.Abs(unstableRes.TemporalStability-expectedUnstable) > 0.001 {
		t.Errorf("unstable.example.com stability = %f; want %f", unstableRes.TemporalStability, expectedUnstable)
	}
	if unstableRes.Passes {
		t.Errorf("unstable.example.com should NOT pass consensus threshold 0.66")
	}

	// Case 5: All attempts return 0.0.0.0 (like jobs.github.com)
	jobsRes := engine.Check(ctx, "jobs.github.com")
	if jobsRes.TemporalStability != 0.0 {
		t.Errorf("jobs.github.com stability = %f; want 0.0 (all 0.0.0.0 IPs should fail isLiveIP)", jobsRes.TemporalStability)
	}
	if jobsRes.Passes {
		t.Errorf("jobs.github.com should NOT pass consensus")
	}
	if len(jobsRes.ResolvedIPs) != 0 {
		t.Errorf("jobs.github.com resolved IPs should be empty, got: %v", jobsRes.ResolvedIPs)
	}

	// Case 6: All attempts return private IPs
	privRes := engine.Check(ctx, "private.corp")
	if privRes.TemporalStability != 0.0 {
		t.Errorf("private.corp stability = %f; want 0.0 (all private IPs should fail isLiveIP)", privRes.TemporalStability)
	}
	if privRes.Passes {
		t.Errorf("private.corp should NOT pass consensus")
	}
	if len(privRes.ResolvedIPs) != 0 {
		t.Errorf("private.corp resolved IPs should be empty, got: %v", privRes.ResolvedIPs)
	}
}
