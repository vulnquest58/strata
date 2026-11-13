package resolver

import "context"

// Result holds the outcome of a single DNS resolution attempt.
type Result struct {
	// Hostname is the queried name.
	Hostname string
	// IPs contains all resolved A/AAAA addresses.
	IPs []string
	// CNAME is the canonical name if the record resolved via a CNAME chain.
	CNAME string
	// Resolves indicates whether at least one IP was returned.
	Resolves bool
	// Protocol indicates the transport used: "doh" or "raw".
	Protocol string
	// ProviderName is the human-readable name of the resolver endpoint used.
	ProviderName string
}

// Resolver is the minimal interface for a DNS resolution backend.
// The two implementations are DoHResolver (net/http) and RawResolver (miekg/dns).
type Resolver interface {
	// Resolve performs a DNS A/AAAA lookup for the given hostname.
	Resolve(ctx context.Context, hostname string) Result

	// Protocol returns "doh" or "raw".
	Protocol() string

	// Name returns a human-readable identifier for this resolver instance.
	Name() string
}
