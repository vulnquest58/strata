package miner

// IndustryProfile holds context-specific vocabulary for a target industry.
type IndustryProfile struct {
	Name     string
	Keywords []string
	Prefixes []string
	Suffixes []string
}

// knownProfiles maps industry names to their vocabulary profiles.
var knownProfiles = map[string]IndustryProfile{
	"tech": {
		Name: "tech",
		Keywords: []string{
			"api", "dev", "staging", "prod", "internal", "admin", "cdn",
			"dashboard", "app", "web", "portal", "backend", "frontend",
			"microservice", "gateway", "auth", "oauth", "sso", "sdk",
			"docs", "status", "monitor", "metrics", "grafana", "jenkins",
			"gitlab", "github", "ci", "cd", "build", "deploy", "release",
			"sandbox", "qa", "uat", "preview", "demo", "lab", "test",
		},
		Prefixes: []string{"api", "dev", "prod", "staging", "internal", "app"},
		Suffixes: []string{"v2", "v3", "eu", "us", "ap", "beta", "test"},
	},
	"finance": {
		Name: "finance",
		Keywords: []string{
			"secure", "banking", "core", "transaction", "payment", "gateway",
			"swift", "ach", "wire", "transfer", "account", "ledger", "fraud",
			"compliance", "kyc", "aml", "risk", "trading", "market", "quote",
			"portfolio", "wealth", "invest", "loan", "credit", "debit", "card",
			"mobile", "online", "ibk", "ebanking", "corp", "retail", "private",
		},
		Prefixes: []string{"secure", "banking", "core", "payment", "mobile"},
		Suffixes: []string{"secure", "corp", "eu", "us", "prod"},
	},
	"ecommerce": {
		Name: "ecommerce",
		Keywords: []string{
			"shop", "store", "cart", "checkout", "payment", "order", "product",
			"catalog", "search", "recommend", "review", "seller", "buyer",
			"warehouse", "inventory", "shipping", "tracking", "delivery",
			"promo", "coupon", "loyalty", "reward", "affiliate", "partner",
			"media", "cdn", "image", "assets", "static", "account", "wishlist",
		},
		Prefixes: []string{"shop", "store", "api", "cdn", "media"},
		Suffixes: []string{"eu", "us", "asia", "prod", "v2"},
	},
	"healthcare": {
		Name: "healthcare",
		Keywords: []string{
			"patient", "clinical", "ehr", "emr", "provider", "portal", "lab",
			"pharmacy", "prescription", "imaging", "radiology", "billing",
			"claims", "insurance", "telemedicine", "telemed", "consult",
			"secure", "hipaa", "admin", "staff", "doctor", "nurse", "icu",
			"scheduling", "appointment", "referral", "analytics", "data",
		},
		Prefixes: []string{"patient", "provider", "clinical", "secure", "portal"},
		Suffixes: []string{"secure", "prod", "eu", "us"},
	},
	"auto": {
		Name: "auto",
		Keywords: []string{
			"tech", "auto", "car", "drive", "fleet", "dealer", "service",
			"parts", "connect", "vehicle", "telematics", "mobility", "charging",
			"ev", "hybrid", "rental", "lease", "finance", "insurance",
		},
		Prefixes: []string{"fleet", "connect", "service", "dealer"},
		Suffixes: []string{"connect", "eu", "us", "prod"},
	},
}

// GetProfile returns the industry profile matching the given name.
// Falls back to the "tech" profile for "auto" detection.
// Returns nil for "auto" detection when industry is not detected.
func GetProfile(industry string) *IndustryProfile {
	if industry == "auto" || industry == "" {
		return nil // caller should auto-detect
	}
	p, ok := knownProfiles[industry]
	if !ok {
		// Fall back to tech if unknown
		tech := knownProfiles["tech"]
		return &tech
	}
	return &p
}

// AutoDetect attempts to infer the industry from known subdomain tokens.
// Returns the detected profile or the tech default.
func AutoDetect(subdomains []string) *IndustryProfile {
	scores := make(map[string]int)

	for _, sub := range subdomains {
		tokens := tokenize(sub)
		for _, tok := range tokens {
			for industry, profile := range knownProfiles {
				for _, kw := range profile.Keywords {
					if tok == kw {
						scores[industry]++
					}
				}
			}
		}
	}

	best := ""
	bestScore := 0
	for industry, score := range scores {
		if score > bestScore {
			bestScore = score
			best = industry
		}
	}

	if best == "" {
		tech := knownProfiles["tech"]
		return &tech
	}
	p := knownProfiles[best]
	return &p
}


