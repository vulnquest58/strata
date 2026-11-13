package orgintel

import "time"

// OrgIdentity represents the organizational registration identity of a domain.
type OrgIdentity struct {
	Domain         string    `json:"domain"`
	RegistrantOrg  string    `json:"registrant_org"`
	RegistrarWHOIS string    `json:"registrar_whois"`
	Source         string    `json:"source"`
	Confidence     float64   `json:"confidence"`
	IsPrivacyProxy bool      `json:"is_privacy_proxy"`
	DiscoveredAt   time.Time `json:"discovered_at"`
}

// CorporateAffiliation represents a discovered non-infrastructure corporate link between two domains.
type CorporateAffiliation struct {
	DomainA      string    `json:"domain_a"`
	DomainB      string    `json:"domain_b"`
	MatchedOrg   string    `json:"matched_org"`
	RegistrarA   string    `json:"registrar_a"`
	RegistrarB   string    `json:"registrar_b"`
	Confidence   float64   `json:"confidence"`
	DiscoveredAt time.Time `json:"discovered_at"`
}
