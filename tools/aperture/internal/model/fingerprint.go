package model

import (
	"net"
	"strings"
	"time"
)

// InfrastructureFingerprint captures the network, TLS, and hosting identity of an asset.
type InfrastructureFingerprint struct {
	AssetID      string    `json:"asset_id"`
	RootDomain   string    `json:"root_domain"`
	ResolvedIPs  []string  `json:"resolved_ips"`
	IPRanges24   []string  `json:"ip_ranges_24"`  // CIDR /24 subnets
	ASNSet       []string  `json:"asn_set"`       // ASNs associated with resolved IPs
	ASN          int       `json:"asn"`           // Primary ASN
	ASOrg        string    `json:"as_org"`        // AS Organization name
	CDNProviders []string  `json:"cdn_providers"` // Detected CDN services
	CertIssuers  []string  `json:"cert_issuers"`  // TLS Certificate Issuers
	SANList      []string  `json:"san_list"`      // Subject Alternative Names from TLS certs
	ExtractedAt  time.Time `json:"extracted_at"`
}

// CrossTargetCorrelation represents a shared infrastructure link discovered between two different root domains.
type CrossTargetCorrelation struct {
	ID              string         `json:"id"`
	RootDomainA     string         `json:"root_domain_a"`
	RootDomainB     string         `json:"root_domain_b"`
	AssetA          string         `json:"asset_a"`
	AssetB          string         `json:"asset_b"`
	CorrelationType string         `json:"correlation_type"` // "shared_cert_san", "shared_subnet_24", "shared_cdn"
	SharedElement   string         `json:"shared_element"`   // e.g. shared domain in SAN, /24 subnet, etc.
	Confidence      float64        `json:"confidence"`       // correlation strength (0.0–1.0)
	Evidence        map[string]any `json:"evidence,omitempty"`
	DiscoveredAt    time.Time      `json:"discovered_at"`
}

// CalculateSubnet24 returns the /24 CIDR prefix for an IPv4 address.
func CalculateSubnet24(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}
	return ipv4.Mask(net.CIDRMask(24, 32)).String() + "/24"
}

// DetectCDN checks known IP ranges or CNAME/CDN signatures.
func DetectCDN(resolvedIPs []string, metadata map[string]any) []string {
	var providers []string
	seen := make(map[string]bool)

	addProvider := func(p string) {
		if !seen[p] {
			seen[p] = true
			providers = append(providers, p)
		}
	}

	for _, ipStr := range resolvedIPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		// Fastly ranges (e.g. 151.101.0.0/16, 199.232.0.0/16)
		if strings.HasPrefix(ipStr, "151.101.") || strings.HasPrefix(ipStr, "199.232.") {
			addProvider("Fastly")
		}
		// Cloudflare ranges (e.g. 104.16.0.0/12, 172.64.0.0/13, 108.162.0.0/16)
		if strings.HasPrefix(ipStr, "104.16.") || strings.HasPrefix(ipStr, "104.17.") ||
			strings.HasPrefix(ipStr, "104.18.") || strings.HasPrefix(ipStr, "104.19.") ||
			strings.HasPrefix(ipStr, "104.20.") || strings.HasPrefix(ipStr, "104.21.") ||
			strings.HasPrefix(ipStr, "172.64.") || strings.HasPrefix(ipStr, "172.65.") ||
			strings.HasPrefix(ipStr, "172.66.") || strings.HasPrefix(ipStr, "172.67.") {
			addProvider("Cloudflare")
		}
		// GitHub Pages / Fastly (185.199.108.0/22)
		if strings.HasPrefix(ipStr, "185.199.108.") || strings.HasPrefix(ipStr, "185.199.109.") ||
			strings.HasPrefix(ipStr, "185.199.110.") || strings.HasPrefix(ipStr, "185.199.111.") {
			addProvider("GitHub Pages")
		}
		// Amazon CloudFront (e.g. 13.224-227, 13.32-35, 143.204, 52.84, etc.)
		if strings.HasPrefix(ipStr, "13.224.") || strings.HasPrefix(ipStr, "13.225.") ||
			strings.HasPrefix(ipStr, "13.226.") || strings.HasPrefix(ipStr, "13.227.") ||
			strings.HasPrefix(ipStr, "143.204.") {
			addProvider("CloudFront")
		}
	}

	if metadata != nil {
		if cname, ok := metadata["cname"].(string); ok {
			cnameLower := strings.ToLower(cname)
			if strings.Contains(cnameLower, "cloudflare") {
				addProvider("Cloudflare")
			}
			if strings.Contains(cnameLower, "cloudfront") {
				addProvider("CloudFront")
			}
			if strings.Contains(cnameLower, "fastly") {
				addProvider("Fastly")
			}
			if strings.Contains(cnameLower, "github.io") {
				addProvider("GitHub Pages")
			}
			if strings.Contains(cnameLower, "akamai") || strings.Contains(cnameLower, "edgekey") {
				addProvider("Akamai")
			}
		}
	}

	return providers
}
