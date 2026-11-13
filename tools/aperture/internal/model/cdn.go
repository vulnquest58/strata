package model

import (
	"strings"
)

// PublicCDNProviders is the list of multi-tenant CDNs where shared IPs do not imply common ownership.
var PublicCDNProviders = map[string]bool{
	"cloudflare":   true,
	"fastly":       true,
	"cloudfront":   true,
	"akamai":       true,
	"github pages": true,
	"azure cdn":    true,
	"google cdn":   true,
}

// IsPublicCDN returns true if any detected CDN provider or AS Organization belongs to a known public multi-tenant CDN.
func IsPublicCDN(providers []string, asOrg string) bool {
	for _, p := range providers {
		if PublicCDNProviders[strings.ToLower(strings.TrimSpace(p))] {
			return true
		}
	}

	asOrgUpper := strings.ToUpper(asOrg)
	if strings.Contains(asOrgUpper, "CLOUDFLARE") ||
		strings.Contains(asOrgUpper, "FASTLY") ||
		strings.Contains(asOrgUpper, "AKAMAI") ||
		strings.Contains(asOrgUpper, "AMAZON") ||
		strings.Contains(asOrgUpper, "CLOUDFRONT") {
		return true
	}

	return false
}
