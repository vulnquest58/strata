package model

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type asnCacheEntry struct {
	asn   int
	asOrg string
	err   error
}

var (
	asnCache sync.Map
	dnsResolver = &net.Resolver{
		PreferGo: true,
	}
)

// LookupASN queries Team Cymru DNS TXT records to passively determine the ASN and Org for an IP address.
func LookupASN(ipStr string) (int, string, error) {
	cleanIP := strings.TrimSpace(ipStr)
	ip := net.ParseIP(cleanIP)
	if ip == nil {
		return 0, "", fmt.Errorf("invalid IP: %q", ipStr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		// IPv6 reverse lookups could be added; for now handle IPv4 passively
		return 0, "", nil
	}

	// Skip private and loopback addresses
	if ipv4.IsLoopback() || ipv4.IsPrivate() || ipv4.IsUnspecified() {
		return 0, "", nil
	}

	// Check cache
	if val, ok := asnCache.Load(cleanIP); ok {
		entry := val.(asnCacheEntry)
		return entry.asn, entry.asOrg, entry.err
	}

	asn, asOrg, err := performCymruLookup(ipv4)
	asnCache.Store(cleanIP, asnCacheEntry{asn: asn, asOrg: asOrg, err: err})
	return asn, asOrg, err
}

func performCymruLookup(ipv4 net.IP) (int, string, error) {
	// Reverse IPv4 octets: 185.199.108.153 -> 153.108.199.185.origin.asn.cymru.com
	revDNS := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ipv4[3], ipv4[2], ipv4[1], ipv4[0])

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	records, err := dnsResolver.LookupTXT(ctx, revDNS)
	if err != nil {
		return 0, "", fmt.Errorf("cymru origin dns lookup: %w", err)
	}

	if len(records) == 0 {
		return 0, "", nil
	}

	// Format: "54113 | 185.199.108.0/24 | US | ripencc | 2017-04-13"
	parts := strings.Split(records[0], "|")
	if len(parts) == 0 {
		return 0, "", nil
	}

	asnStr := strings.TrimSpace(parts[0])
	// If multiple ASNs, take first
	if fields := strings.Fields(asnStr); len(fields) > 0 {
		asnStr = fields[0]
	}

	asnNum, err := strconv.Atoi(asnStr)
	if err != nil {
		return 0, "", fmt.Errorf("parsing asn %q: %w", asnStr, err)
	}

	// Now lookup Org: AS54113.asn.cymru.com
	asOrg := lookupASOrg(asnNum)
	return asnNum, asOrg, nil
}

func lookupASOrg(asnNum int) string {
	cacheKey := fmt.Sprintf("AS%d", asnNum)
	if val, ok := asnCache.Load(cacheKey); ok {
		return val.(asnCacheEntry).asOrg
	}

	asDNS := fmt.Sprintf("AS%d.asn.cymru.com", asnNum)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	records, err := dnsResolver.LookupTXT(ctx, asDNS)
	if err != nil || len(records) == 0 {
		return ""
	}

	// Format: "54113 | US | arin | 2011-10-04 | FASTLY - Fastly, Inc., US"
	parts := strings.Split(records[0], "|")
	if len(parts) < 5 {
		return ""
	}

	org := strings.TrimSpace(parts[4])
	asnCache.Store(cacheKey, asnCacheEntry{asn: asnNum, asOrg: org})
	return org
}
