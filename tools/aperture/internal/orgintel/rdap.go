package orgintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	rdapCache  sync.Map
	httpClient = &http.Client{
		Timeout: 8 * time.Second,
	}
)

// SetHTTPClient overrides the HTTP client for isolated, offline unit testing.
func SetHTTPClient(client *http.Client) {
	httpClient = client
}

// ResetRDAPCache clears the in-memory RDAP cache (useful for testing).
func ResetRDAPCache() {
	rdapCache = sync.Map{}
}

type rdapCacheEntry struct {
	identity *OrgIdentity
	err      error
}

type rdapResponse struct {
	ObjectClassName string        `json:"objectClassName"`
	Handle          string        `json:"handle"`
	LDHName         string        `json:"ldhName"`
	Links           []rdapLink    `json:"links"`
	Entities        []rdapEntity  `json:"entities"`
}

type rdapLink struct {
	Value string `json:"value"`
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type"`
}

type rdapEntity struct {
	ObjectClassName string        `json:"objectClassName"`
	Handle          string        `json:"handle"`
	Roles           []string      `json:"roles"`
	VCardArray      []interface{} `json:"vcardArray"`
	Entities        []rdapEntity  `json:"entities"`
}

// LookupOrgIdentity queries domain RDAP to extract the registrant organization and registrar.
func LookupOrgIdentity(domain string) (*OrgIdentity, error) {
	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	if cleanDomain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	// Check cache
	if val, ok := rdapCache.Load(cleanDomain); ok {
		entry := val.(rdapCacheEntry)
		return entry.identity, entry.err
	}

	identity, err := performRDAPLookup(cleanDomain)
	rdapCache.Store(cleanDomain, rdapCacheEntry{identity: identity, err: err})
	return identity, err
}

func performRDAPLookup(domain string) (*OrgIdentity, error) {
	primaryURL := fmt.Sprintf("https://rdap.org/domain/%s", domain)

	respData, relatedURL, err := fetchRDAP(primaryURL)
	if err != nil {
		return nil, fmt.Errorf("rdap query for %s: %w", domain, err)
	}

	org, registrar := parseRDAPEntities(respData.Entities)

	// If registrant org was not in thin response but there is a related registrar RDAP link, follow it
	if (org == "" || IsPrivacyProxy(org)) && relatedURL != "" {
		if thickData, _, err := fetchRDAP(relatedURL); err == nil {
			thickOrg, thickReg := parseRDAPEntities(thickData.Entities)
			if thickOrg != "" {
				org = thickOrg
			}
			if thickReg != "" {
				registrar = thickReg
			}
		}
	}

	isProxy := IsPrivacyProxy(org)
	conf := 0.0
	if org != "" && !isProxy {
		conf = 0.90
	} else if isProxy {
		conf = 0.10
	}

	identity := &OrgIdentity{
		Domain:         domain,
		RegistrantOrg:  org,
		RegistrarWHOIS: registrar,
		Source:         "icann_rdap_whois",
		Confidence:     conf,
		IsPrivacyProxy: isProxy,
		DiscoveredAt:   time.Now().UTC(),
	}

	return identity, nil
}

func fetchRDAP(url string) (*rdapResponse, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", "Aperture/1.0 (Attack Surface Intelligence; RDAP Client)")
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &rdapResponse{}, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("http %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	var rdap respRDAP
	if err := json.Unmarshal(body, &rdap); err != nil {
		return nil, "", fmt.Errorf("unmarshal rdap: %w", err)
	}

	// Look for related registrar thick RDAP link
	relatedURL := ""
	for _, link := range rdap.Links {
		if link.Rel == "related" && strings.HasPrefix(link.Href, "http") {
			relatedURL = link.Href
			break
		}
	}

	converted := &rdapResponse{
		ObjectClassName: rdap.ObjectClassName,
		Handle:          rdap.Handle,
		LDHName:         rdap.LDHName,
		Links:           rdap.Links,
		Entities:        rdap.Entities,
	}

	return converted, relatedURL, nil
}

type respRDAP struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	LDHName         string       `json:"ldhName"`
	Links           []rdapLink   `json:"links"`
	Entities        []rdapEntity `json:"entities"`
}

func parseRDAPEntities(entities []rdapEntity) (registrantOrg string, registrarName string) {
	for _, ent := range entities {
		roles := ent.Roles
		isRegistrant := hasRole(roles, "registrant")
		isRegistrar := hasRole(roles, "registrar")

		if isRegistrant && registrantOrg == "" {
			registrantOrg = extractOrgFromVCard(ent.VCardArray)
		}
		if isRegistrar && registrarName == "" {
			registrarName = extractOrgOrFNFromVCard(ent.VCardArray)
		}

		// Also check nested entities
		if len(ent.Entities) > 0 {
			nestedOrg, nestedReg := parseRDAPEntities(ent.Entities)
			if registrantOrg == "" && nestedOrg != "" {
				registrantOrg = nestedOrg
			}
			if registrarName == "" && nestedReg != "" {
				registrarName = nestedReg
			}
		}
	}
	return registrantOrg, registrarName
}

func hasRole(roles []string, target string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, target) {
			return true
		}
	}
	return false
}

// extractOrgFromVCard navigates RFC 7095 vcardArray: ["vcard", [ ["org", {...}, "text", "Company Name"], ... ]]
func extractOrgFromVCard(vcard []interface{}) string {
	if len(vcard) < 2 {
		return ""
	}
	items, ok := vcard[1].([]interface{})
	if !ok {
		return ""
	}

	for _, item := range items {
		entry, ok := item.([]interface{})
		if !ok || len(entry) < 4 {
			continue
		}
		propName, ok := entry[0].(string)
		if !ok {
			continue
		}
		if strings.EqualFold(propName, "org") {
			// value is entry[3]
			if val, ok := entry[3].(string); ok && strings.TrimSpace(val) != "" {
				return strings.TrimSpace(val)
			}
		}
	}
	return ""
}

func extractOrgOrFNFromVCard(vcard []interface{}) string {
	org := extractOrgFromVCard(vcard)
	if org != "" {
		return org
	}

	if len(vcard) < 2 {
		return ""
	}
	items, ok := vcard[1].([]interface{})
	if !ok {
		return ""
	}

	for _, item := range items {
		entry, ok := item.([]interface{})
		if !ok || len(entry) < 4 {
			continue
		}
		propName, ok := entry[0].(string)
		if !ok {
			continue
		}
		if strings.EqualFold(propName, "fn") {
			if val, ok := entry[3].(string); ok && strings.TrimSpace(val) != "" {
				return strings.TrimSpace(val)
			}
		}
	}
	return ""
}
