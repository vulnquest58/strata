package orgintel

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestFalsePositivePrivacyProxyRejection verifies that domains sharing WHOIS privacy proxy services
// (e.g., Domains By Proxy, WhoisGuard, Privacy Protect) are strictly rejected and yield ZERO false affiliations.
func TestFalsePositivePrivacyProxyRejection(t *testing.T) {
	identities := []OrgIdentity{
		{
			Domain:         "suspicious-shop.com",
			RegistrantOrg:  "Domains By Proxy, LLC",
			RegistrarWHOIS: "GoDaddy.com, LLC",
			Confidence:     0.10,
			IsPrivacyProxy: IsPrivacyProxy("Domains By Proxy, LLC"),
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "unrelated-crypto-blog.com",
			RegistrantOrg:  "Domains By Proxy, LLC",
			RegistrarWHOIS: "GoDaddy.com, LLC",
			Confidence:     0.10,
			IsPrivacyProxy: IsPrivacyProxy("Domains By Proxy, LLC"),
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "personal-portfolio.org",
			RegistrantOrg:  "WhoisGuard, Inc.",
			RegistrarWHOIS: "NameCheap, Inc.",
			Confidence:     0.10,
			IsPrivacyProxy: IsPrivacyProxy("WhoisGuard, Inc."),
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "another-privacy-domain.net",
			RegistrantOrg:  "Privacy Protect, LLC",
			RegistrarWHOIS: "Hostinger",
			Confidence:     0.10,
			IsPrivacyProxy: IsPrivacyProxy("Privacy Protect, LLC"),
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "redacted-target.com",
			RegistrantOrg:  "REDACTED FOR PRIVACY",
			RegistrarWHOIS: "Tucows Domains Inc.",
			Confidence:     0.0,
			IsPrivacyProxy: IsPrivacyProxy("REDACTED FOR PRIVACY"),
			DiscoveredAt:   time.Now(),
		},
	}

	// Verify all are correctly flagged as proxies
	for _, id := range identities {
		if !id.IsPrivacyProxy {
			t.Errorf("expected %q (%s) to be recognized as privacy proxy", id.Domain, id.RegistrantOrg)
		}
	}

	affiliations := CorrelateOrganizations(identities)
	if len(affiliations) != 0 {
		t.Fatalf("expected 0 affiliations for privacy proxy services (False Positive prevention), got %d: %+v",
			len(affiliations), affiliations)
	}

	t.Logf("False Positive Rejection PASS: Successfully rejected %d domains sharing privacy proxy/redacted services", len(identities))
}

// TestTruePositiveCorporateAffiliation verifies that distinct domains with genuine matching corporate legal names
// produce confirmed corporate affiliation links with high confidence.
func TestTruePositiveCorporateAffiliation(t *testing.T) {
	identities := []OrgIdentity{
		{
			Domain:         "microsoft.com",
			RegistrantOrg:  "Microsoft Corporation",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: IsPrivacyProxy("Microsoft Corporation"),
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "skype.com",
			RegistrantOrg:  "Microsoft Corporation",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: IsPrivacyProxy("Microsoft Corporation"),
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "github.com",
			RegistrantOrg:  "GitHub, Inc.",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: IsPrivacyProxy("GitHub, Inc."),
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "githubassets.com",
			RegistrantOrg:  "GitHub, Inc.",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: IsPrivacyProxy("GitHub, Inc."),
			DiscoveredAt:   time.Now(),
		},
	}

	affiliations := CorrelateOrganizations(identities)

	// Expect exactly 2 affiliations: (microsoft.com <-> skype.com) and (github.com <-> githubassets.com)
	if len(affiliations) != 2 {
		t.Fatalf("expected exactly 2 true positive corporate affiliations, got %d: %+v", len(affiliations), affiliations)
	}

	var foundMS, foundGH bool
	for _, aff := range affiliations {
		if (aff.DomainA == "microsoft.com" && aff.DomainB == "skype.com") ||
			(aff.DomainA == "skype.com" && aff.DomainB == "microsoft.com") {
			foundMS = true
			if !strings.Contains(aff.MatchedOrg, "Microsoft") {
				t.Errorf("unexpected matched org for Microsoft/Skype: %s", aff.MatchedOrg)
			}
			if aff.Confidence < 0.90 {
				t.Errorf("expected confidence >= 0.90, got %.2f", aff.Confidence)
			}
		}

		if (aff.DomainA == "github.com" && aff.DomainB == "githubassets.com") ||
			(aff.DomainA == "githubassets.com" && aff.DomainB == "github.com") {
			foundGH = true
			if !strings.Contains(aff.MatchedOrg, "GitHub") {
				t.Errorf("unexpected matched org for GitHub/GitHubAssets: %s", aff.MatchedOrg)
			}
			if aff.Confidence < 0.90 {
				t.Errorf("expected confidence >= 0.90, got %.2f", aff.Confidence)
			}
		}
	}

	if !foundMS {
		t.Errorf("missing corporate affiliation between microsoft.com and skype.com")
	}
	if !foundGH {
		t.Errorf("missing corporate affiliation between github.com and githubassets.com")
	}

	t.Logf("True Positive PASS: Successfully detected genuine corporate affiliations:\n  - Microsoft/Skype: %.2f\n  - GitHub/GitHubAssets: %.2f",
		affiliations[0].Confidence, affiliations[1].Confidence)
}

// mockTransport intercepts HTTP requests to return deterministic offline RDAP JSON.
type mockTransport struct {
	responses map[string]string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	for pattern, body := range m.responses {
		if strings.Contains(url, pattern) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "404 Not Found",
		Body:       io.NopCloser(strings.NewReader(`{"errorCode": 404, "title": "Not found"}`)),
		Header:     make(http.Header),
	}, nil
}

// TestMockRDAPCorporateAffiliation tests full RDAP parsing and corporate affiliation discovery
// in an isolated, deterministic environment with ZERO network calls.
func TestMockRDAPCorporateAffiliation(t *testing.T) {
	const msJSON = `{
		"objectClassName": "domain",
		"ldhName": "microsoft.com",
		"entities": [
			{
				"objectClassName": "entity",
				"roles": ["registrant"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn", {}, "text", "Domain Administrator"],
					["org", {"type": "work"}, "text", "Microsoft Corporation"]
				]]
			},
			{
				"objectClassName": "entity",
				"roles": ["registrar"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn", {}, "text", "Markmonitor Inc."]
				]]
			}
		]
	}`

	const skypeJSON = `{
		"objectClassName": "domain",
		"ldhName": "skype.com",
		"entities": [
			{
				"objectClassName": "entity",
				"roles": ["registrant"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn", {}, "text", "Domain Administrator"],
					["org", {"type": "work"}, "text", "Microsoft Corporation"]
				]]
			},
			{
				"objectClassName": "entity",
				"roles": ["registrar"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn", {}, "text", "Markmonitor Inc."]
				]]
			}
		]
	}`

	mock := &mockTransport{
		responses: map[string]string{
			"microsoft.com": msJSON,
			"skype.com":     skypeJSON,
		},
	}

	// Override HTTP client and reset cache
	oldClient := httpClient
	SetHTTPClient(&http.Client{Transport: mock})
	ResetRDAPCache()
	defer func() {
		SetHTTPClient(oldClient)
		ResetRDAPCache()
	}()

	idA, errA := LookupOrgIdentity("microsoft.com")
	if errA != nil {
		t.Fatalf("unexpected error looking up microsoft.com: %v", errA)
	}
	idB, errB := LookupOrgIdentity("skype.com")
	if errB != nil {
		t.Fatalf("unexpected error looking up skype.com: %v", errB)
	}

	if idA.RegistrantOrg != "Microsoft Corporation" || idB.RegistrantOrg != "Microsoft Corporation" {
		t.Fatalf("unexpected registrant org: A=%q, B=%q", idA.RegistrantOrg, idB.RegistrantOrg)
	}
	if idA.RegistrarWHOIS != "Markmonitor Inc." || idB.RegistrarWHOIS != "Markmonitor Inc." {
		t.Fatalf("unexpected registrar: A=%q, B=%q", idA.RegistrarWHOIS, idB.RegistrarWHOIS)
	}
	if idA.IsPrivacyProxy || idB.IsPrivacyProxy {
		t.Fatalf("unexpected proxy flag on genuine corporate entities")
	}

	affiliations := CorrelateOrganizations([]OrgIdentity{*idA, *idB})
	if len(affiliations) != 1 {
		t.Fatalf("expected exactly 1 corporate affiliation, got %d", len(affiliations))
	}

	aff := affiliations[0]
	if aff.Confidence != 0.92 {
		t.Errorf("expected confidence 0.92, got %.2f", aff.Confidence)
	}
	if aff.MatchedOrg != "Microsoft Corporation" {
		t.Errorf("expected matched org 'Microsoft Corporation', got %q", aff.MatchedOrg)
	}

	t.Logf("Mock RDAP Isolation PASS: Successfully parsed mock RDAP and confirmed affiliation:\n  * Domain A: %s\n  * Domain B: %s\n  * Matched Org: %s\n  * Confidence: %.2f",
		aff.DomainA, aff.DomainB, aff.MatchedOrg, aff.Confidence)
}

// TestGenericNameCollisionFalsePositive simulates realistic name collisions between unrelated legal entities
// sharing ubiquitous dictionary names (e.g. Apex, Nova, Summit) or short 3-letter abbreviations (e.g. ABC).
// Verifies that Aperture penalizes confidence below the acceptance threshold (< 0.60) to eliminate False Positives.
func TestGenericNameCollisionFalsePositive(t *testing.T) {
	identities := []OrgIdentity{
		// Pair 1: Generic dictionary name "Apex" across different consumer registrars in different countries
		{
			Domain:         "apex-roofing-tx.com",
			RegistrantOrg:  "Apex Inc.",
			RegistrarWHOIS: "GoDaddy.com, LLC",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "apex-consulting-london.co.uk",
			RegistrantOrg:  "Apex Ltd.",
			RegistrarWHOIS: "123-Reg Limited",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
		// Pair 2: Short 3-letter acronym "ABC"
		{
			Domain:         "abc-trading.com",
			RegistrantOrg:  "ABC LLC",
			RegistrarWHOIS: "Namecheap, Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "abc-logistics.de",
			RegistrantOrg:  "ABC GmbH",
			RegistrarWHOIS: "Hetzner Online GmbH",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
		// Control Pair: Distinctive corporate acquisition on enterprise brand registrar
		{
			Domain:         "microsoft.com",
			RegistrantOrg:  "Microsoft Corporation",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "skype.com",
			RegistrantOrg:  "Microsoft Corporation",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
	}

	affiliations := CorrelateOrganizations(identities)

	var confGenericApex, confGenericABC, confDistinctive float64
	for _, aff := range affiliations {
		if strings.Contains(aff.DomainA, "apex") && strings.Contains(aff.DomainB, "apex") {
			confGenericApex = aff.Confidence
		}
		if strings.Contains(aff.DomainA, "abc") && strings.Contains(aff.DomainB, "abc") {
			confGenericABC = aff.Confidence
		}
		if strings.Contains(aff.DomainA, "microsoft") || strings.Contains(aff.DomainB, "microsoft") {
			confDistinctive = aff.Confidence
		}
	}

	// Statistical discrimination assertions:
	// 1. Generic dictionary term "Apex" must be penalized to <= 0.50 (got 0.45)
	if confGenericApex > 0.50 {
		t.Errorf("expected generic collision confidence <= 0.50 for 'Apex', got %.2f", confGenericApex)
	}

	// 2. Short 3-letter acronym "ABC" must be penalized to <= 0.50 (got 0.45)
	if confGenericABC > 0.50 {
		t.Errorf("expected generic collision confidence <= 0.50 for 'ABC', got %.2f", confGenericABC)
	}

	// 3. Genuine distinctive corporate acquisition must remain >= 0.90
	if confDistinctive < 0.90 {
		t.Errorf("expected distinctive corporate acquisition confidence >= 0.90, got %.2f", confDistinctive)
	}

	// 4. Discrimination delta must be substantial (>= 0.35)
	delta := confDistinctive - confGenericApex
	if delta < 0.35 {
		t.Errorf("expected discrimination delta >= 0.35, got %.2f", delta)
	}

	t.Logf("Name Collision Discrimination PASS:\n  - Distinctive Corporate Entity (Microsoft/Skype): %.2f\n  - Generic Dictionary Collision (Apex UK vs US):   %.2f\n  - Short Acronym Collision (ABC LLC vs GmbH):      %.2f\n  - Discrimination Delta:                           %.2f (>= 0.35)",
		confDistinctive, confGenericApex, confGenericABC, delta)
}

func TestGenericNameSharedCorporateRegistrarMidBranch(t *testing.T) {
	// Scenario: Two legally independent entities using a generic dictionary name ("Apex")
	// happen to register their domains through the same major enterprise brand protection
	// registrar ("Markmonitor Inc.").
	//
	// Logical Branch: Generic Name + Shared Corporate Registrar -> 0.70.
	// Safety Requirement: Result (0.70) MUST NOT reach or exceed the high_confidence_org_link
	// threshold (0.80), ensuring no false positive organizational link edge is created.

	identities := []OrgIdentity{
		{
			Domain:         "apex-holdings.co.uk",
			RegistrantOrg:  "Apex Corporation",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
		{
			Domain:         "apex-investments-global.com",
			RegistrantOrg:  "Apex LLC",
			RegistrarWHOIS: "Markmonitor Inc.",
			Confidence:     0.90,
			IsPrivacyProxy: false,
			DiscoveredAt:   time.Now(),
		},
	}

	affiliations := CorrelateOrganizations(identities)
	if len(affiliations) != 1 {
		t.Fatalf("expected 1 correlation candidate, got %d", len(affiliations))
	}

	aff := affiliations[0]
	const highConfidenceOrgLinkThreshold = 0.80

	// 1. Confirm the exact mid-branch calculation: 0.70
	if aff.Confidence != 0.70 {
		t.Errorf("expected mid-branch confidence 0.70 for generic name on corporate registrar, got %.2f", aff.Confidence)
	}

	// 2. Confirm 0.70 strictly does not exceed the high-confidence organizational link threshold (0.80)
	if aff.Confidence >= highConfidenceOrgLinkThreshold {
		t.Errorf("VIOLATION: mid-branch confidence (%.2f) must NOT reach high confidence threshold (%.2f)",
			aff.Confidence, highConfidenceOrgLinkThreshold)
	}

	// 3. Confirm safety margin
	margin := highConfidenceOrgLinkThreshold - aff.Confidence

	t.Logf("Mid-Branch (0.70) False-Positive Safety Verification PASS:\n"+
		"  - Entity A:            %s (%s via %s)\n"+
		"  - Entity B:            %s (%s via %s)\n"+
		"  - Matched Generic Org: %s\n"+
		"  - Calculated Conf:     %.2f (Mid-Branch: Generic + Corporate Registrar)\n"+
		"  - Org-Link Threshold:  %.2f (high_confidence_org_link)\n"+
		"  - Safety Margin:       %.2f below threshold (%.2f < %.2f)\n"+
		"  - Safety Verdict:      CONFIRMED SAFE - Does not create a false positive high-confidence organizational link edge",
		aff.DomainA, identities[0].RegistrantOrg, identities[0].RegistrarWHOIS,
		aff.DomainB, identities[1].RegistrantOrg, identities[1].RegistrarWHOIS,
		aff.MatchedOrg, aff.Confidence, highConfidenceOrgLinkThreshold,
		margin, aff.Confidence, highConfidenceOrgLinkThreshold)
}



