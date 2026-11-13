//go:build integration

package orgintel

import (
	"os"
	"testing"
)

// TestLiveMARealWorldPair conducts a live RDAP query on a real-world M&A acquisition (Microsoft & Skype)
// proving end-to-end operational capability across live networks.
// Guarded by the integration build tag AND APERTURE_LIVE_TESTS environment variable for absolute CI stability.
func TestLiveMARealWorldPair(t *testing.T) {
	if os.Getenv("APERTURE_LIVE_TESTS") == "" {
		t.Skip("skipping live network RDAP test: APERTURE_LIVE_TESTS environment variable is not set")
	}

	domainA := "microsoft.com"
	domainB := "skype.com"

	idA, errA := LookupOrgIdentity(domainA)
	if errA != nil {
		t.Fatalf("failed live RDAP query for %s: %v", domainA, errA)
	}
	idB, errB := LookupOrgIdentity(domainB)
	if errB != nil {
		t.Fatalf("failed live RDAP query for %s: %v", domainB, errB)
	}

	t.Logf("Live RDAP Response for %s:\n  - Registrant Org: %q\n  - Registrar: %q\n  - IsPrivacyProxy: %v",
		domainA, idA.RegistrantOrg, idA.RegistrarWHOIS, idA.IsPrivacyProxy)
	t.Logf("Live RDAP Response for %s:\n  - Registrant Org: %q\n  - Registrar: %q\n  - IsPrivacyProxy: %v",
		domainB, idB.RegistrantOrg, idB.RegistrarWHOIS, idB.IsPrivacyProxy)

	if idA.IsPrivacyProxy || idB.IsPrivacyProxy {
		t.Fatalf("unexpected proxy flag on genuine corporate entities")
	}

	if idA.RegistrantOrg == "" || idB.RegistrantOrg == "" {
		t.Fatalf("expected non-empty registrant org from live RDAP")
	}

	affiliations := CorrelateOrganizations([]OrgIdentity{*idA, *idB})
	if len(affiliations) != 1 {
		t.Fatalf("expected 1 corporate affiliation from live M&A pair, got %d", len(affiliations))
	}

	aff := affiliations[0]
	t.Logf("CONFIRMED LIVE M&A AFFILIATION:\n  * Domain A: %s\n  * Domain B: %s\n  * Matched Org: %s\n  * Confidence: %.2f\n  * Registrar A: %s\n  * Registrar B: %s",
		aff.DomainA, aff.DomainB, aff.MatchedOrg, aff.Confidence, aff.RegistrarA, aff.RegistrarB)

	if aff.Confidence < 0.90 {
		t.Errorf("expected live affiliation confidence >= 0.90, got %.2f", aff.Confidence)
	}
}
