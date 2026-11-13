package orgintel

import (
	"strings"
	"time"
)

// CorrelateOrganizations examines organizational identities across domains and extracts
// corporate affiliations when a verified, non-proxy legal registrant organization matches.
func CorrelateOrganizations(identities []OrgIdentity) []CorporateAffiliation {
	var affiliations []CorporateAffiliation

	for i := 0; i < len(identities); i++ {
		for j := i + 1; j < len(identities); j++ {
			idA := identities[i]
			idB := identities[j]

			if idA.Domain == idB.Domain {
				continue
			}

			// Reject if either is a privacy proxy, redacted, or missing
			if idA.IsPrivacyProxy || idB.IsPrivacyProxy {
				continue
			}
			if idA.RegistrantOrg == "" || idB.RegistrantOrg == "" {
				continue
			}

			normA := NormalizeCorporateName(idA.RegistrantOrg)
			normB := NormalizeCorporateName(idB.RegistrantOrg)

			if normA == "" || normB == "" {
				continue
			}

			// Exact match on normalized legal corporate entity stem
			if normA == normB {
				isGeneric := IsGenericBusinessName(normA)
				isCorpRegA := IsCorporateRegistrar(idA.RegistrarWHOIS)
				sameRegistrar := idA.RegistrarWHOIS != "" && strings.EqualFold(idA.RegistrarWHOIS, idB.RegistrarWHOIS)

				// Calculate statistically justified confidence:
				// 1. Generic / Ubiquitous names (e.g., "Apex", "Nova", "Summit", or <= 3 letters like "ABC"):
				//    High risk of incidental name collision between unrelated businesses in different jurisdictions.
				//    Confidence is heavily penalized to 0.45 (below threshold).
				//    If verified under the same enterprise brand protection registrar (e.g. MarkMonitor),
				//    it recovers to 0.70.
				// 2. Distinctive Corporate Names (e.g., "Microsoft", "GitHub", multi-word brand):
				//    Base confidence is 0.88.
				//    If verified under the same corporate registrar portfolio, confidence reaches 0.92.
				conf := 0.88
				if isGeneric {
					if sameRegistrar && isCorpRegA {
						conf = 0.70
					} else {
						conf = 0.45
					}
				} else if sameRegistrar {
					if isCorpRegA {
						conf = 0.92
					} else {
						conf = 0.90
					}
				}

				matchedOrg := idA.RegistrantOrg
				if len(idB.RegistrantOrg) > len(matchedOrg) {
					matchedOrg = idB.RegistrantOrg
				}

				affiliations = append(affiliations, CorporateAffiliation{
					DomainA:      idA.Domain,
					DomainB:      idB.Domain,
					MatchedOrg:   matchedOrg,
					RegistrarA:   idA.RegistrarWHOIS,
					RegistrarB:   idB.RegistrarWHOIS,
					Confidence:   conf,
					DiscoveredAt: time.Now().UTC(),
				})
			}
		}
	}

	return affiliations
}
