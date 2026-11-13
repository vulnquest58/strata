package correlate

import (
	"sort"
	"testing"
)

func TestNamingSimilarity(t *testing.T) {
	testCases := []struct {
		domA     string
		domB     string
		minScore float64
		maxScore float64
	}{
		{"github.com", "githubassets.com", 0.85, 1.0}, // Stem prefix match
		{"github.com", "github.io", 1.0, 1.0},         // Exact stem match
		{"stripe.com", "stripdn.com", 0.80, 0.98},     // Typo / close brand
		{"apple.com", "microsoft.com", 0.0, 0.50},     // Unrelated domains
	}

	for _, tc := range testCases {
		score := NamingSimilarity(tc.domA, tc.domB)
		if score < tc.minScore || score > tc.maxScore {
			t.Errorf("NamingSimilarity(%q, %q) = %.4f; expected between %.2f and %.2f",
				tc.domA, tc.domB, score, tc.minScore, tc.maxScore)
		}
	}
}

func TestWeightedConfidence(t *testing.T) {
	base := 0.70

	// Case 1: True Positive (github.com and githubassets.com)
	// sharedASN=true, isPublicCDN=true -> no private ASN bonus, penalty -0.30
	// namingSimilarity ~= 0.90 -> bonus +0.5625
	// weight = 1.0 - 0.30 + 0.5625 = 1.2625 -> conf = 0.70 * 1.2625 = 0.8838 >= 0.85
	simGitHub := NamingSimilarity("github.com", "githubassets.com")
	confGitHub := WeightedConfidence(base, true, true, simGitHub)
	if confGitHub < 0.85 {
		t.Errorf("expected confGitHub >= 0.85, got %.4f", confGitHub)
	}

	// Case 2: Unrelated companies sharing a public CDN (e.g. Cloudflare)
	// sharedASN=true, isPublicCDN=true -> penalty -0.30, namingSimilarity = 0.0
	// weight = 1.0 - 0.30 = 0.70 -> conf = 0.70 * 0.70 = 0.490 < 0.55
	simUnrelated := NamingSimilarity("alpha.com", "zebra.com")
	confUnrelated := WeightedConfidence(base, true, true, simUnrelated)
	if confUnrelated >= 0.55 {
		t.Errorf("expected unrelated CDN overlap to be penalized below 0.55, got %.4f", confUnrelated)
	}

	// Case 3: Private dedicated infrastructure (not public CDN) with shared ASN and high similarity
	// sharedASN=true, isPublicCDN=false (+0.40), namingSimilarity=1.0 (+0.75)
	// weight = 1.0 + 0.40 + 0.75 = 2.15 -> capped at 0.98
	confPrivate := WeightedConfidence(base, true, false, 1.0)
	if confPrivate != 0.98 {
		t.Errorf("expected private infra confidence capped at 0.98, got %.4f", confPrivate)
	}

	// Case 4: Protection ceiling (max 0.98)
	confCeiling := WeightedConfidence(0.90, true, false, 1.0)
	if confCeiling > 0.98 {
		t.Errorf("expected confidence capped at 0.98, got %.4f", confCeiling)
	}
}

func TestConfidenceDiscrimination(t *testing.T) {
	base := 0.70

	// 1. True Positive with naming similarity: github.com and githubassets.com
	// Both on Fastly (AS54113 isPublicCDN=true), but strong brand naming similarity (~0.90)
	simTP := NamingSimilarity("github.com", "githubassets.com")
	confTP := WeightedConfidence(base, true, true, simTP)

	if confTP < 0.85 {
		t.Errorf("expected True Positive confidence >= 0.85, got %.4f", confTP)
	}

	// 2. False Positive: Two unrelated companies on Cloudflare
	// Both on Cloudflare (isPublicCDN=true), no naming similarity (0.0)
	simFP := NamingSimilarity("alpha.com", "zebra.com")
	confFP := WeightedConfidence(base, true, true, simFP)

	if confFP >= 0.55 {
		t.Errorf("expected False Positive confidence < 0.55, got %.4f", confFP)
	}

	// 3. True Positive WITHOUT naming similarity (M&A / Rebranding / Multi-brand holding)
	// Same dedicated private ASN (isPublicCDN=false), completely different names (e.g. google.com <-> alphabet.com, facebook.com <-> meta.com)
	// Must remain high confidence (>= 0.75) based purely on private infrastructure ownership
	confTPNoName := WeightedConfidence(base, true, false, 0.15)
	if confTPNoName < 0.75 {
		t.Errorf("expected True Positive without naming similarity to remain >= 0.75, got %.4f", confTPNoName)
	}

	// 4. Discrimination Deltas (must be >= 0.25)
	deltaBrand := confTP - confFP
	if deltaBrand < 0.25 {
		t.Errorf("expected discrimination delta >= 0.25 between TP with brand (%.4f) and FP (%.4f), got %.4f",
			confTP, confFP, deltaBrand)
	}

	deltaPrivate := confTPNoName - confFP
	if deltaPrivate < 0.25 {
		t.Errorf("expected discrimination delta >= 0.25 between TP private ASN (%.4f) and FP (%.4f), got %.4f",
			confTPNoName, confFP, deltaPrivate)
	}

	t.Logf("Discrimination Verified:\n  - TP (Brand Match on CDN): %.4f (>= 0.85)\n  - TP (Private ASN, No Name Match): %.4f (>= 0.75)\n  - FP (Unrelated on CDN): %.4f (< 0.55)\n  - Delta (Brand vs FP): %.4f (>= 0.25)\n  - Delta (Private ASN vs FP): %.4f (>= 0.25)",
		confTP, confTPNoName, confFP, deltaBrand, deltaPrivate)
}

func TestJaroWinklerStatisticalNoiseFloor(t *testing.T) {
	// Sample of 60 distinct, unrelated domains across diverse industries (generates 1,770 pairs)
	unrelatedDomains := []string{
		"google.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
		"spotify.com", "twitter.com", "linkedin.com", "uber.com", "airbnb.com",
		"dropbox.com", "salesforce.com", "oracle.com", "ibm.com", "intel.com",
		"cisco.com", "adobe.com", "nvidia.com", "samsung.com", "sony.com",
		"toyota.com", "honda.com", "ford.com", "boeing.com", "airbus.com",
		"walmart.com", "target.com", "costco.com", "ikea.com", "nike.com",
		"adidas.com", "starbucks.com", "mcdonalds.com", "pepsi.com", "pfizer.com",
		"visa.com", "mastercard.com", "paypal.com", "stripe.com", "siemens.com",
		"verizon.com", "bbc.com", "cnn.com", "reuters.com", "wikipedia.org",
		"reddit.com", "quora.com", "medium.com", "cloudflare.com", "fastly.com",
		"slack.com", "zoom.com", "shopify.com", "ebay.com", "etsy.com",
		"bmw.com", "audi.com", "spacex.com", "raytheon.com", "palantir.com",
	}

	var scores []float64
	for i := 0; i < len(unrelatedDomains); i++ {
		for j := i + 1; j < len(unrelatedDomains); j++ {
			s := NamingSimilarity(unrelatedDomains[i], unrelatedDomains[j])
			scores = append(scores, s)
		}
	}

	sort.Float64s(scores)
	n := len(scores)

	median := scores[n/2]
	p90 := scores[int(float64(n)*0.90)]
	p95 := scores[int(float64(n)*0.95)]

	// Statistical Assertions:
	// 1. Median random noise must be <= 0.50
	if median > 0.50 {
		t.Errorf("expected median similarity <= 0.50, got %.4f", median)
	}

	// 2. 90th percentile must be <= 0.60
	if p90 > 0.60 {
		t.Errorf("expected 90th percentile <= 0.60, got %.4f", p90)
	}

	// 3. 95th percentile should be <= 0.65
	if p95 > 0.65 {
		t.Errorf("expected 95th percentile <= 0.65, got %.4f", p95)
	}

	t.Logf("Statistical Noise Floor Analysis (N=%d pairs):\n  - Median: %.4f\n  - P90: %.4f\n  - P95: %.4f (JaroNoiseFloor=%.2f sits at the ~94th percentile)",
		n, median, p90, p95, JaroNoiseFloor)
}

func TestWeightedConfidenceCapSaturation(t *testing.T) {
	base := 0.70
	similarities := []float64{0.65, 0.76, 0.85, 0.99}
	results := make([]float64, len(similarities))
	for i, sim := range similarities {
		results[i] = WeightedConfidence(base, true, false, sim) // sharedASN=true, isPublicCDN=false
		t.Logf("namingSimilarity=%.2f -> confidence=%.4f", sim, results[i])
	}

	distinctMap := make(map[float64]bool)
	for _, r := range results {
		distinctMap[r] = true
	}
	distinctCount := len(distinctMap)
	t.Logf("Distinct confidence values count: %d / %d", distinctCount, len(similarities))

	if distinctCount <= 2 {
		t.Logf("SATURATION PROVEN: Multiple distinct naming similarity values hit the cap (confidence=%.4f), proving saturation under private shared ASN", results[0])
	}
}

