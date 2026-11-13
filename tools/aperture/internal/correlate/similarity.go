package correlate

import (
	"math"
	"strings"
)

// StripTLD removes standard common top-level domain suffixes.
func StripTLD(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	tlds := []string{
		".com", ".net", ".org", ".io", ".dev", ".app", ".co.uk", ".gov", ".edu", ".ai", ".cloud",
	}
	for _, tld := range tlds {
		if strings.HasSuffix(d, tld) {
			d = strings.TrimSuffix(d, tld)
			break
		}
	}
	// If subdomains exist in root domain string (rare for root domains, but safe), take last label
	parts := strings.Split(d, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return d
}

// NamingSimilarity calculates the Jaro-Winkler string similarity between two domain stems.
func NamingSimilarity(domainA, domainB string) float64 {
	s1 := StripTLD(domainA)
	s2 := StripTLD(domainB)

	if s1 == "" || s2 == "" {
		return 0.0
	}
	if s1 == s2 {
		return 1.0
	}

	return jaroWinkler(s1, s2)
}

func jaroWinkler(s1, s2 string) float64 {
	jaro := jaroDistance(s1, s2)
	if jaro < 0.7 {
		return jaro
	}

	// Common prefix length up to 4
	prefixLen := 0
	maxPrefix := 4
	if len(s1) < maxPrefix {
		maxPrefix = len(s1)
	}
	if len(s2) < maxPrefix {
		maxPrefix = len(s2)
	}

	for i := 0; i < maxPrefix; i++ {
		if s1[i] == s2[i] {
			prefixLen++
		} else {
			break
		}
	}

	// Winkler scaling factor p = 0.1
	return jaro + float64(prefixLen)*0.1*(1.0-jaro)
}

func jaroDistance(s1, s2 string) float64 {
	len1 := len(s1)
	len2 := len(s2)

	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	matchWindow := int(math.Floor(float64(int(math.Max(float64(len1), float64(len2))))/2.0)) - 1
	if matchWindow < 0 {
		matchWindow = 0
	}

	s1Matches := make([]bool, len1)
	s2Matches := make([]bool, len2)

	matches := 0
	for i := 0; i < len1; i++ {
		start := int(math.Max(0, float64(i-matchWindow)))
		end := int(math.Min(float64(i+matchWindow+1), float64(len2)))

		for j := start; j < end; j++ {
			if s2Matches[j] {
				continue
			}
			if s1[i] != s2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	transpositions := 0
	k := 0
	for i := 0; i < len1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}

	m := float64(matches)
	t := float64(transpositions) / 2.0

	return (m/float64(len1) + m/float64(len2) + (m-t)/m) / 3.0
}

// JaroNoiseFloor defines the baseline similarity floor (~94th percentile of random unrelated domain pairs).
// Similarity scores below this floor represent incidental letter matching rather than genuine brand linkage.
const JaroNoiseFloor = 0.60

// WeightedConfidence calculates the context-weighted confidence for infrastructure overlap.
// Prevents signal double-counting: shared ASN only promotes confidence if the ASN is private/dedicated (not a public CDN).
// Normalizes naming similarity above JaroNoiseFloor (0.60) so that incidental letter matches don't dilute the CDN penalty.
// Dedicated private ASN (+0.40) provides strong confidence (>= 0.75) even when brand names differ completely (M&A / rebranding).
func WeightedConfidence(base float64, sharedASN bool, isPublicCDN bool, namingSimilarity float64) float64 {
	weight := 1.0

	// 1. الترقية فقط إذا كان الـ ASN مخصصاً ومملوكاً للجهة (وليس مزود CDN عام)
	// يوفر إشارة قوية مستقلة تماماً عن التسمية (لحالات الاستحواذ وإعادة التسمية M&A)
	if sharedASN && !isPublicCDN {
		weight += 0.40
	}

	// 2. خصم إذا كان الطرفان على CDN عام متعدد المشتركين
	if isPublicCDN {
		weight -= 0.30
	}

	// 3. تطبيع تشابه التسمية فوق حاجز الضجيج العشوائي (0.60):
	// درجات Jaro أقل من 0.60 ناتجة عن أحرف عشوائية مشتركة ولا تدل على أي علاقة علامة تجارية
	normSimilarity := 0.0
	if namingSimilarity > JaroNoiseFloor {
		normSimilarity = (namingSimilarity - JaroNoiseFloor) / (1.0 - JaroNoiseFloor)
	}

	// رفع وزن التسمية الفعلي ليكون الإشارة الحاسمة عند وجود CDN عام
	weight += normSimilarity * 0.75

	return math.Min(base*weight, 0.98) // سقف حماية من overconfidence
}
