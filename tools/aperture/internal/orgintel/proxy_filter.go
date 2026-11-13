package orgintel

import (
	"regexp"
	"strings"
)

// knownProxies contains known WHOIS privacy and proxy providers.
var knownProxies = []string{
	"domains by proxy",
	"whoisguard",
	"withheld for privacy",
	"privacy protect",
	"contact privacy",
	"private by design",
	"proxy protection",
	"identity protection service",
	"dnstination",
	"super privacy service",
	"automattic privacy",
	"whois privacy corp",
	"privacy guardian",
	"anonymize",
	"privacy hero",
	"mydomain privacy",
	"tucows privacy",
	"redacted for privacy",
	"redacted registrant",
	"data protected",
	"gdpr masked",
	"private registrant",
	"privacy service",
	"registration private",
}

var proxyKeywords = []string{
	"privacy",
	"proxy",
	"whoisguard",
	"withheld",
	"redacted",
	"anonymize",
	"anonymized",
}

// IsPrivacyProxy checks if a registrant organization string indicates a privacy proxy service or redacted record.
func IsPrivacyProxy(orgName string) bool {
	clean := strings.ToLower(strings.TrimSpace(orgName))
	if clean == "" {
		return true
	}

	// 1. Direct match or substring in known proxy blocklist
	for _, proxy := range knownProxies {
		if strings.Contains(clean, proxy) {
			return true
		}
	}

	// 2. Keyword heuristic checks for combined phrases
	for _, kw := range proxyKeywords {
		if strings.Contains(clean, kw) {
			return true
		}
	}

	return false
}

var corporateSuffixes = []string{
	"corporation",
	"corp.",
	"corp",
	"incorporated",
	"inc.",
	"inc",
	"limited liability company",
	"llc",
	"l.l.c.",
	"limited",
	"ltd.",
	"ltd",
	"company",
	"co.",
	"co",
	"gmbh",
	"s.a.",
	"s.r.o.",
	"pty",
	"plc",
	"ag",
}

var nonAlphaNumRegex = regexp.MustCompile(`[^a-z0-9\s]+`)
var multiSpaceRegex = regexp.MustCompile(`\s+`)

// NormalizeCorporateName strips legal entity suffixes and punctuation for accurate identity matching.
// Example: "Microsoft Corporation" -> "microsoft"
// Example: "GitHub, Inc." -> "github"
func NormalizeCorporateName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}

	// Replace non-alphanumeric (except spaces) with space
	n = nonAlphaNumRegex.ReplaceAllString(n, " ")
	n = multiSpaceRegex.ReplaceAllString(n, " ")
	n = strings.TrimSpace(n)

	words := strings.Fields(n)
	if len(words) == 0 {
		return ""
	}

	// Strip trailing corporate suffixes
	cleanedWords := make([]string, 0, len(words))
	for _, w := range words {
		isSuffix := false
		for _, sfx := range corporateSuffixes {
			cleanSfx := strings.Trim(sfx, ".")
			if w == cleanSfx {
				isSuffix = true
				break
			}
		}
		if !isSuffix {
			cleanedWords = append(cleanedWords, w)
		}
	}

	result := strings.Join(cleanedWords, " ")
	if result == "" {
		// If the name was only suffixes, fallback to original cleaned
		return n
	}
	return result
}

var genericBusinessNames = map[string]bool{
	// Classic single-word dictionary stems
	"apex":          true,
	"summit":        true,
	"nova":          true,
	"delta":         true,
	"atlas":         true,
	"beacon":        true,
	"pinnacle":      true,
	"matrix":        true,
	"nexus":         true,
	"global":        true,
	"solutions":     true,
	"holdings":      true,
	"ventures":      true,
	"management":    true,
	"international": true,
	"group":         true,
	"consulting":    true,
	"services":      true,
	"digital":       true,
	"enterprises":   true,
	"capital":       true,
	"investments":   true,
	"technologies":  true,
	"media":         true,
	"infinity":      true,
	"horizon":       true,
	"prime":         true,
	"vanguard":      true,
	"alliance":      true,
	"genesis":       true,
	"phoenix":       true,
	"quantum":       true,
	"omega":         true,

	// Expanded enterprise dictionary stems (Track B)
	"zenith":        true,
	"vertex":        true,
	"elite":         true,
	"premier":       true,
	"dynamic":       true,
	"innovative":    true,
	"strategic":     true,
	"vision":        true,
	"forward":       true,
	"insight":       true,
	"catalyst":      true,
	"synergy":       true,
	"momentum":      true,
	"vantage":       true,
	"ascent":        true,
	"core":          true,
	"unified":       true,
	"systems":       true,
	"networks":      true,
	"partners":      true,
	"standard":      true,
	"general":       true,
	"national":      true,
	"central":       true,
	"universal":     true,
	"enterprise":    true,
	"united":        true,
	"pacific":       true,
	"atlantic":      true,
	"first":         true,
	"direct":        true,
	"precision":     true,
	"frontier":      true,
	"foundation":    true,
	"optimum":       true,
	"elevate":       true,
	"integrity":     true,
	"sterling":      true,
	"sovereign":     true,
	"paramount":     true,
	"crest":         true,
	"compass":       true,
	"cornerstone":   true,
	"pioneer":       true,
	"trident":       true,
	"titan":         true,
	"legacy":        true,
	"axiom":         true,
	"spectrum":      true,
	"vector":        true,
	"fusion":        true,
	"clarity":       true,
	"focus":         true,
	"connect":       true,
	"link":          true,
	"stream":        true,
	"pulse":         true,
	"spark":         true,
	"logic":         true,
	"sync":          true,
	"element":       true,
	"bridge":        true,
	"gateway":       true,
	"vista":         true,
	"logistics":     true,
	"analytics":     true,
	"security":      true,
	"cyber":         true,
	"labs":          true,
	"studios":       true,
	"properties":    true,
	"realty":        true,
	"financial":     true,
	"advisors":      true,
	"asset":         true,
	"assets":        true,
}

// IsGenericBusinessName checks if a normalized corporate stem is an ubiquitous dictionary term,
// short abbreviation (<= 3 letters), or multi-word generic combination with high probability of incidental
// cross-jurisdictional name collision.
func IsGenericBusinessName(stem string) bool {
	s := strings.ToLower(strings.TrimSpace(stem))
	if len(s) <= 3 {
		return true // 3 letters or fewer is an acronym prone to worldwide collisions (e.g. "abc", "xyz")
	}
	if genericBusinessNames[s] {
		return true
	}
	// Check if multi-word stem consists entirely of generic business words (e.g. "vertex solutions", "prime holdings")
	words := strings.Fields(s)
	if len(words) > 1 {
		allGeneric := true
		for _, w := range words {
			if !genericBusinessNames[w] && len(w) > 3 {
				allGeneric = false
				break
			}
		}
		if allGeneric {
			return true
		}
	}
	return false
}

var corporateRegistrars = []string{
	"markmonitor",
	"csc corporate domains",
	"corporation service company",
	"safenames",
	"lexsynergy",
	"com laude",
	"clarivate",
}

// IsCorporateRegistrar checks if the registrar is an enterprise brand-protection registrar (e.g., MarkMonitor, CSC)
// where registrations require verified corporate identity and authorization.
func IsCorporateRegistrar(registrar string) bool {
	reg := strings.ToLower(strings.TrimSpace(registrar))
	for _, cr := range corporateRegistrars {
		if strings.Contains(reg, cr) {
			return true
		}
	}
	return false
}
