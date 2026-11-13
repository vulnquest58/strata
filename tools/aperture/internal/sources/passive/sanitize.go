package passive

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// rfc1035HostnameRe validates standard DNS hostnames according to RFC 1035 / RFC 1123.
	// Labels up to 63 chars, alphanumeric and hyphens, no leading/trailing hyphens.
	rfc1035HostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

	// formatStringRe catches unreplaced format specifiers like %s, %d, %v, %x.
	formatStringRe = regexp.MustCompile(`%[a-zA-Z0-9]`)
)

// SanitizeHostname validates and cleans a raw hostname candidate for a given target domain.
// It returns the normalized hostname and true if valid, or "", false if invalid or corrupt.
func SanitizeHostname(raw string, target string) (string, bool) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return "", false
	}

	// Reject any format-string residues (%s, %d, etc.)
	if formatStringRe.MatchString(raw) {
		return "", false
	}

	// Strip leading wildcard (*.) if present, e.g. *.sub.domain.com -> sub.domain.com
	for strings.HasPrefix(raw, "*.") {
		raw = strings.TrimPrefix(raw, "*.")
		raw = strings.TrimLeft(raw, ".")
	}

	if raw == "" {
		return "", false
	}

	// Reject control characters, spaces, or URL fragments
	if strings.ContainsAny(raw, " \t\r\n/\\:;?#@!$^&*()=+[]{}|'\"<>") {
		return "", false
	}

	// Validate against RFC 1035 / 1123 hostname structure
	if !rfc1035HostnameRe.MatchString(raw) {
		return "", false
	}

	// Scope validation: must match target domain or be a subdomain of target
	target = strings.TrimSpace(strings.ToLower(target))
	if target != "" {
		if raw != target && !strings.HasSuffix(raw, "."+target) {
			return "", false
		}
	}

	return raw, true
}

// SanitizeURL validates and cleans a raw URL.
// Rejects unreplaced format strings (%s, %d), unparseable URIs, and missing scheme/host.
func SanitizeURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	// Reject any unreplaced format strings like %s, %d (allow standard hex encoding like %20)
	if strings.Contains(raw, "%s") || strings.Contains(raw, "%d") || strings.Contains(raw, "%v") {
		return "", false
	}

	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return "", false
	}

	// Scheme must be http or https
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}

	return parsed.String(), true
}
