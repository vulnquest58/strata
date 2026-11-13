package model

import "time"

// Subdomain represents a discovered subdomain with its metadata and confidence score.
type Subdomain struct {
	Name         string    `json:"name"`
	Confidence   float64   `json:"confidence"`
	Source       string    `json:"source"`
	EchoFrom     []string  `json:"echo_from,omitempty"`
	Resolves     bool      `json:"resolves"`
	Wildcard     bool      `json:"wildcard,omitempty"`  // filtered as wildcard DNS
	IPAddresses  []string  `json:"ip_addresses,omitempty"`
	HTTPStatus   int       `json:"http_status,omitempty"`
	ServerHeader string    `json:"server_header,omitempty"`
	TLSSANMatch  bool      `json:"tls_san_match,omitempty"`
	EchoDepth    int       `json:"echo_depth"`
	FirstSeen    time.Time `json:"first_seen"`
}

// ScanResult is the top-level result of a full EchoForge scan.
type ScanResult struct {
	Domain           string      `json:"domain"`
	ScanID           string      `json:"scan_id"`
	StartTime        time.Time   `json:"start_time"`
	EndTime          time.Time   `json:"end_time"`
	Duration         string      `json:"duration"`
	TotalDiscovered  int         `json:"total_discovered"`
	TotalResolved    int         `json:"total_resolved"`
	HighConfidence   int         `json:"high_confidence"`
	WildcardFiltered int         `json:"wildcard_filtered,omitempty"`
	WildcardDetected bool        `json:"wildcard_detected,omitempty"`
	Subdomains       []Subdomain `json:"subdomains"`
}

// ScanConfig holds all runtime configuration for a scan.
type ScanConfig struct {
	Domain        string
	StealthMode   bool
	EchoDepth     int
	Threads       int
	TimeoutSecs   int
	OutputFormat  string
	OutputFile    string
	MinConfidence float64
	Industry      string
	NoVerify      bool
	NoEvolve      bool
	WordlistPath  string
	FullPassive   bool
	Verbose       bool
	Quiet         bool
	ProxyURL      string
}

// Source constants for subdomain discovery attribution.
const (
	SourceCRTSH       = "crt.sh"
	SourceWayback     = "wayback"
	SourceOTX         = "otx"
	SourceCommonCrawl = "commoncrawl"
	SourceWordlist    = "wordlist"
	SourceEcho        = "echo"
	SourceMarkov      = "markov"
	SourceNGram       = "ngram"
)
