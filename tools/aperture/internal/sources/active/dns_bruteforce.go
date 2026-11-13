package active

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"aperture/internal/model"
	"aperture/internal/sources"
)

//go:embed wordlists/top10000.txt
var defaultWordlistFS embed.FS

// DNSBruteforce is an active source plugin that resolves candidate subdomains
// from a wordlist directly via raw UDP DNS. Requires --active flag.
//
// Unlike passive sources, this makes direct DNS queries to the target's authoritative
// resolvers, so it reveals subdomains not indexed in any OSINT database.
type DNSBruteforce struct {
	wordlistPath string // empty = use embedded default
	servers      []string
	timeoutSecs  int
}

// NewDNSBruteforce creates a bruteforce plugin.
// wordlistPath: path to a custom wordlist file, or "" to use the embedded top-10000 list.
// servers: raw DNS server addresses in "ip:53" format.
func NewDNSBruteforce(wordlistPath string, servers []string, timeoutSecs int) *DNSBruteforce {
	if len(servers) == 0 {
		servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	return &DNSBruteforce{
		wordlistPath: wordlistPath,
		servers:      servers,
		timeoutSecs:  timeoutSecs,
	}
}

func (d *DNSBruteforce) Name() string                    { return "dns_bruteforce" }
func (d *DNSBruteforce) Category() model.SourceCategory  { return model.SourceActive }
func (d *DNSBruteforce) DefaultPriorReliability() float64 { return 0.90 } // direct resolution = high reliability

func (d *DNSBruteforce) Discover(ctx context.Context, target string) (<-chan sources.RawCandidate, error) {
	words, err := d.loadWords()
	if err != nil {
		return nil, fmt.Errorf("dns_bruteforce: loading wordlist: %w", err)
	}

	out := make(chan sources.RawCandidate, 512)

	go func() {
		defer close(out)

		sem := make(chan struct{}, 50) // 50 concurrent DNS queries
		var wg sync.WaitGroup
		idx := 0 // server round-robin index

		for _, word := range words {
			if ctx.Err() != nil {
				break
			}
			hostname := fmt.Sprintf("%s.%s", word, target)
			server := d.servers[idx%len(d.servers)]
			idx++

			wg.Add(1)
			sem <- struct{}{}
			go func(h, srv string) {
				defer wg.Done()
				defer func() { <-sem }()

				ips := resolveA(ctx, h, srv, d.timeoutSecs)
				if len(ips) == 0 {
					return
				}
				select {
				case out <- sources.RawCandidate{
					AssetID:      h,
					SourcePlugin: d.Name(),
					AssetType:    model.AssetSubdomain,
					RawScore:     95.0,
					Evidence: map[string]any{
						"method":         "dns_bruteforce",
						"resolved_ips":   ips,
						"dns_server":     srv,
					},
				}:
				case <-ctx.Done():
				}
			}(hostname, server)
		}
		wg.Wait()
	}()

	return out, nil
}

// resolveA performs a single A record DNS query via raw UDP.
func resolveA(ctx context.Context, hostname, server string, timeoutSecs int) []string {
	client := &dns.Client{
		Net:     "udp",
		Timeout: time.Duration(timeoutSecs) * time.Second,
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, server)
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return nil
	}

	var ips []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}

// loadWords reads the wordlist from file (if configured) or the embedded default.
func (d *DNSBruteforce) loadWords() ([]string, error) {
	var scanner *bufio.Scanner

	if d.wordlistPath != "" {
		// TODO: open external file
		return nil, fmt.Errorf("external wordlist support will be added in M4 polish")
	}

	// Use embedded wordlist.
	f, err := defaultWordlistFS.Open("wordlists/top10000.txt")
	if err != nil {
		return nil, fmt.Errorf("opening embedded wordlist: %w", err)
	}
	defer f.Close()
	scanner = bufio.NewScanner(f)

	var words []string
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		words = append(words, w)
	}
	return words, scanner.Err()
}
