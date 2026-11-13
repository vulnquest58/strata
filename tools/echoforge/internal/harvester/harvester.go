package harvester

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// Result wraps a discovered subdomain with its source attribution.
type Result struct {
	Subdomain string
	Source    string
}

// HarvestSummary holds per-source stats and warnings from a harvest run.
type HarvestSummary struct {
	Source  string
	Count   int
	Warning string // non-empty if source had an error
}

// Harvester orchestrates all passive seed sources concurrently.
type Harvester struct {
	domain      string
	stealth     bool
	fullPassive bool
	wordlist    string
}

// New creates a new passive Harvester for the given domain.
func New(domain string, stealth, fullPassive bool, wordlist string) *Harvester {
	return &Harvester{
		domain:      domain,
		stealth:     stealth,
		fullPassive: fullPassive,
		wordlist:    wordlist,
	}
}

// HarvestAllWithSummary runs all passive sources concurrently and returns
// a deduplicated subdomain list plus per-source stats for caller-side display.
func (h *Harvester) HarvestAllWithSummary(ctx context.Context) ([]Result, []HarvestSummary) {
	type sourceResult struct {
		name    string
		entries []string
		err     error
	}

	sources := []struct {
		name  string
		fetch func(ctx context.Context) ([]string, error)
	}{
		{
			name: "crt.sh",
			fetch: func(ctx context.Context) ([]string, error) {
				return NewCRTSHHarvester(h.stealth).Fetch(ctx, h.domain)
			},
		},
		{
			name: "hackertarget",
			fetch: func(ctx context.Context) ([]string, error) {
				return NewHackerTargetHarvester(h.stealth).Fetch(ctx, h.domain)
			},
		},
		{
			name: "anubis",
			fetch: func(ctx context.Context) ([]string, error) {
				return NewAnubisHarvester(h.stealth).Fetch(ctx, h.domain)
			},
		},
		{
			name: "rapiddns",
			fetch: func(ctx context.Context) ([]string, error) {
				return NewRapidDNSHarvester(h.stealth).Fetch(ctx, h.domain)
			},
		},
		{
			name: "wayback",
			fetch: func(ctx context.Context) ([]string, error) {
				return NewWaybackHarvester(h.stealth).Fetch(ctx, h.domain)
			},
		},
		{
			name: "otx",
			fetch: func(ctx context.Context) ([]string, error) {
				return NewOTXHarvester(h.stealth).Fetch(ctx, h.domain)
			},
		},
	}

	if h.fullPassive {
		sources = append(sources, struct {
			name  string
			fetch func(ctx context.Context) ([]string, error)
		}{
			name: "commoncrawl",
			fetch: func(ctx context.Context) ([]string, error) {
				return NewCommonCrawlHarvester(h.stealth).Fetch(ctx, h.domain)
			},
		})
	}

	ch := make(chan sourceResult, len(sources))
	var wg sync.WaitGroup

	for _, src := range sources {
		wg.Add(1)
		go func(name string, fn func(ctx context.Context) ([]string, error)) {
			defer wg.Done()
			log.Debug().Str("source", name).Msg("harvesting")
			entries, err := fn(ctx)
			ch <- sourceResult{name: name, entries: entries, err: err}
		}(src.name, src.fetch)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	seen := make(map[string]bool)
	var results []Result
	var summaries []HarvestSummary
	remoteSuccessCount := 0

	for r := range ch {
		summary := HarvestSummary{Source: r.name}
		if r.err != nil {
			// Shorten common error messages for display
			warn := r.err.Error()
			if len(warn) > 60 {
				warn = warn[:60] + "…"
			}
			summary.Warning = warn
			summaries = append(summaries, summary)
			continue
		}
		if len(r.entries) > 0 {
			remoteSuccessCount++
		}
		summary.Count = len(r.entries)
		summaries = append(summaries, summary)

		for _, sub := range r.entries {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if sub != "" && !seen[sub] {
				seen[sub] = true
				results = append(results, Result{Subdomain: sub, Source: r.name})
			}
		}
	}

	// Load explicit wordlist if provided
	if h.wordlist != "" {
		if wlResults, err := h.loadWordlist(h.wordlist); err == nil {
			wlCount := 0
			for _, sub := range wlResults {
				if !seen[sub] {
					seen[sub] = true
					results = append(results, Result{Subdomain: sub, Source: "wordlist"})
					wlCount++
				}
			}
			summaries = append(summaries, HarvestSummary{Source: "wordlist", Count: wlCount})
		}
	}

	// Fallback: if all remote sources failed, load the built-in common wordlist
	if remoteSuccessCount == 0 {
		builtinPaths := []string{
			filepath.Join("data", "wordlists", "common.txt"),
			filepath.Join("..", "..", "data", "wordlists", "common.txt"),
		}
		for _, path := range builtinPaths {
			if wlResults, err := h.loadWordlist(path); err == nil && len(wlResults) > 0 {
				fbCount := 0
				for _, sub := range wlResults {
					if !seen[sub] {
						seen[sub] = true
						results = append(results, Result{Subdomain: sub, Source: "wordlist-builtin"})
						fbCount++
					}
				}
				summaries = append(summaries, HarvestSummary{
					Source:  "wordlist-builtin",
					Count:   fbCount,
					Warning: "all remote sources unavailable — using built-in wordlist",
				})
				break
			}
		}
	}

	return results, summaries
}

// HarvestAll is the backward-compatible wrapper.
func (h *Harvester) HarvestAll(ctx context.Context) ([]Result, error) {
	results, _ := h.HarvestAllWithSummary(ctx)
	return results, nil
}

// loadWordlist reads subdomain names from a wordlist file and prefixes them with the domain.
func (h *Harvester) loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()

	var results []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if strings.Contains(word, ".") {
			results = append(results, word)
		} else {
			results = append(results, word+"."+h.domain)
		}
	}
	return results, scanner.Err()
}
