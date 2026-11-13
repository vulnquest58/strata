package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RawResolver resolves DNS via traditional UDP/TCP using the miekg/dns library.
// This provides a different protocol path from DoH for genuine consensus diversity —
// a hostname confirmed by both DoH and raw UDP is much more reliable than two DoH checks.
type RawResolver struct {
	name   string
	server string // "8.8.8.8:53" format
	client *dns.Client
}

// NewRawResolver creates a raw UDP DNS resolver targeting the given server.
func NewRawResolver(name, server string, timeoutSecs int) *RawResolver {
	return &RawResolver{
		name:   name,
		server: server,
		client: &dns.Client{
			Net:     "udp",
			Timeout: time.Duration(timeoutSecs) * time.Second,
		},
	}
}

func (r *RawResolver) Protocol() string { return "raw" }
func (r *RawResolver) Name() string     { return r.name }

// Resolve performs an A + AAAA DNS lookup over raw UDP using miekg/dns.
func (r *RawResolver) Resolve(ctx context.Context, hostname string) Result {
	result := Result{
		Hostname:     hostname,
		Protocol:     "raw",
		ProviderName: r.name,
	}

	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	var allIPs []string
	var cname string

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		ips, cn, err := r.queryRaw(ctx, hostname, qtype)
		if err == nil {
			allIPs = append(allIPs, ips...)
			if cn != "" && cname == "" {
				cname = cn
			}
		}
	}

	result.IPs = allIPs
	result.CNAME = cname
	result.Resolves = len(allIPs) > 0
	return result
}

func (r *RawResolver) queryRaw(ctx context.Context, hostname string, qtype uint16) ([]string, string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(hostname, qtype)
	msg.RecursionDesired = true

	// Use the context deadline if set; otherwise fall back to the client timeout.
	client := r.client
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, "", fmt.Errorf("context deadline already exceeded")
		}
		clientCopy := *r.client
		clientCopy.Timeout = remaining
		client = &clientCopy
	}

	resp, _, err := client.Exchange(msg, r.server)
	if err != nil {
		// Retry once over TCP on truncation.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, "", err
		}
		tcpClient := &dns.Client{Net: "tcp", Timeout: client.Timeout}
		resp, _, err = tcpClient.Exchange(msg, r.server)
		if err != nil {
			return nil, "", err
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, "", fmt.Errorf("DNS rcode %d for %s", resp.Rcode, hostname)
	}

	var ips []string
	var cname string
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.String())
		case *dns.CNAME:
			if cname == "" {
				cname = strings.TrimSuffix(v.Target, ".")
			}
		}
	}
	return ips, cname, nil
}
