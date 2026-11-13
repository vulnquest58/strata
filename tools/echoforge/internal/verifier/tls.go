package verifier

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSVerifier checks TLS certificates to extract SANs and validate hostname matches.
type TLSVerifier struct {
	timeout time.Duration
}

// TLSResult holds the result of a TLS fingerprint check.
type TLSResult struct {
	Hostname    string
	SANs        []string
	CommonName  string
	SANMatch    bool
	Issuer      string
	NotAfter    string
	Reachable   bool
}

// NewTLSVerifier creates a TLS verifier with the given timeout.
func NewTLSVerifier(timeoutSecs int) *TLSVerifier {
	return &TLSVerifier{
		timeout: time.Duration(timeoutSecs) * time.Second,
	}
}

// Check performs a TLS handshake and extracts certificate details.
// It does NOT validate the certificate (InsecureSkipVerify=true) to catch
// misconfigured or self-signed certs that still indicate a live host.
func (v *TLSVerifier) Check(ctx context.Context, hostname string) TLSResult {
	result := TLSResult{Hostname: hostname}

	dialer := &net.Dialer{Timeout: v.timeout}
	addr := fmt.Sprintf("%s:443", hostname)

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec — intentional for recon
		ServerName:         hostname,
	})
	if err != nil {
		return result
	}
	defer conn.Close()

	result.Reachable = true
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return result
	}

	cert := certs[0]
	result.CommonName = cert.Subject.CommonName
	result.NotAfter = cert.NotAfter.Format("2006-01-02")
	if len(cert.Issuer.Organization) > 0 {
		result.Issuer = cert.Issuer.Organization[0]
	}

	// Collect all SANs (DNS names)
	for _, san := range cert.DNSNames {
		san = strings.ToLower(strings.TrimPrefix(san, "*."))
		result.SANs = append(result.SANs, san)
	}

	// Check if our hostname matches the CN or any SAN
	hostLower := strings.ToLower(hostname)
	cnLower := strings.ToLower(strings.TrimPrefix(cert.Subject.CommonName, "*."))

	if cnLower == hostLower || strings.HasSuffix(hostLower, "."+cnLower) {
		result.SANMatch = true
	}
	for _, san := range result.SANs {
		if san == hostLower || strings.HasSuffix(hostLower, "."+san) {
			result.SANMatch = true
			break
		}
	}

	return result
}
