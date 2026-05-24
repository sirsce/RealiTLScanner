package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	Host        string
	Port        string
	IP          string
	ServerName  string
	Fingerprint string
	Version     uint16
	IsReality   bool
	Latency     time.Duration
	Error       error
}

// Scanner performs TLS/Reality scanning on target hosts.
type Scanner struct {
	Timeout    time.Duration
	Concurrent int
}

// NewScanner creates a new Scanner with the given timeout and concurrency.
func NewScanner(timeout time.Duration, concurrent int) *Scanner {
	return &Scanner{
		Timeout:    timeout,
		Concurrent: concurrent,
	}
}

// Scan performs a TLS handshake against the given host:port and returns a ScanResult.
func (s *Scanner) Scan(host, port string) ScanResult {
	result := ScanResult{
		Host: host,
		Port: port,
	}

	addr := net.JoinHostPort(host, port)

	// Resolve IP address
	addrs, err := net.LookupHost(host)
	if err == nil && len(addrs) > 0 {
		result.IP = addrs[0]
	}

	dialer := &net.Dialer{
		Timeout: s.Timeout,
	}

	start := time.Now()

	// Perform TLS dial with custom config to capture certificate details
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We want to inspect even self-signed / Reality certs
		MinVersion:         tls.VersionTLS12,
	})

	result.Latency = time.Since(start)

	if err != nil {
		result.Error = fmt.Errorf("TLS dial failed: %w", err)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.Version = state.Version

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.ServerName = cert.Subject.CommonName
		result.Fingerprint = fingerprintCert(cert.Raw)
		result.IsReality = detectReality(state)
	}

	return result
}

// ScanBatch scans a list of host:port pairs concurrently and returns results.
func (s *Scanner) ScanBatch(targets []string) []ScanResult {
	sem := make(chan struct{}, s.Concurrent)
	results := make([]ScanResult, len(targets))
	done := make(chan struct{})

	for i, target := range targets {
		go func(idx int, t string) {
			sem <- struct{}{}
			defer func() {
				<-sem
				done <- struct{}{}
			}()

			host, port, err := net.SplitHostPort(t)
			if err != nil {
				host = t
				port = "443"
			}
			results[idx] = s.Scan(host, port)
		}(i, target)
	}

	for range targets {
		<-done
	}

	return results
}

// detectReality attempts to heuristically detect if the server is running XTLS Reality.
// Reality servers typically present a valid TLS 1.3 connection with a real website's certificate.
func detectReality(state tls.ConnectionState) bool {
	// Reality always uses TLS 1.3
	if state.Version != tls.VersionTLS13 {
		return false
	}
	// Additional heuristics can be added here (e.g., ALPN, session ticket checks)
	return true
}
