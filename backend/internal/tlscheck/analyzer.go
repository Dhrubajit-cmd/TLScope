package tlscheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"tlscope/internal/models"
)

var (
	// RFC 1123 hostname regex (labels 1-63 alphanumeric/hyphen, total length <= 253)
	hostnameLabelRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidateHostname verifies that the input is a well-formed DNS hostname,
// rejecting full URLs, schemes, arbitrary ports, IP literals, and invalid formats.
func ValidateHostname(input string) (string, error) {
	cleaned := strings.TrimSpace(strings.ToLower(input))
	if cleaned == "" {
		return "", errors.New("hostname cannot be empty")
	}

	// Reject IP literals (IPv4 and IPv6)
	if net.ParseIP(cleaned) != nil {
		return "", errors.New("invalid format: IP address literals are prohibited; please enter a valid DNS hostname")
	}

	// Reject full URLs or URI schemes
	if strings.Contains(cleaned, "://") || strings.Contains(cleaned, "/") ||
		strings.Contains(cleaned, "?") || strings.Contains(cleaned, "#") ||
		strings.Contains(cleaned, "@") {
		return "", errors.New("invalid format: full URLs, paths, or query parameters are not permitted (enter only a domain name, e.g., example.com)")
	}

	// Reject port specification (e.g., example.com:443 or :80)
	if strings.Contains(cleaned, ":") {
		return "", errors.New("invalid format: port specification is not permitted; assessment is strictly restricted to standard HTTPS port 443")
	}

	// Reject reserved localhost explicitly
	if cleaned == "localhost" {
		return "", errors.New("domain \"localhost\" is a reserved, local, or non-public domain name")
	}

	// Total length check (RFC 1035 / RFC 1123 max 253 chars)
	if len(cleaned) > 253 {
		return "", errors.New("hostname exceeds maximum permissible length of 253 characters")
	}

	// Disallow leading or trailing dots
	if strings.HasPrefix(cleaned, ".") || strings.HasSuffix(cleaned, ".") {
		return "", errors.New("hostname cannot start or end with a dot")
	}

	// Split labels
	labels := strings.Split(cleaned, ".")
	if len(labels) < 2 {
		return "", errors.New("hostname must contain at least two domain labels (e.g., domain.tld); single-label or intranet names are disallowed")
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("domain labels must be between 1 and 63 characters in length")
		}
		if !hostnameLabelRegex.MatchString(label) {
			return "", fmt.Errorf("domain label %q contains invalid characters or illegal hyphen placement", label)
		}
	}

	// Check top-level domain (TLD): cannot be entirely numeric
	tld := labels[len(labels)-1]
	allDigits := true
	for _, r := range tld {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", errors.New("top-level domain cannot be purely numeric")
	}

	// Explicitly prohibit known intranet/reserved domains
	reservedTLDs := map[string]bool{
		"local":    true,
		"internal": true,
		"lan":      true,
		"home":     true,
		"corp":     true,
		"onion":    true,
	}
	if reservedTLDs[tld] || cleaned == "localhost" {
		return "", fmt.Errorf("domain %q is a reserved, local, or non-public domain name", cleaned)
	}

	return cleaned, nil
}

// IsSafeIP inspects an IP address to ensure it does not target loopback, private RFC1918,
// link-local, multicast, carrier-grade NAT, or other prohibited internal subnets (SSRF protection).
func IsSafeIP(ip net.IP) (bool, string) {
	if ip == nil {
		return false, "invalid or nil IP address"
	}

	// Unspecified (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return false, "target resolves to an unspecified address (0.0.0.0 or ::)"
	}

	// Loopback (127.0.0.0/8 or ::1)
	if ip.IsLoopback() {
		return false, "target resolves to a loopback address (127.0.0.0/8 or ::1)"
	}

	// Multicast
	if ip.IsMulticast() {
		return false, "target resolves to a multicast address"
	}

	// Link-local (169.254.0.0/16 or fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false, "target resolves to a link-local address (169.254.0.0/16 or fe80::/10)"
	}

	// Standard Go private check (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
	if ip.IsPrivate() {
		return false, "target resolves to a private RFC 1918 or RFC 4193 internal subnet"
	}

	// Check special IPv4 ranges:
	// - Carrier Grade NAT (100.64.0.0/10)
	// - TEST-NET-1 (192.0.2.0/24), TEST-NET-2 (198.51.100.0/24), TEST-NET-3 (203.0.113.0/24)
	// - Benchmarking (198.18.0.0/15)
	// - Reserved (240.0.0.0/4)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && (ip4[1]&0xc0) == 64 {
			return false, "target resolves to a Carrier-Grade NAT address (100.64.0.0/10)"
		}
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return false, "target resolves to TEST-NET-1 (192.0.2.0/24)"
		}
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return false, "target resolves to TEST-NET-2 (198.51.100.0/24)"
		}
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return false, "target resolves to TEST-NET-3 (203.0.113.0/24)"
		}
		if ip4[0] == 198 && (ip4[1]&0xfe) == 18 {
			return false, "target resolves to benchmarking range (198.18.0.0/15)"
		}
		if (ip4[0] & 0xf0) == 240 {
			return false, "target resolves to reserved class E address space (240.0.0.0/4)"
		}
	}

	return true, ""
}

// ResolveSafeDestination performs DNS lookup for the hostname and ensures all returned IP
// addresses are safe public destinations, returning the validated IP to be dialed.
func ResolveSafeDestination(ctx context.Context, hostname string) (string, error) {
	resolver := &net.Resolver{}
	dnsCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(dnsCtx, hostname)
	if err != nil {
		return "", fmt.Errorf("DNS resolution failed for hostname %q: %w", hostname, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("DNS resolution yielded no IP addresses for %q", hostname)
	}

	// Verify all resolved IPs against SSRF rules to prevent DNS-rebinding or split-view attacks
	var validIP string
	for _, ipAddr := range ips {
		safe, reason := IsSafeIP(ipAddr.IP)
		if !safe {
			return "", fmt.Errorf("prohibited destination: DNS record for %q resolved to restricted address %s (%s)", hostname, ipAddr.IP.String(), reason)
		}
		if validIP == "" {
			validIP = ipAddr.IP.String()
		}
	}

	return validIP, nil
}

// PerformTLSAssessment connects to port 443 of the validated destination, negotiates TLS,
// extracts certificates, runs verification algorithms, and returns a complete AssessmentResult.
func PerformTLSAssessment(ctx context.Context, inputHostname string) (*models.AssessmentResult, error) {
	startTime := time.Now()

	// 1. Validate hostname
	hostname, err := ValidateHostname(inputHostname)
	if err != nil {
		return nil, fmt.Errorf("hostname validation error: %w", err)
	}

	assessment := &models.AssessmentResult{
		ID:        fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		Hostname:  hostname,
		Port:      443,
		Timestamp: startTime,
		Status:    "incomplete",
		ServerName: hostname,
		Validation: models.ValidationResult{
			CompletedChecks:  make([]models.CheckResult, 0),
			IncompleteChecks: make([]string, 0),
		},
		Findings: make([]models.Finding, 0),
	}

	// 2. DNS Resolution with SSRF Prevention
	resolvedIP, err := ResolveSafeDestination(ctx, hostname)
	if err != nil {
		assessment.Status = "failed"
		assessment.ErrorMessage = err.Error()
		assessment.DurationMs = time.Since(startTime).Milliseconds()
		assessment.Validation.IncompleteChecks = append(assessment.Validation.IncompleteChecks, "CHK-HANDSHAKE", "CHK-HOSTNAME", "CHK-VALIDITY", "CHK-CHAIN", "CHK-PROTOCOL", "CHK-CIPHER", "CHK-KEY")
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-DNS",
			Name:        "DNS Resolution & Destination Safety",
			Description: "Resolves DNS record and verifies target IP is a safe public address.",
			Passed:      false,
			Status:      "failed",
			Details:     err.Error(),
		})
		assessment.Findings, assessment.Score, assessment.SecurityGrade, assessment.ScoreExplanation = GenerateFindings(hostname, 0, 0, nil, &assessment.Validation, assessment.Status)
		return assessment, nil
	}

	assessment.ResolvedIP = resolvedIP
	assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
		ID:          "CHK-DNS",
		Name:        "DNS Resolution & Destination Safety",
		Description: "Resolves DNS record and verifies target IP is a safe public address.",
		Passed:      true,
		Status:      "passed",
		Details:     fmt.Sprintf("Successfully resolved to verified public IP: %s", resolvedIP),
	})

	// 3. Establish TCP connection with strict timeout
	dialTimeout := 5 * time.Second
	dialer := &net.Dialer{
		Timeout: dialTimeout,
	}

	targetAddr := net.JoinHostPort(resolvedIP, "443")
	netConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		assessment.Status = "failed"
		assessment.ErrorMessage = fmt.Sprintf("TCP connection to %s:443 failed: %v", resolvedIP, err)
		assessment.DurationMs = time.Since(startTime).Milliseconds()
		assessment.Validation.IncompleteChecks = append(assessment.Validation.IncompleteChecks, "CHK-HANDSHAKE", "CHK-HOSTNAME", "CHK-VALIDITY", "CHK-CHAIN", "CHK-PROTOCOL", "CHK-CIPHER", "CHK-KEY")
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-TCP",
			Name:        "TCP Connection Establishment",
			Description: "Connects to server on standard HTTPS TCP port 443.",
			Passed:      false,
			Status:      "failed",
			Details:     assessment.ErrorMessage,
		})
		assessment.Findings, assessment.Score, assessment.SecurityGrade, assessment.ScoreExplanation = GenerateFindings(hostname, 0, 0, nil, &assessment.Validation, assessment.Status)
		return assessment, nil
	}
	defer netConn.Close()

	// 4. Perform TLS Handshake
	// Note: We set InsecureSkipVerify: true at the low-level TLS transport purely so that we can
	// safely capture the full peer certificate chain even if expired or self-signed.
	// We then execute rigorous x509 verification below. This ensures we never claim an invalid
	// session is trusted, while still giving the user actionable diagnostic metadata.
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	tlsConn := tls.Client(netConn, tlsConfig)
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, 6*time.Second)
	defer handshakeCancel()

	handshakeErr := tlsConn.HandshakeContext(handshakeCtx)
	if handshakeErr != nil {
		assessment.Status = "failed"
		assessment.ErrorMessage = fmt.Sprintf("TLS handshake failed: %v", handshakeErr)
		assessment.DurationMs = time.Since(startTime).Milliseconds()
		assessment.Validation.IncompleteChecks = append(assessment.Validation.IncompleteChecks, "CHK-HOSTNAME", "CHK-VALIDITY", "CHK-CHAIN", "CHK-PROTOCOL", "CHK-CIPHER", "CHK-KEY")
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-HANDSHAKE",
			Name:        "TLS Handshake Negotiation",
			Description: "Negotiates cryptographic parameters and exchanges certificates.",
			Passed:      false,
			Status:      "failed",
			Details:     handshakeErr.Error(),
		})
		assessment.Findings, assessment.Score, assessment.SecurityGrade, assessment.ScoreExplanation = GenerateFindings(hostname, 0, 0, nil, &assessment.Validation, assessment.Status)
		return assessment, nil
	}

	connState := tlsConn.ConnectionState()
	assessment.TLSVersionRaw = connState.Version
	assessment.TLSVersion = formatTLSVersion(connState.Version)
	assessment.CipherSuiteRaw = connState.CipherSuite
	assessment.CipherSuite = tls.CipherSuiteName(connState.CipherSuite)
	assessment.NegotiatedProtocol = connState.NegotiatedProtocol

	assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
		ID:          "CHK-HANDSHAKE",
		Name:        "TLS Handshake Negotiation",
		Description: "Negotiates cryptographic parameters and exchanges certificates.",
		Passed:      true,
		Status:      "passed",
		Details:     fmt.Sprintf("Handshake completed. Protocol: %s, Cipher Suite: %s", assessment.TLSVersion, assessment.CipherSuite),
	})

	// 5. Extract Certificates
	peerCerts := connState.PeerCertificates
	if len(peerCerts) == 0 {
		assessment.Status = "failed"
		assessment.ErrorMessage = "Server completed handshake without presenting any peer certificates."
		assessment.DurationMs = time.Since(startTime).Milliseconds()
		assessment.Findings, assessment.Score, assessment.SecurityGrade, assessment.ScoreExplanation = GenerateFindings(hostname, connState.Version, connState.CipherSuite, nil, &assessment.Validation, assessment.Status)
		return assessment, nil
	}

	leafCert := peerCerts[0]
	leafSummary := certToSummary(leafCert)
	assessment.PeerCertificate = leafSummary

	for _, c := range peerCerts {
		assessment.CertificateChain = append(assessment.CertificateChain, certToSummary(c))
	}

	// 6. Check: Hostname Verification (RFC 6125 / RFC 2818)
	hostnameErr := leafCert.VerifyHostname(hostname)
	if hostnameErr == nil {
		assessment.Validation.HostnameVerified = true
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-HOSTNAME",
			Name:        "Hostname & SAN Matching",
			Description: "Verifies that requested hostname matches certificate Common Name or Subject Alternative Names.",
			Passed:      true,
			Status:      "passed",
			Details:     fmt.Sprintf("Hostname %q matches SAN list (%d entries).", hostname, len(leafSummary.DNSNames)),
		})
	} else {
		assessment.Validation.HostnameVerified = false
		assessment.Validation.HostnameError = hostnameErr.Error()
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-HOSTNAME",
			Name:        "Hostname & SAN Matching",
			Description: "Verifies that requested hostname matches certificate Common Name or Subject Alternative Names.",
			Passed:      false,
			Status:      "failed",
			Details:     hostnameErr.Error(),
		})
	}

	// 7. Check: Temporal Validity (NotBefore / NotAfter)
	now := time.Now()
	if now.Before(leafCert.NotBefore) {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-VALIDITY",
			Name:        "Certificate Temporal Validity",
			Description: "Checks if certificate is currently active and unexpired.",
			Passed:      false,
			Status:      "failed",
			Details:     fmt.Sprintf("Certificate is not yet active (valid from %s).", leafSummary.NotBefore.Format("2006-01-02")),
		})
	} else if now.After(leafCert.NotAfter) {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-VALIDITY",
			Name:        "Certificate Temporal Validity",
			Description: "Checks if certificate is currently active and unexpired.",
			Passed:      false,
			Status:      "failed",
			Details:     fmt.Sprintf("Certificate expired on %s (%d days ago).", leafSummary.NotAfter.Format("2006-01-02"), -leafSummary.DaysRemaining),
		})
	} else {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-VALIDITY",
			Name:        "Certificate Temporal Validity",
			Description: "Checks if certificate is currently active and unexpired.",
			Passed:      true,
			Status:      "passed",
			Details:     fmt.Sprintf("Certificate is active with %d days remaining (expires %s).", leafSummary.DaysRemaining, leafSummary.NotAfter.Format("2006-01-02")),
		})
	}

	// 8. Check: Certificate Chain Trust Verification against System Trust Store
	intermediatePool := x509.NewCertPool()
	for _, cert := range peerCerts[1:] {
		intermediatePool.AddCert(cert)
	}

	verifyOpts := x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediatePool,
		CurrentTime:   now,
	}

	_, chainErr := leafCert.Verify(verifyOpts)
	if chainErr == nil {
		assessment.Validation.ChainVerified = true
		assessment.Validation.TrustStatus = "trusted"
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-CHAIN",
			Name:        "X.509 Certificate Chain Trust",
			Description: "Validates digital signatures up the hierarchy to a trusted Root CA.",
			Passed:      true,
			Status:      "passed",
			Details:     "Certificate chain successfully verified against trusted root store.",
		})
	} else {
		assessment.Validation.ChainVerified = false
		assessment.Validation.ChainError = chainErr.Error()

		if leafSummary.IsExpired {
			assessment.Validation.TrustStatus = "expired"
		} else if !assessment.Validation.HostnameVerified {
			assessment.Validation.TrustStatus = "mismatch"
		} else {
			assessment.Validation.TrustStatus = "untrusted"
		}

		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-CHAIN",
			Name:        "X.509 Certificate Chain Trust",
			Description: "Validates digital signatures up the hierarchy to a trusted Root CA.",
			Passed:      false,
			Status:      "failed",
			Details:     chainErr.Error(),
		})
	}

	// 9. Check: Protocol Version Modernity
	if connState.Version >= tls.VersionTLS13 {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-PROTOCOL",
			Name:        "Protocol Version Modernity",
			Description: "Ensures negotiated TLS version is modern (TLS 1.3).",
			Passed:      true,
			Status:      "passed",
			Details:     "TLS 1.3 negotiated with mandatory forward secrecy.",
		})
	} else if connState.Version == tls.VersionTLS12 {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-PROTOCOL",
			Name:        "Protocol Version Modernity",
			Description: "Ensures negotiated TLS version is modern (TLS 1.3).",
			Passed:      true,
			Status:      "passed",
			Details:     "TLS 1.2 negotiated (secure, but TLS 1.3 is recommended).",
		})
	} else {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-PROTOCOL",
			Name:        "Protocol Version Modernity",
			Description: "Ensures negotiated TLS version is modern (TLS 1.3).",
			Passed:      false,
			Status:      "failed",
			Details:     fmt.Sprintf("Deprecated protocol negotiated: %s.", assessment.TLSVersion),
		})
	}

	// 10. Check: Cipher Suite Strength
	cipherName := assessment.CipherSuite
	isLegacyCipher := strings.Contains(cipherName, "3DES") || strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "_CBC_")
	if isLegacyCipher {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-CIPHER",
			Name:        "Cipher Suite Strength & AEAD",
			Description: "Verifies negotiated cipher suite employs modern AEAD encryption.",
			Passed:      false,
			Status:      "failed",
			Details:     fmt.Sprintf("Legacy or non-AEAD cipher suite: %s", cipherName),
		})
	} else {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-CIPHER",
			Name:        "Cipher Suite Strength & AEAD",
			Description: "Verifies negotiated cipher suite employs modern AEAD encryption.",
			Passed:      true,
			Status:      "passed",
			Details:     fmt.Sprintf("AEAD cipher suite negotiated: %s", cipherName),
		})
	}

	// 11. Check: Key Strength
	if leafSummary.PublicKeyAlgorithm == "RSA" && leafSummary.KeySizeBits < 2048 {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-KEY",
			Name:        "Public Key Length & Security",
			Description: "Verifies public key meets minimum cryptographic requirements (RSA >= 2048).",
			Passed:      false,
			Status:      "failed",
			Details:     fmt.Sprintf("RSA key size %d bits is below 2048-bit minimum.", leafSummary.KeySizeBits),
		})
	} else {
		assessment.Validation.CompletedChecks = append(assessment.Validation.CompletedChecks, models.CheckResult{
			ID:          "CHK-KEY",
			Name:        "Public Key Length & Security",
			Description: "Verifies public key meets minimum cryptographic requirements (RSA >= 2048).",
			Passed:      true,
			Status:      "passed",
			Details:     fmt.Sprintf("%s key length: %d bits", leafSummary.PublicKeyAlgorithm, leafSummary.KeySizeBits),
		})
	}

	assessment.Status = "completed"
	assessment.DurationMs = time.Since(startTime).Milliseconds()

	// Generate findings and compute score/grade
	assessment.Findings, assessment.Score, assessment.SecurityGrade, assessment.ScoreExplanation = GenerateFindings(
		hostname,
		connState.Version,
		connState.CipherSuite,
		leafSummary,
		&assessment.Validation,
		assessment.Status,
	)

	return assessment, nil
}

// certToSummary extracts standard public metadata from an X.509 certificate.
func certToSummary(c *x509.Certificate) *models.CertificateSummary {
	if c == nil {
		return nil
	}

	now := time.Now()
	daysRemaining := int(c.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(c.NotAfter)
	isExpiringSoon := !isExpired && daysRemaining <= 14

	var ipAddresses []string
	for _, ip := range c.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	keySize := 2048
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		keySize = pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		keySize = 256
	}

	shaFingerprint := sha256.Sum256(c.Raw)
	fingerprintHex := strings.ToUpper(hex.EncodeToString(shaFingerprint[:]))
	// Format as XX:XX:XX...
	var formattedFP strings.Builder
	for i := 0; i < len(fingerprintHex); i += 2 {
		if i > 0 {
			formattedFP.WriteString(":")
		}
		formattedFP.WriteString(fingerprintHex[i : i+2])
	}

	serialHex := strings.ToUpper(c.SerialNumber.Text(16))

	return &models.CertificateSummary{
		SubjectCommonName:     c.Subject.CommonName,
		SubjectOrganization:   c.Subject.Organization,
		IssuerCommonName:      c.Issuer.CommonName,
		IssuerOrganization:    c.Issuer.Organization,
		SerialNumber:          serialHex,
		NotBefore:             c.NotBefore,
		NotAfter:              c.NotAfter,
		DaysRemaining:         daysRemaining,
		IsExpired:             isExpired,
		IsExpiringSoon:        isExpiringSoon,
		DNSNames:              c.DNSNames,
		IPAddresses:           ipAddresses,
		SignatureAlgorithm:    c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:    c.PublicKeyAlgorithm.String(),
		KeySizeBits:           keySize,
		FingerprintSHA256:     formattedFP.String(),
		OCSPServer:            c.OCSPServer,
		CRLDistributionPoints: c.CRLDistributionPoints,
		IsCA:                  c.IsCA,
	}
}

func formatTLSVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case 0x0300:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("TLS 0x%04X", v)
	}
}
