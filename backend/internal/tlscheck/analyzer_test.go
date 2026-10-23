package tlscheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tlscope/internal/models"
)

// TestValidateHostname_Valid tests standard compliant domain names.
func TestValidateHostname_Valid(t *testing.T) {
	validHosts := []string{
		"example.com",
		"sub.domain.org",
		"cloudflare.com",
		"api.github.com",
		"my-test-service.co.uk",
		"a.b.c.d.net",
	}

	for _, host := range validHosts {
		cleaned, err := ValidateHostname(host)
		if err != nil {
			t.Errorf("expected %q to be valid, got error: %v", host, err)
		}
		if cleaned != strings.ToLower(host) {
			t.Errorf("expected cleaned hostname %q, got %q", strings.ToLower(host), cleaned)
		}
	}
}

// TestValidateHostname_MalformedRejection verifies rejection of invalid inputs.
func TestValidateHostname_MalformedRejection(t *testing.T) {
	invalidCases := []struct {
		input       string
		errContains string
	}{
		{"", "cannot be empty"},
		{"   ", "cannot be empty"},
		{"https://example.com", "full URLs"},
		{"http://example.com/api", "full URLs"},
		{"example.com/path", "full URLs"},
		{"example.com?query=1", "full URLs"},
		{"example.com#hash", "full URLs"},
		{"user@example.com", "full URLs"},
		{"example.com:443", "port specification"},
		{"example.com:8443", "port specification"},
		{".example.com", "start or end with a dot"},
		{"example.com.", "start or end with a dot"},
		{"-badlabel.com", "illegal hyphen placement"},
		{"badlabel-.com", "illegal hyphen placement"},
		{"bad$char.com", "contains invalid characters"},
		{"singleword", "must contain at least two domain labels"},
		{"localhost", "reserved"},
		{"test.local", "reserved"},
		{"internal.lan", "reserved"},
		{"site.onion", "reserved"},
		{"domain.123", "top-level domain cannot be purely numeric"},
		{strings.Repeat("a", 250) + ".com", "exceeds maximum permissible length"},
	}

	for _, tc := range invalidCases {
		_, err := ValidateHostname(tc.input)
		if err == nil {
			t.Errorf("expected input %q to fail validation, but it passed", tc.input)
		} else if !strings.Contains(err.Error(), tc.errContains) {
			t.Errorf("for input %q, expected error containing %q, got: %v", tc.input, tc.errContains, err)
		}
	}
}

// TestValidateHostname_IPLiterals verifies rejection of IP address strings.
func TestValidateHostname_IPLiterals(t *testing.T) {
	ipLiterals := []string{
		"127.0.0.1",
		"8.8.8.8",
		"10.0.0.1",
		"192.168.1.1",
		"169.254.169.254",
		"::1",
		"fe80::1",
		"2001:db8::1",
	}

	for _, ip := range ipLiterals {
		_, err := ValidateHostname(ip)
		if err == nil {
			t.Errorf("expected IP literal %q to be rejected, but it was accepted", ip)
		} else if !strings.Contains(err.Error(), "IP address literals are prohibited") {
			t.Errorf("expected error about IP literals for %q, got: %v", ip, err)
		}
	}
}

// TestIsSafeIP_ProhibitedDestinations tests SSRF filters on various IP address categories.
func TestIsSafeIP_ProhibitedDestinations(t *testing.T) {
	testCases := []struct {
		ip       string
		expected bool
	}{
		// Prohibited
		{"127.0.0.1", false},
		{"127.0.0.50", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"10.254.1.1", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.0.1", false},
		{"192.168.100.5", false},
		{"169.254.169.254", false},
		{"169.254.1.1", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
		{"::", false},

		// Permitted Public IPs
		{"93.184.216.34", true},  // example.com
		{"1.1.1.1", true},        // Cloudflare DNS
		{"8.8.8.8", true},        // Google DNS
		{"2606:4700::6811:d209", true}, // Public IPv6
	}

	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip)
		safe, reason := IsSafeIP(ip)
		if safe != tc.expected {
			t.Errorf("IsSafeIP(%q) = %v (reason: %s), expected %v", tc.ip, safe, reason, tc.expected)
		}
	}
}

// TestFindings_ExpiredCertificate verifies detection of expired certificates.
func TestFindings_ExpiredCertificate(t *testing.T) {
	now := time.Now()
	expiredSummary := &models.CertificateSummary{
		SubjectCommonName:  "expired.example.com",
		NotBefore:          now.Add(-60 * 24 * time.Hour),
		NotAfter:           now.Add(-5 * 24 * time.Hour),
		DaysRemaining:      -5,
		IsExpired:          true,
		IsExpiringSoon:     false,
		PublicKeyAlgorithm: "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "SHA256-RSA",
	}

	validation := &models.ValidationResult{
		HostnameVerified: true,
		ChainVerified:    false,
		ChainError:       "x509: certificate has expired",
		TrustStatus:      "expired",
	}

	findings, score, grade, _ := GenerateFindings(
		"expired.example.com",
		tls.VersionTLS13,
		tls.TLS_AES_128_GCM_SHA256,
		expiredSummary,
		validation,
		"completed",
	)

	hasExpiredRule := false
	for _, f := range findings {
		if f.RuleID == "TLS-RULE-EXPIRED" {
			hasExpiredRule = true
			if f.Severity != "HIGH" {
				t.Errorf("expected TLS-RULE-EXPIRED severity to be HIGH, got %s", f.Severity)
			}
		}
	}

	if !hasExpiredRule {
		t.Errorf("expected TLS-RULE-EXPIRED finding to be generated")
	}

	if grade != "F" {
		t.Errorf("expected security grade to be F for expired certificate, got %s", grade)
	}

	if score == nil || *score > 50 {
		t.Errorf("expected low score for expired certificate, got %v", score)
	}
}

// TestFindings_HostnameMismatch verifies hostname mismatch detection.
func TestFindings_HostnameMismatch(t *testing.T) {
	now := time.Now()
	summary := &models.CertificateSummary{
		SubjectCommonName:  "otherdomain.com",
		DNSNames:           []string{"otherdomain.com", "api.otherdomain.com"},
		NotBefore:          now.Add(-10 * 24 * time.Hour),
		NotAfter:           now.Add(90 * 24 * time.Hour),
		DaysRemaining:      90,
		IsExpired:          false,
		PublicKeyAlgorithm: "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "SHA256-RSA",
	}

	validation := &models.ValidationResult{
		HostnameVerified: false,
		HostnameError:    "x509: certificate is valid for otherdomain.com, not target.example.com",
		ChainVerified:    true,
		TrustStatus:      "mismatch",
	}

	findings, score, grade, _ := GenerateFindings(
		"target.example.com",
		tls.VersionTLS13,
		tls.TLS_AES_128_GCM_SHA256,
		summary,
		validation,
		"completed",
	)

	hasMismatch := false
	for _, f := range findings {
		if f.RuleID == "TLS-RULE-HOSTNAME-MISMATCH" {
			hasMismatch = true
			if f.Severity != "HIGH" {
				t.Errorf("expected TLS-RULE-HOSTNAME-MISMATCH severity to be HIGH, got %s", f.Severity)
			}
		}
	}

	if !hasMismatch {
		t.Errorf("expected TLS-RULE-HOSTNAME-MISMATCH to be generated")
	}

	if grade != "F" && grade != "C" {
		t.Errorf("expected grade F or C for hostname mismatch, got %s", grade)
	}

	if score == nil || *score >= 70 {
		t.Errorf("expected score deduction for mismatch, got %v", score)
	}
}

// TestFindings_ExpirationWarningBoundaries verifies the 14-day and 30-day boundaries.
func TestFindings_ExpirationWarningBoundaries(t *testing.T) {
	now := time.Now()

	// 1. Expiring in 5 days (<= 14 days) -> TLS-RULE-EXPIRING-SOON
	summary5 := &models.CertificateSummary{
		SubjectCommonName:  "soon.example.com",
		DNSNames:           []string{"soon.example.com"},
		NotBefore:          now.Add(-80 * 24 * time.Hour),
		NotAfter:           now.Add(5 * 24 * time.Hour),
		DaysRemaining:      5,
		IsExpired:          false,
		IsExpiringSoon:     true,
		PublicKeyAlgorithm: "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "SHA256-RSA",
	}

	validationValid := &models.ValidationResult{
		HostnameVerified: true,
		ChainVerified:    true,
		TrustStatus:      "trusted",
	}

	findings5, _, grade5, _ := GenerateFindings("soon.example.com", tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, summary5, validationValid, "completed")
	hasSoon := false
	for _, f := range findings5 {
		if f.RuleID == "TLS-RULE-EXPIRING-SOON" {
			hasSoon = true
			if f.Severity != "MEDIUM" {
				t.Errorf("expected MEDIUM severity for expiring soon, got %s", f.Severity)
			}
		}
	}
	if !hasSoon {
		t.Errorf("expected TLS-RULE-EXPIRING-SOON for certificate with 5 days remaining")
	}
	if grade5 != "B" {
		t.Errorf("expected grade B for 5 days remaining, got %s", grade5)
	}

	// 2. Expiring in 20 days (14 < days <= 30) -> TLS-RULE-EXPIRING-30D
	summary20 := &models.CertificateSummary{
		SubjectCommonName:  "approaching.example.com",
		DNSNames:           []string{"approaching.example.com"},
		NotBefore:          now.Add(-70 * 24 * time.Hour),
		NotAfter:           now.Add(20 * 24 * time.Hour),
		DaysRemaining:      20,
		IsExpired:          false,
		IsExpiringSoon:     false,
		PublicKeyAlgorithm: "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "SHA256-RSA",
	}

	findings20, _, _, _ := GenerateFindings("approaching.example.com", tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, summary20, validationValid, "completed")
	has30d := false
	for _, f := range findings20 {
		if f.RuleID == "TLS-RULE-EXPIRING-30D" {
			has30d = true
			if f.Severity != "LOW" {
				t.Errorf("expected LOW severity for approaching expiration, got %s", f.Severity)
			}
		}
	}
	if !has30d {
		t.Errorf("expected TLS-RULE-EXPIRING-30D for certificate with 20 days remaining")
	}

	// 3. Expiring in 90 days (> 30 days) -> No expiration warning
	summary90 := &models.CertificateSummary{
		SubjectCommonName:  "healthy.example.com",
		DNSNames:           []string{"healthy.example.com"},
		NotBefore:          now.Add(-10 * 24 * time.Hour),
		NotAfter:           now.Add(90 * 24 * time.Hour),
		DaysRemaining:      90,
		IsExpired:          false,
		IsExpiringSoon:     false,
		PublicKeyAlgorithm: "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "SHA256-RSA",
	}

	findings90, score90, grade90, _ := GenerateFindings("healthy.example.com", tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, summary90, validationValid, "completed")
	for _, f := range findings90 {
		if strings.Contains(f.RuleID, "EXPIR") {
			t.Errorf("unexpected expiration finding for 90 days remaining: %s", f.RuleID)
		}
	}
	if grade90 != "A+" || *score90 != 100 {
		t.Errorf("expected Grade A+ and 100 score for healthy TLS 1.3 host, got %s (%v)", grade90, score90)
	}
}

// TestFindings_IncompleteAssessment verifies "Insufficient data" behavior.
func TestFindings_IncompleteAssessment(t *testing.T) {
	val := &models.ValidationResult{
		CompletedChecks:  []models.CheckResult{},
		IncompleteChecks: []string{"CHK-HANDSHAKE"},
	}

	_, score, grade, exp := GenerateFindings("timeout.example.com", 0, 0, nil, val, "failed")
	if score != nil {
		t.Errorf("expected score to be nil for incomplete scan, got %v", *score)
	}
	if grade != "Insufficient data" {
		t.Errorf("expected grade 'Insufficient data', got %s", grade)
	}
	if !strings.Contains(exp, "insufficient data") {
		t.Errorf("expected explanation to mention insufficient data, got: %s", exp)
	}
}

// TestLocalTLS_SelfSignedInspection creates a local controlled TLS test server to
// verify certificate extraction and self-signed untrusted chain detection.
func TestLocalTLS_SelfSignedInspection(t *testing.T) {
	// Generate in-memory ECDSA private key and self-signed certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName:   "local-test.internal",
			Organization: []string{"Test Security Unit"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"local-test.internal"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	ts.StartTLS()
	defer ts.Close()

	// Parse presented certificate directly using certToSummary
	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	summary := certToSummary(parsedCert)
	if summary.SubjectCommonName != "local-test.internal" {
		t.Errorf("expected CN 'local-test.internal', got %q", summary.SubjectCommonName)
	}

	if summary.KeySizeBits != 256 {
		t.Errorf("expected 256-bit ECDSA key size, got %d", summary.KeySizeBits)
	}

	// Verify that self-signed detection flags rule
	validation := &models.ValidationResult{
		HostnameVerified: true,
		ChainVerified:    false,
		ChainError:       "x509: certificate signed by unknown authority",
		TrustStatus:      "untrusted",
	}

	findings, _, grade, _ := GenerateFindings("local-test.internal", tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, summary, validation, "completed")
	hasSelfSigned := false
	for _, f := range findings {
		if f.RuleID == "TLS-RULE-SELF-SIGNED" {
			hasSelfSigned = true
		}
	}
	if !hasSelfSigned {
		t.Errorf("expected TLS-RULE-SELF-SIGNED finding for self-signed test cert")
	}
	if grade != "F" {
		t.Errorf("expected grade F for self-signed untrusted cert, got %s", grade)
	}
}
