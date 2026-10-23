package tlscheck

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"tlscope/internal/models"
)

// GenerateFindings analyzes the certificate, TLS connection state, and validation results,
// returning a deterministic list of explainable findings and computing the score/grade.
func GenerateFindings(
	hostname string,
	tlsVersion uint16,
	cipherSuite uint16,
	peerCert *models.CertificateSummary,
	validation *models.ValidationResult,
	status string,
) ([]models.Finding, *int, string, string) {
	var findings []models.Finding

	// If assessment did not complete or failed fundamentally before cert extraction
	if status != "completed" || peerCert == nil {
		scoreExplanation := "Assessment could not complete TLS handshake and certificate extraction; insufficient data to calculate security score."
		return findings, nil, "Insufficient data", scoreExplanation
	}

	now := time.Now()

	// 1. Certificate Temporal Expiration
	if peerCert.IsExpired {
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-EXPIRED",
			Title:            "Certificate Has Expired",
			Severity:         "HIGH",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("Certificate expired on %s (%d days ago).", peerCert.NotAfter.Format("2006-01-02 15:04:05 MST"), -peerCert.DaysRemaining),
			Explanation:      "The certificate is past its designated validity period. Browsers and TLS clients will reject connections with expired certificates, displaying severe security warnings and terminating encrypted communications.",
			Remediation:      "Renew and deploy an active certificate immediately through your Certificate Authority (CA) or automated ACME provider.",
			Status:           "failed",
		})
	} else if now.Before(peerCert.NotBefore) {
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-NOT-YET-VALID",
			Title:            "Certificate Is Not Yet Valid",
			Severity:         "HIGH",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("Certificate validity window begins on %s.", peerCert.NotBefore.Format("2006-01-02 15:04:05 MST")),
			Explanation:      "The certificate's start date (NotBefore) is in the future. Clients with accurate clocks will reject this certificate as premature.",
			Remediation:      "Check server and client system clocks (NTP synchronization). If the issue persists, re-issue the certificate with an immediate activation timestamp.",
			Status:           "failed",
		})
	} else if peerCert.DaysRemaining <= 14 {
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-EXPIRING-SOON",
			Title:            "Certificate Expiring Soon (Within 14 Days)",
			Severity:         "MEDIUM",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("Certificate expires in %d days on %s.", peerCert.DaysRemaining, peerCert.NotAfter.Format("2006-01-02 15:04:05 MST")),
			Explanation:      "The certificate is approaching its expiration date. If renewal is not completed before expiry, client connections will encounter hard TLS handshake errors.",
			Remediation:      "Initiate certificate renewal and trigger automated server deployment before the validity window elapses.",
			Status:           "warning",
		})
	} else if peerCert.DaysRemaining <= 30 {
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-EXPIRING-30D",
			Title:            "Certificate Approaching Expiration (Within 30 Days)",
			Severity:         "LOW",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("Certificate expires in %d days on %s.", peerCert.DaysRemaining, peerCert.NotAfter.Format("2006-01-02 15:04:05 MST")),
			Explanation:      "The certificate is within normal 30-day renewal windows. Automated renewal should occur shortly.",
			Remediation:      "Verify that automated certificate renewal daemons (e.g. Certbot / system ACME client) are scheduled and functional.",
			Status:           "warning",
		})
	}

	// 2. Hostname Verification
	if !validation.HostnameVerified {
		evidence := fmt.Sprintf("Requested hostname %q does not match Common Name %q or any SANs: %v.", hostname, peerCert.SubjectCommonName, peerCert.DNSNames)
		if validation.HostnameError != "" {
			evidence = fmt.Sprintf("%s Reason: %s", evidence, validation.HostnameError)
		}
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-HOSTNAME-MISMATCH",
			Title:            "Hostname Verification Failed",
			Severity:         "HIGH",
			AffectedHostname: hostname,
			Evidence:         evidence,
			Explanation:      "The certificate does not cover the domain requested by the client in either the Subject Alternative Name (SAN) extension or the Subject Common Name. This is a critical security violation indicating potential domain spoofing or misconfigured web server vhosts.",
			Remediation:      "Reissue the certificate ensuring the requested domain name is listed in the Subject Alternative Names (SAN), or correct server SNI routing.",
			Status:           "failed",
		})
	}

	// 3. Certificate Chain Trust & Self-Signed Detection
	if !validation.ChainVerified {
		isSelfSigned := peerCert.SubjectCommonName == peerCert.IssuerCommonName && len(peerCert.IssuerOrganization) > 0 && len(peerCert.SubjectOrganization) > 0 && peerCert.SubjectOrganization[0] == peerCert.IssuerOrganization[0]
		if isSelfSigned || (peerCert.SubjectCommonName == peerCert.IssuerCommonName && peerCert.SubjectCommonName != "") {
			findings = append(findings, models.Finding{
				RuleID:           "TLS-RULE-SELF-SIGNED",
				Title:            "Self-Signed Certificate Detected",
				Severity:         "HIGH",
				AffectedHostname: hostname,
				Evidence:         fmt.Sprintf("Certificate Subject (%q) matches Issuer (%q) without a recognized public trust anchor.", peerCert.SubjectCommonName, peerCert.IssuerCommonName),
				Explanation:      "Self-signed certificates are not issued by a known, publicly audited Certificate Authority. Browsers and production TLS clients reject them by default to guard against Man-in-the-Middle (MitM) attacks.",
				Remediation:      "Replace the self-signed certificate with one issued by a publicly trusted CA (such as Let's Encrypt) or install the custom private root CA in client trust stores.",
				Status:           "failed",
			})
		} else {
			evidence := "Certificate chain could not be verified against the system trust store."
			if validation.ChainError != "" {
				evidence = fmt.Sprintf("Verification failure: %s", validation.ChainError)
			}
			findings = append(findings, models.Finding{
				RuleID:           "TLS-RULE-CHAIN-UNTRUSTED",
				Title:            "Certificate Chain Not Trusted",
				Severity:         "HIGH",
				AffectedHostname: hostname,
				Evidence:         evidence,
				Explanation:      "The server did not supply a complete certificate chain leading to a trusted root CA in the system trust store, or the intermediate CA is missing or untrusted.",
				Remediation:      "Ensure your web server (Nginx/Apache/Caddy) serves the full certificate bundle containing all required intermediate CA certificates.",
				Status:           "failed",
			})
		}
	}

	// 4. Insecure Signature Algorithms
	sigUpper := strings.ToUpper(peerCert.SignatureAlgorithm)
	if strings.Contains(sigUpper, "SHA1") || strings.Contains(sigUpper, "MD5") {
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-WEAK-SIGNATURE",
			Title:            "Insecure Signature Hash Algorithm",
			Severity:         "HIGH",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("Certificate is signed using %s.", peerCert.SignatureAlgorithm),
			Explanation:      "SHA-1 and MD5 signature algorithms are cryptographically broken due to practical collision attacks and are rejected by modern standards and browsers.",
			Remediation:      "Re-issue certificate utilizing a secure modern hash algorithm, such as SHA-256 or SHA-384.",
			Status:           "failed",
		})
	}

	// 5. Weak Key Length
	if peerCert.PublicKeyAlgorithm == "RSA" && peerCert.KeySizeBits > 0 && peerCert.KeySizeBits < 2048 {
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-WEAK-KEY",
			Title:            "Inadequate RSA Key Length",
			Severity:         "HIGH",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("RSA key length is %d bits (minimum safe standard is 2048 bits).", peerCert.KeySizeBits),
			Explanation:      "RSA keys under 2048 bits do not provide sufficient cryptographic strength and are vulnerable to modern factorization efforts.",
			Remediation:      "Generate a new private key with at least 2048-bit RSA (or 256-bit ECDSA) and re-issue the certificate.",
			Status:           "failed",
		})
	}

	// 6. TLS Protocol Version Checks
	switch tlsVersion {
	case tls.VersionTLS13:
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-TLS13-MODERN",
			Title:            "Modern TLS 1.3 Negotiated",
			Severity:         "INFO",
			AffectedHostname: hostname,
			Evidence:         "Negotiated protocol is TLS 1.3 (RFC 8446).",
			Explanation:      "TLS 1.3 provides enhanced security by mandating Perfect Forward Secrecy, eliminating outdated cipher primitives, and shortening the handshake latency to 1-RTT.",
			Remediation:      "No remediation required. Maintain up-to-date TLS libraries and security patches.",
			Status:           "passed",
		})
	case tls.VersionTLS12:
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-TLS12-ACCEPTABLE",
			Title:            "TLS 1.2 Negotiated",
			Severity:         "INFO",
			AffectedHostname: hostname,
			Evidence:         "Negotiated protocol is TLS 1.2 (RFC 5246).",
			Explanation:      "TLS 1.2 is widely compatible and secure when used with AEAD cipher suites and forward secrecy, but lacks the latency benefits and tightened cryptographic defaults of TLS 1.3.",
			Remediation:      "Enable TLS 1.3 on your web server or edge proxy while retaining TLS 1.2 for legacy client compatibility.",
			Status:           "passed",
		})
	case tls.VersionTLS10, tls.VersionTLS11:
		versionStr := "TLS 1.0"
		if tlsVersion == tls.VersionTLS11 {
			versionStr = "TLS 1.1"
		}
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-OBSOLETE-TLS",
			Title:            "Obsolete TLS Protocol Negotiated",
			Severity:         "HIGH",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("Server negotiated deprecated protocol %s.", versionStr),
			Explanation:      "TLS 1.0 and 1.1 have known architectural weaknesses (e.g. BEAST, POODLE) and are officially deprecated by RFC 8996. PCI-DSS and major browsers forbid their usage.",
			Remediation:      "Disable TLS 1.0 and 1.1 in your server configuration. Require TLS 1.2 as the minimum and enable TLS 1.3.",
			Status:           "failed",
		})
	default:
		// Older SSL versions or unknown
		if tlsVersion < tls.VersionTLS10 && tlsVersion > 0 {
			findings = append(findings, models.Finding{
				RuleID:           "TLS-RULE-OBSOLETE-SSL",
				Title:            "Insecure Legacy SSL Protocol Negotiated",
				Severity:         "HIGH",
				AffectedHostname: hostname,
				Evidence:         fmt.Sprintf("Server negotiated legacy SSL version 0x%04X.", tlsVersion),
				Explanation:      "Legacy SSL (SSLv2, SSLv3) is critically insecure and susceptible to trivial eavesdropping and exploitation.",
				Remediation:      "Disable all SSL versions immediately. Enforce modern TLS 1.2+.",
				Status:           "failed",
			})
		}
	}

	// 7. Check for Weak Ciphers (e.g., 3DES, CBC mode without AEAD, RC4)
	cipherName := tls.CipherSuiteName(cipherSuite)
	if strings.Contains(cipherName, "3DES") || strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "_CBC_") {
		findings = append(findings, models.Finding{
			RuleID:           "TLS-RULE-WEAK-CIPHER",
			Title:            "Legacy or Non-AEAD Cipher Suite Negotiated",
			Severity:         "MEDIUM",
			AffectedHostname: hostname,
			Evidence:         fmt.Sprintf("Negotiated cipher suite is %s.", cipherName),
			Explanation:      "The negotiated cipher suite utilizes legacy algorithms or CBC mode, which may be susceptible to padding oracle attacks. Modern configurations prioritize AEAD ciphers such as AES-GCM or CHACHA20-POLY1305.",
			Remediation:      "Configure server cipher preference to prioritize AEAD ciphers (e.g. ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256).",
			Status:           "warning",
		})
	}

	// Calculate Score and Grade
	score, grade, scoreExp := calculateScoreAndGrade(findings, tlsVersion, validation, peerCert)
	return findings, score, grade, scoreExp
}

// calculateScoreAndGrade implements a deterministic, explainable scoring formula:
// Base: 100
// Deductions:
// - Expired or Not Yet Valid: -40
// - Hostname Mismatch: -35
// - Untrusted Certificate Chain: -35
// - Obsolete TLS (< 1.2): -40
// - Insecure Signature (SHA-1/MD5): -30
// - Weak RSA Key (< 2048): -25
// - Expiring <= 14 days: -15
// - Expiring <= 30 days: -5
// - Weak/Legacy Cipher: -15
// - TLS 1.2 instead of TLS 1.3: -5
func calculateScoreAndGrade(
	findings []models.Finding,
	tlsVersion uint16,
	validation *models.ValidationResult,
	peerCert *models.CertificateSummary,
) (*int, string, string) {
	score := 100
	var deductions []string

	for _, f := range findings {
		switch f.RuleID {
		case "TLS-RULE-EXPIRED", "TLS-RULE-NOT-YET-VALID":
			score -= 40
			deductions = append(deductions, "Certificate validity window violation (-40)")
		case "TLS-RULE-HOSTNAME-MISMATCH":
			score -= 35
			deductions = append(deductions, "Hostname verification mismatch (-35)")
		case "TLS-RULE-CHAIN-UNTRUSTED", "TLS-RULE-SELF-SIGNED":
			score -= 35
			deductions = append(deductions, "Untrusted certificate authority or chain failure (-35)")
		case "TLS-RULE-OBSOLETE-TLS", "TLS-RULE-OBSOLETE-SSL":
			score -= 40
			deductions = append(deductions, "Deprecated/insecure TLS protocol (-40)")
		case "TLS-RULE-WEAK-SIGNATURE":
			score -= 30
			deductions = append(deductions, "Insecure certificate signature algorithm (-30)")
		case "TLS-RULE-WEAK-KEY":
			score -= 25
			deductions = append(deductions, "Weak public key length (-25)")
		case "TLS-RULE-EXPIRING-SOON":
			score -= 20
			deductions = append(deductions, "Certificate expires in <= 14 days (-20)")
		case "TLS-RULE-EXPIRING-30D":
			score -= 10
			deductions = append(deductions, "Certificate expires in <= 30 days (-10)")
		case "TLS-RULE-WEAK-CIPHER":
			score -= 15
			deductions = append(deductions, "Non-AEAD or legacy cipher suite (-15)")
		case "TLS-RULE-TLS12-ACCEPTABLE":
			score -= 5
			deductions = append(deductions, "TLS 1.2 negotiated instead of TLS 1.3 (-5)")
		}
	}

	// Cap score at 45 (Grade F) if any HIGH severity finding exists (expired, mismatch, untrusted chain, weak key)
	hasHighSeverity := false
	for _, f := range findings {
		if f.Severity == "HIGH" {
			hasHighSeverity = true
			break
		}
	}
	if hasHighSeverity && score > 45 {
		score = 45
		deductions = append(deductions, "Critical high-severity security finding capped score to 45 (Grade F)")
	}

	if score < 0 {
		score = 0
	}

	var grade string
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 85:
		grade = "A"
	case score >= 70:
		grade = "B"
	case score >= 50:
		grade = "C"
	default:
		grade = "F"
	}

	explanation := fmt.Sprintf("Calculated score %d/100 (Grade %s). Base: 100 points.", score, grade)
	if len(deductions) > 0 {
		explanation = fmt.Sprintf("%s Deductions applied: %s.", explanation, strings.Join(deductions, ", "))
	} else {
		explanation = fmt.Sprintf("%s Zero security deductions; optimal TLS 1.3 and PKI trust configuration.", explanation)
	}

	return &score, grade, explanation
}
