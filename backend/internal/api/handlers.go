package api

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"tlscope/internal/models"
	"tlscope/internal/tlscheck"
)

var (
	appStartTime = time.Now()
	appVersion   = "1.0.0"
)

// HistoryStore maintains a bounded, thread-safe in-memory list of recent assessment results.
type HistoryStore struct {
	mu       sync.RWMutex
	capacity int
	items    []*models.AssessmentResult
}

// NewHistoryStore creates a bounded history buffer.
func NewHistoryStore(capacity int) *HistoryStore {
	if capacity <= 0 {
		capacity = 50
	}
	return &HistoryStore{
		capacity: capacity,
		items:    make([]*models.AssessmentResult, 0, capacity),
	}
}

// Add prepends a new assessment result to history, enforcing capacity.
func (h *HistoryStore) Add(res *models.AssessmentResult) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Prepend
	h.items = append([]*models.AssessmentResult{res}, h.items...)
	if len(h.items) > h.capacity {
		h.items = h.items[:h.capacity]
	}
}

// GetAllSummaries returns summaries of all saved assessments.
func (h *HistoryStore) GetAllSummaries() []models.HistorySummary {
	h.mu.RLock()
	defer h.mu.RUnlock()

	summaries := make([]models.HistorySummary, 0, len(h.items))
	for _, it := range h.items {
		highCount := 0
		warnCount := 0
		for _, f := range it.Findings {
			if f.Severity == "HIGH" {
				highCount++
			} else if f.Severity == "MEDIUM" || f.Severity == "LOW" {
				warnCount++
			}
		}

		summaries = append(summaries, models.HistorySummary{
			ID:                it.ID,
			Hostname:          it.Hostname,
			ResolvedIP:        it.ResolvedIP,
			Timestamp:         it.Timestamp,
			Status:            it.Status,
			TLSVersion:        it.TLSVersion,
			TrustStatus:       it.Validation.TrustStatus,
			SecurityGrade:     it.SecurityGrade,
			Score:             it.Score,
			FindingCount:      len(it.Findings),
			HighSeverityCount: highCount,
			WarningCount:      warnCount,
			IsDemo:            it.IsDemo,
		})
	}
	return summaries
}

// GetByID returns the full assessment result matching the given ID.
func (h *HistoryStore) GetByID(id string) (*models.AssessmentResult, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, it := range h.items {
		if it.ID == id {
			return it, true
		}
	}
	return nil, false
}

// Clear wipes all recorded history items.
func (h *HistoryStore) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.items = make([]*models.AssessmentResult, 0, h.capacity)
}

// Server holds API dependencies.
type Server struct {
	History *HistoryStore
}

// NewServer initializes API dependencies.
func NewServer() *Server {
	return &Server{
		History: NewHistoryStore(50),
	}
}

// RegisterRoutes sets up REST endpoints with CORS and logging.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/analyze", s.handleAnalyze)
	mux.HandleFunc("GET /api/history", s.handleGetHistory)
	mux.HandleFunc("GET /api/history/", s.handleGetHistoryByID)
	mux.HandleFunc("DELETE /api/history", s.handleClearHistory)
	mux.HandleFunc("GET /api/demo", s.handleGetDemo)
	mux.HandleFunc("POST /api/report/html", s.handleGenerateHTMLReport)
}

// handleHealth returns API operational health and runtime information.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := models.HealthResponse{
		Status:        "ok",
		Version:       appVersion,
		Timestamp:     time.Now(),
		UptimeSeconds: int64(time.Since(appStartTime).Seconds()),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAnalyze accepts a hostname, validates it, and triggers a real TLS assessment.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	// Restrict request body size to 4KB to avoid resource exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request payload or payload exceeded size limit.")
		return
	}

	var req models.AnalyzeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_JSON", "Request body must be valid JSON: {\"hostname\": \"example.com\"}")
		return
	}

	cleanedHost, err := tlscheck.ValidateHostname(req.Hostname)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_HOSTNAME", err.Error())
		return
	}

	// Bounded assessment timeout: 15 seconds
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	result, err := tlscheck.PerformTLSAssessment(ctx, cleanedHost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ASSESSMENT_ERROR", err.Error())
		return
	}

	// Record in memory history
	s.History.Add(result)

	writeJSON(w, http.StatusOK, result)
}

// handleGetHistory returns summaries of recent scans.
func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	summaries := s.History.GetAllSummaries()
	writeJSON(w, http.StatusOK, summaries)
}

// handleGetHistoryByID returns the full assessment for a given scan ID.
func (s *Server) handleGetHistoryByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/history/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "MISSING_ID", "Assessment ID is required")
		return
	}

	item, found := s.History.GetByID(id)
	if !found {
		// Also check if it's one of the demo IDs
		demos := GetDemoScenarios()
		for _, d := range demos {
			if d.ID == id {
				writeJSON(w, http.StatusOK, d)
				return
			}
		}
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Assessment with ID %q was not found in history.", id))
		return
	}

	writeJSON(w, http.StatusOK, item)
}

// handleClearHistory wipes the in-memory history.
func (s *Server) handleClearHistory(w http.ResponseWriter, r *http.Request) {
	s.History.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"message": "History cleared successfully"})
}

// handleGetDemo returns clearly labeled synthetic test results for classroom demonstration.
func (s *Server) handleGetDemo(w http.ResponseWriter, r *http.Request) {
	demos := GetDemoScenarios()
	writeJSON(w, http.StatusOK, demos)
}

// handleGenerateHTMLReport accepts an AssessmentResult JSON and returns a self-contained, sanitized HTML document.
func (s *Server) handleGenerateHTMLReport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	var result models.AssessmentResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REPORT_DATA", "Failed to parse assessment result data for report.")
		return
	}

	htmlContent := renderSanitizedHTMLReport(&result)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"tlscope-report-%s.html\"", sanitizeFilename(result.Hostname)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(htmlContent))
}

// GetDemoScenarios generates realistic synthetic assessment results for demonstration.
func GetDemoScenarios() []*models.AssessmentResult {
	now := time.Now()

	score25 := 25
	score45 := 45
	score80 := 80
	score95 := 95
	score100 := 100

	return []*models.AssessmentResult{
		{
			ID:                 "demo-expired-cert",
			Hostname:           "expired.example.internal",
			ResolvedIP:         "198.51.100.12",
			Port:               443,
			Timestamp:          now.Add(-10 * time.Minute),
			DurationMs:         240,
			Status:             "completed",
			TLSVersion:         "TLS 1.3",
			TLSVersionRaw:      0x0304,
			CipherSuite:        "TLS_AES_128_GCM_SHA256",
			CipherSuiteRaw:     0x1301,
			ServerName:         "expired.example.internal",
			NegotiatedProtocol: "h2",
			IsDemo:             true,
			PeerCertificate: &models.CertificateSummary{
				SubjectCommonName:     "expired.example.internal",
				SubjectOrganization:   []string{"Acme Test Corp"},
				IssuerCommonName:      "DigiTrust Global Root CA",
				IssuerOrganization:    []string{"DigiTrust Security Inc."},
				SerialNumber:          "7F34A91B008C23E1",
				NotBefore:             now.Add(-390 * 24 * time.Hour),
				NotAfter:              now.Add(-25 * 24 * time.Hour),
				DaysRemaining:         -25,
				IsExpired:             true,
				IsExpiringSoon:        false,
				DNSNames:              []string{"expired.example.internal", "www.expired.example.internal"},
				SignatureAlgorithm:    "SHA256-RSA",
				PublicKeyAlgorithm:    "RSA",
				KeySizeBits:           2048,
				FingerprintSHA256:     "E3:5A:91:02:88:F4:71:A9:00:23:BC:11:82:34:55:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67",
			},
			Validation: models.ValidationResult{
				HostnameVerified: true,
				ChainVerified:    false,
				ChainError:       "x509: certificate has expired or is not yet valid",
				TrustStatus:      "expired",
				CompletedChecks: []models.CheckResult{
					{ID: "CHK-DNS", Name: "DNS Resolution", Description: "Safe IP verification", Passed: true, Status: "passed", Details: "Resolved to safe synthetic IP 198.51.100.12"},
					{ID: "CHK-HANDSHAKE", Name: "TLS Handshake", Description: "TLS negotiation", Passed: true, Status: "passed", Details: "TLS 1.3 / AES-128-GCM"},
					{ID: "CHK-HOSTNAME", Name: "Hostname Verification", Description: "SAN matching", Passed: true, Status: "passed", Details: "Hostname matches SAN list."},
					{ID: "CHK-VALIDITY", Name: "Certificate Validity", Description: "Temporal checks", Passed: false, Status: "failed", Details: "Certificate expired 25 days ago."},
					{ID: "CHK-CHAIN", Name: "Chain Verification", Description: "Trust validation", Passed: false, Status: "failed", Details: "Certificate expired; chain verification aborted."},
				},
			},
			Findings: []models.Finding{
				{
					RuleID:           "TLS-RULE-EXPIRED",
					Title:            "Certificate Has Expired",
					Severity:         "HIGH",
					AffectedHostname: "expired.example.internal",
					Evidence:         fmt.Sprintf("Certificate expired on %s (25 days ago).", now.Add(-25*24*time.Hour).Format("2006-01-02")),
					Explanation:      "The certificate is past its validity period. Browsers and TLS clients will reject connections with expired certificates, displaying severe security warnings and terminating encrypted communications.",
					Remediation:      "Renew and deploy an active certificate immediately through your Certificate Authority (CA) or automated ACME provider.",
					Status:           "failed",
				},
				{
					RuleID:           "TLS-RULE-CHAIN-UNTRUSTED",
					Title:            "Certificate Chain Not Trusted",
					Severity:         "HIGH",
					AffectedHostname: "expired.example.internal",
					Evidence:         "Verification failure: x509: certificate has expired or is not yet valid.",
					Explanation:      "The certificate chain could not be verified due to expiration.",
					Remediation:      "Renew the certificate chain bundle.",
					Status:           "failed",
				},
				{
					RuleID:           "TLS-RULE-TLS13-MODERN",
					Title:            "Modern TLS 1.3 Negotiated",
					Severity:         "INFO",
					AffectedHostname: "expired.example.internal",
					Evidence:         "Negotiated protocol is TLS 1.3 (RFC 8446).",
					Explanation:      "TLS 1.3 provides enhanced security by mandating Perfect Forward Secrecy.",
					Remediation:      "No remediation required for protocol version.",
					Status:           "passed",
				},
			},
			SecurityGrade:    "F",
			Score:            &score25,
			ScoreExplanation: "Calculated score 25/100 (Grade F). Base: 100 points. Deductions: Certificate validity window violation (-40), Untrusted certificate authority or chain failure (-35).",
		},
		{
			ID:                 "demo-hostname-mismatch",
			Hostname:           "mismatch.example.internal",
			ResolvedIP:         "198.51.100.14",
			Port:               443,
			Timestamp:          now.Add(-25 * time.Minute),
			DurationMs:         190,
			Status:             "completed",
			TLSVersion:         "TLS 1.3",
			TLSVersionRaw:      0x0304,
			CipherSuite:        "TLS_AES_256_GCM_SHA384",
			CipherSuiteRaw:     0x1302,
			ServerName:         "mismatch.example.internal",
			NegotiatedProtocol: "h2",
			IsDemo:             true,
			PeerCertificate: &models.CertificateSummary{
				SubjectCommonName:     "api.internal-cloud.net",
				SubjectOrganization:   []string{"Cloud Services Group"},
				IssuerCommonName:      "GlobalSign Cloud CA - R3",
				IssuerOrganization:    []string{"GlobalSign nv-sa"},
				SerialNumber:          "5D22C990145FA80B",
				NotBefore:             now.Add(-60 * 24 * time.Hour),
				NotAfter:              now.Add(305 * 24 * time.Hour),
				DaysRemaining:         305,
				IsExpired:             false,
				IsExpiringSoon:        false,
				DNSNames:              []string{"api.internal-cloud.net", "*.internal-cloud.net"},
				SignatureAlgorithm:    "SHA256-RSA",
				PublicKeyAlgorithm:    "RSA",
				KeySizeBits:           2048,
				FingerprintSHA256:     "1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09:1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09",
			},
			Validation: models.ValidationResult{
				HostnameVerified: false,
				HostnameError:    "x509: certificate is valid for api.internal-cloud.net, *.internal-cloud.net, not mismatch.example.internal",
				ChainVerified:    true,
				TrustStatus:      "mismatch",
				CompletedChecks: []models.CheckResult{
					{ID: "CHK-DNS", Name: "DNS Resolution", Description: "Safe IP verification", Passed: true, Status: "passed", Details: "Resolved to safe synthetic IP 198.51.100.14"},
					{ID: "CHK-HANDSHAKE", Name: "TLS Handshake", Description: "TLS negotiation", Passed: true, Status: "passed", Details: "TLS 1.3 / AES-256-GCM"},
					{ID: "CHK-HOSTNAME", Name: "Hostname Verification", Description: "SAN matching", Passed: false, Status: "failed", Details: "Hostname does not match SAN entries."},
					{ID: "CHK-VALIDITY", Name: "Certificate Validity", Description: "Temporal checks", Passed: true, Status: "passed", Details: "Certificate active (305 days remaining)."},
					{ID: "CHK-CHAIN", Name: "Chain Verification", Description: "Trust validation", Passed: true, Status: "passed", Details: "Chain verified against root authority."},
				},
			},
			Findings: []models.Finding{
				{
					RuleID:           "TLS-RULE-HOSTNAME-MISMATCH",
					Title:            "Hostname Verification Failed",
					Severity:         "HIGH",
					AffectedHostname: "mismatch.example.internal",
					Evidence:         "Requested hostname \"mismatch.example.internal\" does not match Common Name \"api.internal-cloud.net\" or any SANs: [api.internal-cloud.net *.internal-cloud.net].",
					Explanation:      "The certificate presented by the server does not cover the domain name specified in the client request. This indicates misconfigured virtual hosts or potential server impersonation.",
					Remediation:      "Reissue certificate including \"mismatch.example.internal\" in the SAN list or update server SNI binding.",
					Status:           "failed",
				},
				{
					RuleID:           "TLS-RULE-TLS13-MODERN",
					Title:            "Modern TLS 1.3 Negotiated",
					Severity:         "INFO",
					AffectedHostname: "mismatch.example.internal",
					Evidence:         "Negotiated protocol is TLS 1.3 (RFC 8446).",
					Explanation:      "TLS 1.3 provides enhanced security and lower latency.",
					Remediation:      "No remediation required.",
					Status:           "passed",
				},
			},
			SecurityGrade:    "F",
			Score:            &score45,
			ScoreExplanation: "Calculated score 45/100 (Grade F). Base: 100 points. Deductions: Hostname verification mismatch (-35), Critical high-severity security finding capped score to 45 (Grade F).",
		},
		{
			ID:                 "demo-self-signed",
			Hostname:           "selfsigned.example.internal",
			ResolvedIP:         "198.51.100.18",
			Port:               443,
			Timestamp:          now.Add(-45 * time.Minute),
			DurationMs:         160,
			Status:             "completed",
			TLSVersion:         "TLS 1.3",
			TLSVersionRaw:      0x0304,
			CipherSuite:        "TLS_CHACHA20_POLY1305_SHA256",
			CipherSuiteRaw:     0x1303,
			ServerName:         "selfsigned.example.internal",
			NegotiatedProtocol: "h2",
			IsDemo:             true,
			PeerCertificate: &models.CertificateSummary{
				SubjectCommonName:     "selfsigned.example.internal",
				SubjectOrganization:   []string{"Internal Security Lab"},
				IssuerCommonName:      "selfsigned.example.internal",
				IssuerOrganization:    []string{"Internal Security Lab"},
				SerialNumber:          "1122334455667788",
				NotBefore:             now.Add(-10 * 24 * time.Hour),
				NotAfter:              now.Add(355 * 24 * time.Hour),
				DaysRemaining:         355,
				IsExpired:             false,
				IsExpiringSoon:        false,
				DNSNames:              []string{"selfsigned.example.internal"},
				SignatureAlgorithm:    "SHA256-RSA",
				PublicKeyAlgorithm:    "RSA",
				KeySizeBits:           2048,
				FingerprintSHA256:     "99:88:77:66:55:44:33:22:11:00:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
				IsCA:                  true,
			},
			Validation: models.ValidationResult{
				HostnameVerified: true,
				ChainVerified:    false,
				ChainError:       "x509: certificate signed by unknown authority",
				TrustStatus:      "untrusted",
				CompletedChecks: []models.CheckResult{
					{ID: "CHK-DNS", Name: "DNS Resolution", Description: "Safe IP verification", Passed: true, Status: "passed", Details: "Resolved to safe synthetic IP 198.51.100.18"},
					{ID: "CHK-HANDSHAKE", Name: "TLS Handshake", Description: "TLS negotiation", Passed: true, Status: "passed", Details: "TLS 1.3 / CHACHA20-POLY1305"},
					{ID: "CHK-HOSTNAME", Name: "Hostname Verification", Description: "SAN matching", Passed: true, Status: "passed", Details: "Hostname matches SAN."},
					{ID: "CHK-VALIDITY", Name: "Certificate Validity", Description: "Temporal checks", Passed: true, Status: "passed", Details: "Valid for 355 days."},
					{ID: "CHK-CHAIN", Name: "Chain Verification", Description: "Trust validation", Passed: false, Status: "failed", Details: "Certificate signed by unknown authority (self-signed)."},
				},
			},
			Findings: []models.Finding{
				{
					RuleID:           "TLS-RULE-SELF-SIGNED",
					Title:            "Self-Signed Certificate Detected",
					Severity:         "HIGH",
					AffectedHostname: "selfsigned.example.internal",
					Evidence:         "Certificate Subject (\"selfsigned.example.internal\") matches Issuer (\"selfsigned.example.internal\") without a recognized public trust anchor.",
					Explanation:      "Self-signed certificates are not signed by a trusted certificate authority and trigger browser warnings.",
					Remediation:      "Replace the self-signed certificate with one issued by a publicly trusted CA.",
					Status:           "failed",
				},
				{
					RuleID:           "TLS-RULE-TLS13-MODERN",
					Title:            "Modern TLS 1.3 Negotiated",
					Severity:         "INFO",
					AffectedHostname: "selfsigned.example.internal",
					Evidence:         "Negotiated protocol is TLS 1.3 (RFC 8446).",
					Explanation:      "Protocol version is modern.",
					Remediation:      "No remediation required.",
					Status:           "passed",
				},
			},
			SecurityGrade:    "F",
			Score:            &score45,
			ScoreExplanation: "Calculated score 45/100 (Grade F). Base: 100 points. Deductions: Untrusted certificate authority or chain failure (-35), Critical high-severity security finding capped score to 45 (Grade F).",
		},
		{
			ID:                 "demo-expiring-soon",
			Hostname:           "expiring-soon.example.internal",
			ResolvedIP:         "198.51.100.22",
			Port:               443,
			Timestamp:          now.Add(-1 * time.Hour),
			DurationMs:         210,
			Status:             "completed",
			TLSVersion:         "TLS 1.3",
			TLSVersionRaw:      0x0304,
			CipherSuite:        "TLS_AES_128_GCM_SHA256",
			CipherSuiteRaw:     0x1301,
			ServerName:         "expiring-soon.example.internal",
			NegotiatedProtocol: "h2",
			IsDemo:             true,
			PeerCertificate: &models.CertificateSummary{
				SubjectCommonName:     "expiring-soon.example.internal",
				SubjectOrganization:   []string{"Fintech Solutions Ltd."},
				IssuerCommonName:      "Let's Encrypt Authority R3",
				IssuerOrganization:    []string{"Let's Encrypt"},
				SerialNumber:          "03A123985CF89A10",
				NotBefore:             now.Add(-85 * 24 * time.Hour),
				NotAfter:              now.Add(5 * 24 * time.Hour),
				DaysRemaining:         5,
				IsExpired:             false,
				IsExpiringSoon:        true,
				DNSNames:              []string{"expiring-soon.example.internal"},
				SignatureAlgorithm:    "SHA256-RSA",
				PublicKeyAlgorithm:    "RSA",
				KeySizeBits:           2048,
				FingerprintSHA256:     "22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11",
			},
			Validation: models.ValidationResult{
				HostnameVerified: true,
				ChainVerified:    true,
				TrustStatus:      "trusted",
				CompletedChecks: []models.CheckResult{
					{ID: "CHK-DNS", Name: "DNS Resolution", Description: "Safe IP verification", Passed: true, Status: "passed", Details: "Resolved to safe synthetic IP 198.51.100.22"},
					{ID: "CHK-HANDSHAKE", Name: "TLS Handshake", Description: "TLS negotiation", Passed: true, Status: "passed", Details: "TLS 1.3 / AES-128-GCM"},
					{ID: "CHK-HOSTNAME", Name: "Hostname Verification", Description: "SAN matching", Passed: true, Status: "passed", Details: "Hostname matches SAN."},
					{ID: "CHK-VALIDITY", Name: "Certificate Validity", Description: "Temporal checks", Passed: true, Status: "passed", Details: "Certificate active with 5 days remaining."},
					{ID: "CHK-CHAIN", Name: "Chain Verification", Description: "Trust validation", Passed: true, Status: "passed", Details: "Chain verified against Let's Encrypt root."},
				},
			},
			Findings: []models.Finding{
				{
					RuleID:           "TLS-RULE-EXPIRING-SOON",
					Title:            "Certificate Expiring Soon (Within 14 Days)",
					Severity:         "MEDIUM",
					AffectedHostname: "expiring-soon.example.internal",
					Evidence:         fmt.Sprintf("Certificate expires in 5 days on %s.", now.Add(5*24*time.Hour).Format("2006-01-02")),
					Explanation:      "The certificate is approaching its expiration date. If renewal is not completed before expiry, client connections will encounter hard TLS handshake errors.",
					Remediation:      "Initiate certificate renewal and trigger automated server deployment before the validity window elapses.",
					Status:           "warning",
				},
				{
					RuleID:           "TLS-RULE-TLS13-MODERN",
					Title:            "Modern TLS 1.3 Negotiated",
					Severity:         "INFO",
					AffectedHostname: "expiring-soon.example.internal",
					Evidence:         "Negotiated protocol is TLS 1.3 (RFC 8446).",
					Explanation:      "TLS 1.3 provides enhanced security.",
					Remediation:      "No remediation required.",
					Status:           "passed",
				},
			},
			SecurityGrade:    "B",
			Score:            &score80,
			ScoreExplanation: "Calculated score 80/100 (Grade B). Base: 100 points. Deductions: Certificate expires in <= 14 days (-20).",
		},
		{
			ID:                 "demo-tls12-legacy",
			Hostname:           "tls12-legacy.example.internal",
			ResolvedIP:         "198.51.100.26",
			Port:               443,
			Timestamp:          now.Add(-2 * time.Hour),
			DurationMs:         280,
			Status:             "completed",
			TLSVersion:         "TLS 1.2",
			TLSVersionRaw:      0x0303,
			CipherSuite:        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			CipherSuiteRaw:     0xC02F,
			ServerName:         "tls12-legacy.example.internal",
			NegotiatedProtocol: "http/1.1",
			IsDemo:             true,
			PeerCertificate: &models.CertificateSummary{
				SubjectCommonName:     "tls12-legacy.example.internal",
				SubjectOrganization:   []string{"Enterprise Legacy App"},
				IssuerCommonName:      "DigiCert Global Root G2",
				IssuerOrganization:    []string{"DigiCert Inc"},
				SerialNumber:          "4B1299C0012FA",
				NotBefore:             now.Add(-30 * 24 * time.Hour),
				NotAfter:              now.Add(335 * 24 * time.Hour),
				DaysRemaining:         335,
				IsExpired:             false,
				IsExpiringSoon:        false,
				DNSNames:              []string{"tls12-legacy.example.internal"},
				SignatureAlgorithm:    "SHA256-RSA",
				PublicKeyAlgorithm:    "RSA",
				KeySizeBits:           2048,
				FingerprintSHA256:     "33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22",
			},
			Validation: models.ValidationResult{
				HostnameVerified: true,
				ChainVerified:    true,
				TrustStatus:      "trusted",
				CompletedChecks: []models.CheckResult{
					{ID: "CHK-DNS", Name: "DNS Resolution", Description: "Safe IP verification", Passed: true, Status: "passed", Details: "Resolved to safe synthetic IP 198.51.100.26"},
					{ID: "CHK-HANDSHAKE", Name: "TLS Handshake", Description: "TLS negotiation", Passed: true, Status: "passed", Details: "TLS 1.2 / ECDHE-RSA-AES128-GCM"},
					{ID: "CHK-HOSTNAME", Name: "Hostname Verification", Description: "SAN matching", Passed: true, Status: "passed", Details: "Hostname matches SAN."},
					{ID: "CHK-VALIDITY", Name: "Certificate Validity", Description: "Temporal checks", Passed: true, Status: "passed", Details: "Valid for 335 days."},
					{ID: "CHK-CHAIN", Name: "Chain Verification", Description: "Trust validation", Passed: true, Status: "passed", Details: "Chain verified successfully."},
				},
			},
			Findings: []models.Finding{
				{
					RuleID:           "TLS-RULE-TLS12-ACCEPTABLE",
					Title:            "TLS 1.2 Negotiated",
					Severity:         "INFO",
					AffectedHostname: "tls12-legacy.example.internal",
					Evidence:         "Negotiated protocol is TLS 1.2 (RFC 5246).",
					Explanation:      "TLS 1.2 is currently secure and widely compatible, but does not provide the improved latency (0-RTT/1-RTT) or streamlined cryptographic hygiene of TLS 1.3.",
					Remediation:      "Enable TLS 1.3 on your web server and reverse proxy while retaining TLS 1.2 as a fallback for legacy clients.",
					Status:           "passed",
				},
			},
			SecurityGrade:    "A",
			Score:            &score95,
			ScoreExplanation: "Calculated score 95/100 (Grade A). Base: 100 points. Deductions: TLS 1.2 negotiated instead of TLS 1.3 (-5).",
		},
		{
			ID:                 "demo-modern-secure",
			Hostname:           "modern-secure.example.com",
			ResolvedIP:         "198.51.100.30",
			Port:               443,
			Timestamp:          now.Add(-3 * time.Hour),
			DurationMs:         145,
			Status:             "completed",
			TLSVersion:         "TLS 1.3",
			TLSVersionRaw:      0x0304,
			CipherSuite:        "TLS_AES_256_GCM_SHA384",
			CipherSuiteRaw:     0x1302,
			ServerName:         "modern-secure.example.com",
			NegotiatedProtocol: "h2",
			IsDemo:             true,
			PeerCertificate: &models.CertificateSummary{
				SubjectCommonName:     "modern-secure.example.com",
				SubjectOrganization:   []string{"Cloud Security Architecture"},
				IssuerCommonName:      "DigiCert Global Root G2",
				IssuerOrganization:    []string{"DigiCert Inc"},
				SerialNumber:          "1A9908F45A12",
				NotBefore:             now.Add(-20 * 24 * time.Hour),
				NotAfter:              now.Add(160 * 24 * time.Hour),
				DaysRemaining:         160,
				IsExpired:             false,
				IsExpiringSoon:        false,
				DNSNames:              []string{"modern-secure.example.com", "api.modern-secure.example.com"},
				SignatureAlgorithm:    "SHA384-RSA",
				PublicKeyAlgorithm:    "RSA",
				KeySizeBits:           4096,
				FingerprintSHA256:     "55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44",
			},
			Validation: models.ValidationResult{
				HostnameVerified: true,
				ChainVerified:    true,
				TrustStatus:      "trusted",
				CompletedChecks: []models.CheckResult{
					{ID: "CHK-DNS", Name: "DNS Resolution", Description: "Safe IP verification", Passed: true, Status: "passed", Details: "Resolved to safe synthetic IP 198.51.100.30"},
					{ID: "CHK-HANDSHAKE", Name: "TLS Handshake", Description: "TLS negotiation", Passed: true, Status: "passed", Details: "TLS 1.3 / AES-256-GCM"},
					{ID: "CHK-HOSTNAME", Name: "Hostname Verification", Description: "SAN matching", Passed: true, Status: "passed", Details: "Hostname matches SAN."},
					{ID: "CHK-VALIDITY", Name: "Certificate Validity", Description: "Temporal checks", Passed: true, Status: "passed", Details: "Valid for 160 days."},
					{ID: "CHK-CHAIN", Name: "Chain Verification", Description: "Trust validation", Passed: true, Status: "passed", Details: "Chain verified against root authority."},
					{ID: "CHK-PROTOCOL", Name: "Protocol Modernity", Description: "TLS version", Passed: true, Status: "passed", Details: "TLS 1.3 modern protocol."},
					{ID: "CHK-CIPHER", Name: "Cipher Suite", Description: "AEAD encryption", Passed: true, Status: "passed", Details: "AES-256-GCM AEAD cipher."},
					{ID: "CHK-KEY", Name: "Key Strength", Description: "Key size", Passed: true, Status: "passed", Details: "RSA 4096-bit key."},
				},
			},
			Findings: []models.Finding{
				{
					RuleID:           "TLS-RULE-TLS13-MODERN",
					Title:            "Modern TLS 1.3 Negotiated",
					Severity:         "INFO",
					AffectedHostname: "modern-secure.example.com",
					Evidence:         "Negotiated protocol is TLS 1.3 with cipher TLS_AES_256_GCM_SHA384.",
					Explanation:      "TLS 1.3 provides optimal security with mandatory forward secrecy and streamlined handshake.",
					Remediation:      "No remediation required.",
					Status:           "passed",
				},
			},
			SecurityGrade:    "A+",
			Score:            &score100,
			ScoreExplanation: "Calculated score 100/100 (Grade A+). Base: 100 points. Zero security deductions; optimal TLS 1.3 and PKI trust configuration.",
		},
	}
}

// renderSanitizedHTMLReport generates a clean, standalone, printable HTML document for an assessment.
func renderSanitizedHTMLReport(r *models.AssessmentResult) string {
	var b strings.Builder

	scoreStr := "Insufficient data"
	if r.Score != nil {
		scoreStr = fmt.Sprintf("%d / 100", *r.Score)
	}

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TLScope Assessment Report — ` + html.EscapeString(r.Hostname) + `</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 32px; background: #f8fafc; color: #0f172a; line-height: 1.5; }
  .container { max-width: 900px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); padding: 36px; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #0f766e; padding-bottom: 20px; margin-bottom: 24px; }
  .title { font-size: 24px; font-weight: 700; color: #0f172a; margin: 0; }
  .subtitle { font-size: 14px; color: #64748b; margin-top: 4px; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
  .badge-grade { font-size: 20px; padding: 8px 18px; }
  .grade-A, .grade-APlus { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
  .grade-B { background: #fef9c3; color: #854d0e; border: 1px solid #fef08a; }
  .grade-C { background: #ffedd5; color: #9a3412; border: 1px solid #fed7aa; }
  .grade-F { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
  .section { margin-bottom: 28px; }
  .section-title { font-size: 16px; font-weight: 700; color: #1e293b; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.05em; }
  .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
  .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 14px; }
  .label { font-size: 12px; font-weight: 600; color: #64748b; text-transform: uppercase; margin-bottom: 4px; }
  .value { font-size: 14px; font-weight: 500; color: #0f172a; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
  th { background: #f1f5f9; text-align: left; padding: 10px 12px; font-weight: 600; color: #475569; border-bottom: 1px solid #cbd5e1; }
  td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  .sev-HIGH { background: #fee2e2; color: #991b1b; }
  .sev-MEDIUM { background: #fef3c7; color: #92400e; }
  .sev-LOW { background: #f1f5f9; color: #475569; }
  .sev-INFO { background: #e0f2fe; color: #0369a1; }
  .disclaimer { margin-top: 36px; padding: 16px; background: #fffbeb; border: 1px solid #fef3c7; border-radius: 6px; font-size: 12px; color: #92400e; }
  @media print {
    body { background: #ffffff; padding: 0; }
    .container { border: none; box-shadow: none; padding: 0; }
  }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 class="title">TLScope Assessment Report</h1>
      <div class="subtitle">Cloud & Network Security Certificate and TLS Analyzer</div>
      <div class="subtitle">Target: <strong>` + html.EscapeString(r.Hostname) + `</strong> | Port: 443 | Generated: ` + html.EscapeString(r.Timestamp.Format("2006-01-02 15:04:05 MST")) + `</div>
    </div>
    <div style="text-align: right;">
      <span class="badge badge-grade grade-` + strings.ReplaceAll(html.EscapeString(r.SecurityGrade), "+", "Plus") + `">Grade ` + html.EscapeString(r.SecurityGrade) + `</span>
      <div style="font-size: 13px; color: #64748b; margin-top: 6px;">Score: ` + html.EscapeString(scoreStr) + `</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Assessment Summary</div>
    <div class="grid">
      <div class="card"><div class="label">Negotiated Protocol</div><div class="value">` + html.EscapeString(r.TLSVersion) + `</div></div>
      <div class="card"><div class="label">Cipher Suite</div><div class="value">` + html.EscapeString(r.CipherSuite) + `</div></div>
      <div class="card"><div class="label">Resolved Public Destination</div><div class="value">` + html.EscapeString(r.ResolvedIP) + `</div></div>
      <div class="card"><div class="label">PKI Trust Status</div><div class="value">` + html.EscapeString(strings.ToUpper(r.Validation.TrustStatus)) + `</div></div>
    </div>
  </div>`)

	if r.PeerCertificate != nil {
		cert := r.PeerCertificate
		b.WriteString(`
  <div class="section">
    <div class="section-title">Presented Peer Certificate Details</div>
    <div class="grid">
      <div class="card"><div class="label">Common Name (CN)</div><div class="value">` + html.EscapeString(cert.SubjectCommonName) + `</div></div>
      <div class="card"><div class="label">Issuer</div><div class="value">` + html.EscapeString(cert.IssuerCommonName) + `</div></div>
      <div class="card"><div class="label">Valid Not Before</div><div class="value">` + html.EscapeString(cert.NotBefore.Format("2006-01-02 15:04:05 MST")) + `</div></div>
      <div class="card"><div class="label">Valid Not After</div><div class="value">` + html.EscapeString(cert.NotAfter.Format("2006-01-02 15:04:05 MST")) + ` (` + fmt.Sprintf("%d", cert.DaysRemaining) + ` days)</div></div>
      <div class="card"><div class="label">Key Specifications</div><div class="value">` + html.EscapeString(fmt.Sprintf("%s %d-bit", cert.PublicKeyAlgorithm, cert.KeySizeBits)) + `</div></div>
      <div class="card"><div class="label">Signature Algorithm</div><div class="value">` + html.EscapeString(cert.SignatureAlgorithm) + `</div></div>
    </div>
    <div class="card" style="margin-top: 16px;">
      <div class="label">Subject Alternative Names (SANs)</div>
      <div class="value" style="font-size: 12px;">` + html.EscapeString(strings.Join(cert.DNSNames, ", ")) + `</div>
    </div>
    <div class="card" style="margin-top: 16px;">
      <div class="label">SHA-256 Fingerprint</div>
      <div class="value" style="font-size: 11px;">` + html.EscapeString(cert.FingerprintSHA256) + `</div>
    </div>
  </div>`)
	}

	b.WriteString(`
  <div class="section">
    <div class="section-title">Security Findings and Remediation Guidance (` + fmt.Sprintf("%d", len(r.Findings)) + `)</div>`)

	if len(r.Findings) == 0 {
		b.WriteString(`<p style="font-size: 14px; color: #166534; background: #dcfce7; padding: 12px; border-radius: 6px;">Zero security findings identified. All evaluated cryptographic and certificate trust parameters satisfied security baseline.</p>`)
	} else {
		b.WriteString(`<table>
      <thead>
        <tr>
          <th style="width: 15%;">Severity</th>
          <th style="width: 25%;">Rule / Title</th>
          <th style="width: 30%;">Observed Evidence</th>
          <th style="width: 30%;">Recommended Remediation</th>
        </tr>
      </thead>
      <tbody>`)
		for _, f := range r.Findings {
			b.WriteString(`<tr>
          <td><span class="badge sev-` + html.EscapeString(f.Severity) + `">` + html.EscapeString(f.Severity) + `</span></td>
          <td><strong>` + html.EscapeString(f.Title) + `</strong><br><small style="color:#64748b;">` + html.EscapeString(f.RuleID) + `</small></td>
          <td><small>` + html.EscapeString(f.Evidence) + `</small></td>
          <td><small>` + html.EscapeString(f.Remediation) + `</small></td>
        </tr>`)
		}
		b.WriteString(`</tbody></table>`)
	}

	b.WriteString(`
  </div>

  <div class="disclaimer">
    <strong>Educational Disclaimer & Scope Limitations:</strong> TLScope is an educational network security assessment tool developed for an academic Cloud & Network Security course. Assessments are restricted to passive TLS handshakes on standard TCP port 443. This report does not represent a comprehensive penetration test, application vulnerability assessment, or absolute guarantee of server security.
  </div>
</div>
</body>
</html>`)

	return b.String()
}

func sanitizeFilename(s string) string {
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	resp := models.ErrorResponse{
		Error: msg,
		Code:  code,
	}
	writeJSON(w, status, resp)
}
