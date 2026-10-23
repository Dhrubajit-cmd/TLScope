package models

import "time"

// AnalyzeRequest represents the payload for POST /api/analyze.
type AnalyzeRequest struct {
	Hostname string `json:"hostname"`
}

// CertificateSummary contains public certificate metadata safely extracted from X.509 certs.
type CertificateSummary struct {
	SubjectCommonName      string    `json:"subjectCommonName"`
	SubjectOrganization    []string  `json:"subjectOrganization"`
	IssuerCommonName       string    `json:"issuerCommonName"`
	IssuerOrganization     []string  `json:"issuerOrganization"`
	SerialNumber           string    `json:"serialNumber"`
	NotBefore              time.Time `json:"notBefore"`
	NotAfter               time.Time `json:"notAfter"`
	DaysRemaining          int       `json:"daysRemaining"`
	IsExpired              bool      `json:"isExpired"`
	IsExpiringSoon         bool      `json:"isExpiringSoon"` // <= 14 days
	DNSNames               []string  `json:"dnsNames"`
	IPAddresses            []string  `json:"ipAddresses"`
	SignatureAlgorithm     string    `json:"signatureAlgorithm"`
	PublicKeyAlgorithm     string    `json:"publicKeyAlgorithm"`
	KeySizeBits            int       `json:"keySizeBits"`
	FingerprintSHA256      string    `json:"fingerprintSHA256"`
	OCSPServer             []string  `json:"ocspServer,omitempty"`
	CRLDistributionPoints  []string  `json:"crlDistributionPoints,omitempty"`
	IsCA                   bool      `json:"isCA"`
}

// CheckResult records an individual check performed during assessment.
type CheckResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	Status      string `json:"status"` // "passed", "failed", "incomplete"
	Details     string `json:"details"`
}

// Finding represents an actionable, explainable security finding with evidence and remediation.
type Finding struct {
	RuleID           string `json:"ruleId"`
	Title            string `json:"title"`
	Severity         string `json:"severity"` // "HIGH", "MEDIUM", "LOW", "INFO"
	AffectedHostname string `json:"affectedHostname"`
	Evidence         string `json:"evidence"`
	Explanation      string `json:"explanation"`
	Remediation      string `json:"remediation"`
	Status           string `json:"status"` // "failed", "warning", "info", "passed"
}

// ValidationResult captures hostname and chain verification outcomes.
type ValidationResult struct {
	HostnameVerified bool          `json:"hostnameVerified"`
	HostnameError    string        `json:"hostnameError,omitempty"`
	ChainVerified    bool          `json:"chainVerified"`
	ChainError       string        `json:"chainError,omitempty"`
	TrustStatus      string        `json:"trustStatus"` // "trusted", "untrusted", "expired", "mismatch", "failed", "incomplete"
	CompletedChecks  []CheckResult `json:"completedChecks"`
	IncompleteChecks []string      `json:"incompleteChecks"`
}

// AssessmentResult is the comprehensive result of a TLS and PKI assessment.
type AssessmentResult struct {
	ID                  string                `json:"id"`
	Hostname            string                `json:"hostname"`
	ResolvedIP          string                `json:"resolvedIp"`
	Port                int                   `json:"port"`
	Timestamp           time.Time             `json:"timestamp"`
	DurationMs          int64                 `json:"durationMs"`
	Status              string                `json:"status"` // "completed", "failed", "incomplete"
	ErrorMessage        string                `json:"errorMessage,omitempty"`
	TLSVersion          string                `json:"tlsVersion"`
	TLSVersionRaw       uint16                `json:"tlsVersionRaw"`
	CipherSuite         string                `json:"cipherSuite"`
	CipherSuiteRaw      uint16                `json:"cipherSuiteRaw"`
	ServerName          string                `json:"serverName"`
	NegotiatedProtocol  string                `json:"negotiatedProtocol,omitempty"`
	PeerCertificate     *CertificateSummary   `json:"peerCertificate,omitempty"`
	CertificateChain    []*CertificateSummary `json:"certificateChain,omitempty"`
	Validation          ValidationResult      `json:"validation"`
	Findings            []Finding             `json:"findings"`
	SecurityGrade       string                `json:"securityGrade"` // "A+", "A", "B", "C", "F", or "Insufficient data"
	Score               *int                  `json:"score,omitempty"`
	ScoreExplanation    string                `json:"scoreExplanation"`
	IsDemo              bool                  `json:"isDemo"`
}

// HistorySummary provides a lightweight item for recent scans list.
type HistorySummary struct {
	ID                string    `json:"id"`
	Hostname          string    `json:"hostname"`
	ResolvedIP        string    `json:"resolvedIp"`
	Timestamp         time.Time `json:"timestamp"`
	Status            string    `json:"status"`
	TLSVersion        string    `json:"tlsVersion"`
	TrustStatus       string    `json:"trustStatus"`
	SecurityGrade     string    `json:"securityGrade"`
	Score             *int      `json:"score,omitempty"`
	FindingCount      int       `json:"findingCount"`
	HighSeverityCount int       `json:"highSeverityCount"`
	WarningCount      int       `json:"warningCount"`
	IsDemo            bool      `json:"isDemo"`
}

// HealthResponse represents the response for GET /api/health.
type HealthResponse struct {
	Status        string    `json:"status"`
	Version       string    `json:"version"`
	Timestamp     time.Time `json:"timestamp"`
	UptimeSeconds int64     `json:"uptimeSeconds"`
}

// ErrorResponse represents structured error messages returned by the API.
type ErrorResponse struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}
