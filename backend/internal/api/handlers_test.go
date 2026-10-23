package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tlscope/internal/models"
)

func setupTestServer() (*Server, *http.ServeMux) {
	s := NewServer()
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	return s, mux
}

// TestHealthEndpoint verifies GET /api/health returns operational status.
func TestHealthEndpoint(t *testing.T) {
	_, mux := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp models.HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}

	if resp.Version == "" {
		t.Errorf("expected non-empty version")
	}
}

// TestAnalyzeEndpoint_InputValidation verifies input validation on POST /api/analyze.
func TestAnalyzeEndpoint_InputValidation(t *testing.T) {
	_, mux := setupTestServer()

	tests := []struct {
		name       string
		payload    string
		expectCode int
		errCode    string
	}{
		{
			name:       "Empty payload",
			payload:    "",
			expectCode: http.StatusBadRequest,
			errCode:    "BAD_JSON",
		},
		{
			name:       "Invalid JSON",
			payload:    "{invalid",
			expectCode: http.StatusBadRequest,
			errCode:    "BAD_JSON",
		},
		{
			name:       "Empty hostname",
			payload:    `{"hostname": ""}`,
			expectCode: http.StatusBadRequest,
			errCode:    "INVALID_HOSTNAME",
		},
		{
			name:       "URL instead of hostname",
			payload:    `{"hostname": "https://example.com/test"}`,
			expectCode: http.StatusBadRequest,
			errCode:    "INVALID_HOSTNAME",
		},
		{
			name:       "Port specified",
			payload:    `{"hostname": "example.com:443"}`,
			expectCode: http.StatusBadRequest,
			errCode:    "INVALID_HOSTNAME",
		},
		{
			name:       "IP literal rejected",
			payload:    `{"hostname": "127.0.0.1"}`,
			expectCode: http.StatusBadRequest,
			errCode:    "INVALID_HOSTNAME",
		},
		{
			name:       "Reserved TLD rejected",
			payload:    `{"hostname": "test.internal"}`,
			expectCode: http.StatusBadRequest,
			errCode:    "INVALID_HOSTNAME",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/analyze", bytes.NewBufferString(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			mux.ServeHTTP(rr, req)

			if rr.Code != tt.expectCode {
				t.Errorf("expected status %d, got %d (body: %s)", tt.expectCode, rr.Code, rr.Body.String())
			}

			var errResp models.ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err == nil {
				if errResp.Code != tt.errCode {
					t.Errorf("expected error code %q, got %q", tt.errCode, errResp.Code)
				}
			}
		})
	}
}

// TestHistoryEndpoint verifies history retrieval, retrieval by ID, and clearing.
func TestHistoryEndpoint(t *testing.T) {
	server, mux := setupTestServer()

	// Initially empty
	req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var summaries []models.HistorySummary
	if err := json.Unmarshal(rr.Body.Bytes(), &summaries); err != nil {
		t.Fatalf("failed to decode history: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected empty history initially, got %d items", len(summaries))
	}

	// Add an item
	testResult := &models.AssessmentResult{
		ID:            "test-item-123",
		Hostname:      "example.com",
		ResolvedIP:    "93.184.216.34",
		Timestamp:     time.Now(),
		Status:        "completed",
		TLSVersion:    "TLS 1.3",
		SecurityGrade: "A+",
		Validation: models.ValidationResult{
			TrustStatus: "trusted",
		},
		Findings: []models.Finding{
			{RuleID: "TLS-RULE-TLS13-MODERN", Title: "Modern TLS 1.3 Negotiated", Severity: "INFO"},
		},
	}
	server.History.Add(testResult)

	// Fetch again
	req = httptest.NewRequest(http.MethodGet, "/api/history", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if err := json.Unmarshal(rr.Body.Bytes(), &summaries); err != nil {
		t.Fatalf("failed to decode history: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 history item, got %d", len(summaries))
	}
	if summaries[0].ID != "test-item-123" || summaries[0].Hostname != "example.com" {
		t.Errorf("unexpected summary data: %+v", summaries[0])
	}

	// Fetch by ID
	req = httptest.NewRequest(http.MethodGet, "/api/history/test-item-123", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	var fetchedItem models.AssessmentResult
	if err := json.Unmarshal(rr.Body.Bytes(), &fetchedItem); err != nil {
		t.Fatalf("failed to unmarshal item by ID: %v", err)
	}
	if fetchedItem.Hostname != "example.com" {
		t.Errorf("expected hostname 'example.com', got %q", fetchedItem.Hostname)
	}

	// Clear history
	req = httptest.NewRequest(http.MethodDelete, "/api/history", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 on DELETE /api/history, got %d", rr.Code)
	}

	// Verify empty
	req = httptest.NewRequest(http.MethodGet, "/api/history", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	_ = json.Unmarshal(rr.Body.Bytes(), &summaries)
	if len(summaries) != 0 {
		t.Errorf("expected 0 items after clear, got %d", len(summaries))
	}
}

// TestDemoEndpoint verifies GET /api/demo returns rich synthetic scenarios.
func TestDemoEndpoint(t *testing.T) {
	_, mux := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/demo", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var demos []*models.AssessmentResult
	if err := json.Unmarshal(rr.Body.Bytes(), &demos); err != nil {
		t.Fatalf("failed to decode demo response: %v", err)
	}

	if len(demos) < 4 {
		t.Errorf("expected at least 4 demo scenarios, got %d", len(demos))
	}

	foundExpired := false
	foundMismatch := false
	foundSelfSigned := false
	foundModern := false

	for _, d := range demos {
		if !d.IsDemo {
			t.Errorf("expected demo item %q to have IsDemo=true", d.Hostname)
		}
		if d.Hostname == "expired.example.internal" {
			foundExpired = true
		}
		if d.Hostname == "mismatch.example.internal" {
			foundMismatch = true
		}
		if d.Hostname == "selfsigned.example.internal" {
			foundSelfSigned = true
		}
		if d.Hostname == "modern-secure.example.com" {
			foundModern = true
		}
	}

	if !foundExpired || !foundMismatch || !foundSelfSigned || !foundModern {
		t.Errorf("demo scenarios missing expected test cases: expired=%v, mismatch=%v, selfsigned=%v, modern=%v", foundExpired, foundMismatch, foundSelfSigned, foundModern)
	}
}

// TestReportHTMLEndpoint verifies POST /api/report/html renders safe HTML.
func TestReportHTMLEndpoint(t *testing.T) {
	_, mux := setupTestServer()

	sample := &models.AssessmentResult{
		ID:            "scan-test-html",
		Hostname:      "test-domain.com",
		ResolvedIP:    "93.184.216.34",
		Timestamp:     time.Now(),
		Status:        "completed",
		TLSVersion:    "TLS 1.3",
		CipherSuite:   "TLS_AES_128_GCM_SHA256",
		SecurityGrade: "A+",
		Validation: models.ValidationResult{
			TrustStatus: "trusted",
		},
		Findings: []models.Finding{
			{
				RuleID:           "TLS-RULE-TLS13-MODERN",
				Title:            "Modern TLS 1.3 Negotiated",
				Severity:         "INFO",
				AffectedHostname: "test-domain.com",
				Evidence:         "Negotiated protocol is TLS 1.3.",
				Remediation:      "No remediation needed.",
			},
		},
	}

	payload, _ := json.Marshal(sample)
	req := httptest.NewRequest(http.MethodPost, "/api/report/html", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected text/html Content-Type, got %q", contentType)
	}

	htmlStr := rr.Body.String()
	if !strings.Contains(htmlStr, "TLScope Assessment Report") {
		t.Errorf("expected HTML report title in response")
	}
	if !strings.Contains(htmlStr, "test-domain.com") {
		t.Errorf("expected hostname in HTML report")
	}
}
