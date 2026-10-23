package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerServesHealthAndAllowedCORSOrigin(t *testing.T) {
	t.Setenv("TLSCOPE_ALLOWED_ORIGINS", "https://tlscope.dhrubajit.dev")
	handler := NewHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Origin", "https://tlscope.dhrubajit.dev")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected health endpoint to return 200, got %d", res.Code)
	}
	if got := res.Header().Get("Access-Control-Allow-Origin"); got != "https://tlscope.dhrubajit.dev" {
		t.Fatalf("expected allowed CORS origin, got %q", got)
	}
}

func TestHandlerRejectsDisallowedPreflightOrigin(t *testing.T) {
	t.Setenv("TLSCOPE_ALLOWED_ORIGINS", "https://tlscope.dhrubajit.dev")
	handler := NewHandler()

	req := httptest.NewRequest(http.MethodOptions, "/api/analyze", nil)
	req.Header.Set("Origin", "https://unexpected.example")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected disallowed origin to return 403, got %d", res.Code)
	}
}
