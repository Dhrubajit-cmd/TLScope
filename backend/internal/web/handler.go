// Package web assembles the TLScope HTTP handler for local and serverless use.
package web

import (
	"net/http"
	"os"
	"strings"

	"tlscope/internal/api"
)

// NewHandler creates the complete TLScope API handler. It deliberately does not
// start a listener, so it can be used by both the local executable and Vercel.
func NewHandler() http.Handler {
	server := api.NewServer()
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	allowedOrigins := configuredOrigins()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if allowedOrigins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if r.Method == http.MethodOptions {
			if origin != "" && !allowedOrigins[origin] {
				http.Error(w, "Origin is not allowed", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func configuredOrigins() map[string]bool {
	// The production deployment sets TLSCOPE_ALLOWED_ORIGINS to the public
	// frontend URL. Local Vite development works without any environment setup.
	raw := os.Getenv("TLSCOPE_ALLOWED_ORIGINS")
	if raw == "" {
		raw = "http://localhost:5173,http://127.0.0.1:5173"
	}

	origins := make(map[string]bool)
	for _, origin := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(origin); trimmed != "" {
			origins[trimmed] = true
		}
	}
	return origins
}
