// Package handler exposes TLScope as a Vercel Go Function.
package handler

import (
	"net/http"
	"sync"

	"tlscope/internal/web"
)

var (
	once    sync.Once
	handler http.Handler
)

func appHandler() http.Handler {
	once.Do(func() {
		handler = web.NewHandler()
	})
	return handler
}

// Handler is discovered by Vercel's Go runtime. vercel.json forwards every
// /api request here and preserves the original request path in the path query.
func Handler(w http.ResponseWriter, r *http.Request) {
	if path := r.URL.Query().Get("path"); path != "" {
		r.URL.Path = path
	}
	appHandler().ServeHTTP(w, r)
}
