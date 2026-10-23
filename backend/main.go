package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tlscope/internal/web"
)

func main() {
	port := flag.Int("port", 8080, "HTTP server port (default 8080)")
	host := flag.String("host", "127.0.0.1", "Host address to bind to (default localhost 127.0.0.1)")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      web.NewHandler(),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("=====================================================")
		log.Printf("  TLScope Backend API Service v1.0.0")
		log.Printf("  Listening on http://%s", addr)
		log.Printf("  Bound to localhost for secure development.")
		log.Printf("  Endpoints: /api/health, /api/analyze, /api/history, /api/demo")
		log.Printf("=====================================================")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Fatal: HTTP server error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down TLScope backend service gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
	log.Println("TLScope backend service stopped.")
}
