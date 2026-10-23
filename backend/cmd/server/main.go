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
	port := flag.String("port", defaultPort(), "HTTP server port")
	host := flag.String("host", defaultHost(), "Host address to bind to")
	flag.Parse()

	addr := fmt.Sprintf("%s:%s", *host, *port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      web.NewHandler(),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("TLScope Backend API Service listening on http://%s", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Fatal: HTTP server error: %v", err)
		}
	}()

	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
}

func defaultPort() string {
	if port := os.Getenv("PORT"); port != "" {
		return port
	}
	return "8080"
}

func defaultHost() string {
	// Vercel assigns PORT and needs the application to accept connections on
	// every interface. Local development remains bound to localhost by default.
	if os.Getenv("PORT") != "" {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}
