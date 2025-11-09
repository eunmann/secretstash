package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/eunmann/secretstash/internal/core"
)

// NewRouter creates a new HTTP router
func NewRouter(secretManager *core.SecretManager) http.Handler {
	r := chi.NewRouter()

	// Apply middleware
	r.Use(RecoveryMiddleware)
	r.Use(LoggingMiddleware)
	r.Use(CORSMiddleware)

	// Create handler
	handler := NewHandler(secretManager)

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Main endpoint - all AWS Secrets Manager requests go to POST /
	r.Post("/", handler.HandleRequest)

	return r
}
