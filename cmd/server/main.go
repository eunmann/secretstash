// Package main provides the HTTP server for AWS Secrets Manager local implementation
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/eunmann/secretstash/internal/api"
	"github.com/eunmann/secretstash/internal/core"
	"github.com/eunmann/secretstash/internal/storage"
)

const (
	defaultPort            = "4566"
	defaultPersistenceFile = "/data/secrets.json"
)

//nolint:funlen // Main function handles setup and shutdown - reasonable length
func main() {
	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	// Get configuration from environment
	port := getEnv("PORT", defaultPort)
	persistenceFile := getEnv("PERSISTENCE_FILE", "")

	log.Info().
		Str("port", port).
		Str("persistence_file", persistenceFile).
		Msg("Starting AWS Secrets Manager Local Mock")

	// Initialize storage
	store := storage.NewMemoryStorage(persistenceFile)

	// Load existing secrets if persistence is enabled
	if persistenceFile != "" {
		if err := store.Load(); err != nil {
			log.Warn().Err(err).Msg("Failed to load persisted secrets, starting fresh")
		} else {
			log.Info().Msg("Loaded persisted secrets")
		}
	}

	// Initialize secret manager
	secretManager := core.NewSecretManager(store)

	// Create HTTP router
	router := api.NewRouter(secretManager)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Info().Str("address", server.Addr).Msg("Server listening")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server...")

	// Save secrets if persistence is enabled
	if persistenceFile != "" {
		if err := store.Save(); err != nil {
			log.Error().Err(err).Msg("Failed to save secrets")
		} else {
			log.Info().Msg("Secrets saved")
		}
	}

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
		shutdownCancel() // Cancel before exit
		os.Exit(1)       //nolint:gocritic // exitAfterDefer acceptable in error path
	}

	log.Info().Msg("Server stopped")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
