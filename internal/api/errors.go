// Package api provides HTTP handlers and routing for the Secrets Manager API
package api

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/eunmann/secretstash/internal/types"
)

// Error type constants matching AWS Secrets Manager errors
const (
	ErrInvalidParameter        = "InvalidParameterException"
	ErrInvalidRequest          = "InvalidRequestException"
	ErrResourceExists          = "ResourceExistsException"
	ErrResourceNotFound        = "ResourceNotFoundException"
	ErrInternalServiceError    = "InternalServiceError"
	ErrInvalidParameterValue   = "InvalidParameterValueException"
	ErrLimitExceeded           = "LimitExceededException"
	ErrDecryptionFailure       = "DecryptionFailure"
	ErrEncryptionFailure       = "EncryptionFailure"
	ErrMalformedPolicyDocument = "MalformedPolicyDocumentException"
	ErrPreconditionNotMet      = "PreconditionNotMetException"
	ErrPublicPolicyException   = "PublicPolicyException"
)

// HTTP status codes for different error types
var errorStatusCodes = map[string]int{
	ErrInvalidParameter:        http.StatusBadRequest,
	ErrInvalidRequest:          http.StatusBadRequest,
	ErrResourceExists:          http.StatusBadRequest,
	ErrResourceNotFound:        http.StatusBadRequest,
	ErrInternalServiceError:    http.StatusInternalServerError,
	ErrInvalidParameterValue:   http.StatusBadRequest,
	ErrLimitExceeded:           http.StatusBadRequest,
	ErrDecryptionFailure:       http.StatusBadRequest,
	ErrEncryptionFailure:       http.StatusInternalServerError,
	ErrMalformedPolicyDocument: http.StatusBadRequest,
	ErrPreconditionNotMet:      http.StatusBadRequest,
	ErrPublicPolicyException:   http.StatusBadRequest,
}

// writeError writes an API error response
func writeError(w http.ResponseWriter, err error) {
	var apiErr *types.APIError
	var ok bool

	if apiErr, ok = err.(*types.APIError); !ok {
		// Wrap non-API errors
		apiErr = &types.APIError{
			Type:    ErrInternalServiceError,
			Message: err.Error(),
		}
	}

	statusCode := getStatusCode(apiErr.Type)

	log.Error().
		Str("error_type", apiErr.Type).
		Str("message", apiErr.Message).
		Int("status_code", statusCode).
		Msg("API error")

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(apiErr) // Error writing response is logged above
}

// getStatusCode returns the HTTP status code for an error type
func getStatusCode(errorType string) int {
	if code, exists := errorStatusCodes[errorType]; exists {
		return code
	}
	return http.StatusInternalServerError
}

// writeJSON writes a successful JSON response
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}
