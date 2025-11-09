package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/eunmann/secretstash/internal/core"
	"github.com/eunmann/secretstash/internal/types"
)

// Handler manages HTTP requests for Secrets Manager API
type Handler struct {
	secretManager *core.SecretManager
}

// NewHandler creates a new API handler
func NewHandler(secretManager *core.SecretManager) *Handler {
	return &Handler{
		secretManager: secretManager,
	}
}

// ServeHTTP implements http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.HandleRequest(w, r)
}

// HandleRequest routes requests based on X-Amz-Target header
//
//nolint:funlen // Request handler with routing logic - complexity justified
func (h *Handler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// AWS JSON protocol uses X-Amz-Target header to determine the action
	target := r.Header.Get("X-Amz-Target")
	if target == "" {
		writeError(w, &types.APIError{
			Type:    ErrInvalidRequest,
			Message: "Missing X-Amz-Target header",
		})
		return
	}

	// Extract action from target (format: "secretsmanager.ActionName")
	parts := strings.Split(target, ".")
	if len(parts) != 2 {
		writeError(w, &types.APIError{
			Type:    ErrInvalidRequest,
			Message: fmt.Sprintf("Invalid X-Amz-Target format: %s", target),
		})
		return
	}

	action := parts[1]

	log.Info().
		Str("action", action).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Msg("Handling request")

	// Route to appropriate handler
	switch action {
	case "CreateSecret":
		h.handleCreateSecret(w, r)
	case "GetSecretValue":
		h.handleGetSecretValue(w, r)
	case "PutSecretValue":
		h.handlePutSecretValue(w, r)
	case "UpdateSecret":
		h.handleUpdateSecret(w, r)
	case "DeleteSecret":
		h.handleDeleteSecret(w, r)
	case "DescribeSecret":
		h.handleDescribeSecret(w, r)
	case "ListSecrets":
		h.handleListSecrets(w, r)
	case "TagResource":
		h.handleTagResource(w, r)
	case "UntagResource":
		h.handleUntagResource(w, r)
	case "UpdateSecretVersionStage":
		h.handleUpdateSecretVersionStage(w, r)
	case "RotateSecret":
		h.handleRotateSecret(w, r)
	case "RestoreSecret":
		h.handleRestoreSecret(w, r)
	case "GetRandomPassword":
		h.handleGetRandomPassword(w, r)
	case "BatchGetSecretValue":
		h.handleBatchGetSecretValue(w, r)
	case "ReplicateSecretToRegions":
		h.handleReplicateSecretToRegions(w, r)
	case "RemoveRegionsFromReplication":
		h.handleRemoveRegionsFromReplication(w, r)
	case "ListSecretVersionIds":
		h.handleListSecretVersionIds(w, r)
	case "CancelRotateSecret":
		h.handleCancelRotateSecret(w, r)
	default:
		writeError(w, &types.APIError{
			Type:    ErrInvalidRequest,
			Message: fmt.Sprintf("Unknown action: %s", action),
		})
	}
}

// handleCreateSecret processes CreateSecret requests
func (h *Handler) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	var req types.CreateSecretRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.CreateSecret(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleGetSecretValue processes GetSecretValue requests
func (h *Handler) handleGetSecretValue(w http.ResponseWriter, r *http.Request) {
	var req types.GetSecretValueRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.GetSecretValue(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handlePutSecretValue processes PutSecretValue requests
func (h *Handler) handlePutSecretValue(w http.ResponseWriter, r *http.Request) {
	var req types.PutSecretValueRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.PutSecretValue(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleUpdateSecret processes UpdateSecret requests
func (h *Handler) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	var req types.UpdateSecretRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.UpdateSecret(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleDeleteSecret processes DeleteSecret requests
func (h *Handler) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	var req types.DeleteSecretRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.DeleteSecret(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleDescribeSecret processes DescribeSecret requests
func (h *Handler) handleDescribeSecret(w http.ResponseWriter, r *http.Request) {
	var req types.DescribeSecretRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.DescribeSecret(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleListSecrets processes ListSecrets requests
func (h *Handler) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	var req types.ListSecretsRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.ListSecrets(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleTagResource processes TagResource requests
func (h *Handler) handleTagResource(w http.ResponseWriter, r *http.Request) {
	var req types.TagResourceRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.TagResource(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleUntagResource processes UntagResource requests
func (h *Handler) handleUntagResource(w http.ResponseWriter, r *http.Request) {
	var req types.UntagResourceRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.UntagResource(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleUpdateSecretVersionStage processes UpdateSecretVersionStage requests
func (h *Handler) handleUpdateSecretVersionStage(w http.ResponseWriter, r *http.Request) {
	var req types.UpdateSecretVersionStageRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.UpdateSecretVersionStage(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleRotateSecret processes RotateSecret requests
func (h *Handler) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	var req types.RotateSecretRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.RotateSecret(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleRestoreSecret processes RestoreSecret requests
func (h *Handler) handleRestoreSecret(w http.ResponseWriter, r *http.Request) {
	var req types.RestoreSecretRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.RestoreSecret(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleGetRandomPassword processes GetRandomPassword requests
func (h *Handler) handleGetRandomPassword(w http.ResponseWriter, r *http.Request) {
	var req types.GetRandomPasswordRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.GetRandomPassword(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleBatchGetSecretValue processes BatchGetSecretValue requests
func (h *Handler) handleBatchGetSecretValue(w http.ResponseWriter, r *http.Request) {
	var req types.BatchGetSecretValueRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.BatchGetSecretValue(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleReplicateSecretToRegions processes ReplicateSecretToRegions requests
func (h *Handler) handleReplicateSecretToRegions(w http.ResponseWriter, r *http.Request) {
	var req types.ReplicateSecretToRegionsRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.ReplicateSecretToRegions(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleRemoveRegionsFromReplication processes RemoveRegionsFromReplication requests
func (h *Handler) handleRemoveRegionsFromReplication(w http.ResponseWriter, r *http.Request) {
	var req types.RemoveRegionsFromReplicationRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.RemoveRegionsFromReplication(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleListSecretVersionIds processes ListSecretVersionIds requests
func (h *Handler) handleListSecretVersionIds(w http.ResponseWriter, r *http.Request) {
	var req types.ListSecretVersionIdsRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.ListSecretVersionIds(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// handleCancelRotateSecret processes CancelRotateSecret requests
func (h *Handler) handleCancelRotateSecret(w http.ResponseWriter, r *http.Request) {
	var req types.CancelRotateSecretRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := h.secretManager.CancelRotateSecret(&req)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, resp)
}

// decodeRequest decodes a JSON request body into the target struct
func decodeRequest(r *http.Request, target interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &types.APIError{
			Type:    ErrInvalidRequest,
			Message: "Failed to read request body",
		}
	}
	defer func() { _ = r.Body.Close() }()

	if len(body) == 0 {
		// Empty body is acceptable for some requests (e.g., ListSecrets)
		return nil
	}

	if err := json.Unmarshal(body, target); err != nil {
		return &types.APIError{
			Type:    ErrInvalidRequest,
			Message: fmt.Sprintf("Invalid JSON: %v", err),
		}
	}

	return nil
}
