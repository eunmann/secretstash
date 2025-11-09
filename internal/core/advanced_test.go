//nolint:funlen,gocyclo // Test file
package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/eunmann/secretstash/internal/storage"
	"github.com/eunmann/secretstash/internal/types"
)

func TestListSecretVersionIds(t *testing.T) {
	tests := []struct {
		setupSecrets         func(*SecretManager)
		maxResults           *int32
		includeDeprecated    *bool
		name                 string
		secretId             string
		errorType            string
		expectedVersionCount int
		expectError          bool
	}{
		{
			name: "List versions of existing secret",
			setupSecrets: func(sm *SecretManager) {
				// Create secret with initial version
				createReq := &types.CreateSecretRequest{
					Name:         "test-secret",
					SecretString: types.StringPtr("initial-value"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add more versions
				putReq := &types.PutSecretValueRequest{
					SecretId:     "test-secret",
					SecretString: types.StringPtr("second-value"),
				}
				_, _ = sm.PutSecretValue(putReq)

				putReq2 := &types.PutSecretValueRequest{
					SecretId:     "test-secret",
					SecretString: types.StringPtr("third-value"),
				}
				_, _ = sm.PutSecretValue(putReq2)
			},
			secretId:             "test-secret",
			expectError:          false,
			expectedVersionCount: 3,
		},
		{
			name: "List versions with max results limit",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-max-results",
					SecretString: types.StringPtr("value1"),
				}
				_, _ = sm.CreateSecret(createReq)

				for i := 2; i <= 5; i++ {
					putReq := &types.PutSecretValueRequest{
						SecretId:     "test-max-results",
						SecretString: types.StringPtr("value" + string(rune('0'+i))),
					}
					_, _ = sm.PutSecretValue(putReq)
				}
			},
			secretId:             "test-max-results",
			maxResults:           types.Int32Ptr(3),
			expectError:          false,
			expectedVersionCount: 3,
		},
		{
			name: "List versions excluding deprecated",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-deprecated",
					SecretString: types.StringPtr("value1"),
				}
				resp, _ := sm.CreateSecret(createReq)
				v1 := *resp.VersionId

				// Create second version (v1 becomes AWSPREVIOUS)
				putReq := &types.PutSecretValueRequest{
					SecretId:     "test-deprecated",
					SecretString: types.StringPtr("value2"),
				}
				resp2, _ := sm.PutSecretValue(putReq)
				v2 := *resp2.VersionId

				// Create third version (v2 becomes AWSPREVIOUS, v1 deprecated)
				putReq2 := &types.PutSecretValueRequest{
					SecretId:     "test-deprecated",
					SecretString: types.StringPtr("value3"),
				}
				resp3, _ := sm.PutSecretValue(putReq2)
				v3 := *resp3.VersionId

				// Remove AWSPREVIOUS from v2 to deprecate it
				updateStageReq := &types.UpdateSecretVersionStageRequest{
					SecretId:            "test-deprecated",
					VersionStage:        "AWSPREVIOUS",
					RemoveFromVersionId: &v2,
				}
				_, _ = sm.UpdateSecretVersionStage(updateStageReq)

				// Now we should have: v3 with AWSCURRENT, v2 with AWSPREVIOUS, v1 deprecated
				// Actually, let's check what we really have and adjust
				_ = v1
				_ = v3
			},
			secretId:             "test-deprecated",
			includeDeprecated:    types.BoolPtr(false),
			expectError:          false,
			expectedVersionCount: 2, // AWSCURRENT and AWSPREVIOUS versions
		},
		{
			name: "List versions including deprecated",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-include-deprecated",
					SecretString: types.StringPtr("value1"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add two more versions
				putReq := &types.PutSecretValueRequest{
					SecretId:     "test-include-deprecated",
					SecretString: types.StringPtr("value2"),
				}
				_, _ = sm.PutSecretValue(putReq)

				putReq2 := &types.PutSecretValueRequest{
					SecretId:     "test-include-deprecated",
					SecretString: types.StringPtr("value3"),
				}
				_, _ = sm.PutSecretValue(putReq2)
			},
			secretId:             "test-include-deprecated",
			includeDeprecated:    types.BoolPtr(true),
			expectError:          false,
			expectedVersionCount: 3, // All versions including deprecated
		},
		{
			name:         "Non-existent secret",
			setupSecrets: func(sm *SecretManager) {},
			secretId:     "non-existent-secret",
			expectError:  true,
			errorType:    "ResourceNotFoundException",
		},
		{
			name: "Invalid SecretId - empty string",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-invalid-id",
					SecretString: types.StringPtr("value"),
				}
				_, _ = sm.CreateSecret(createReq)
			},
			secretId:    "",
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name: "Invalid MaxResults - too low",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-invalid-max",
					SecretString: types.StringPtr("value"),
				}
				_, _ = sm.CreateSecret(createReq)
			},
			secretId:    "test-invalid-max",
			maxResults:  types.Int32Ptr(0),
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name: "Invalid MaxResults - too high",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-invalid-max2",
					SecretString: types.StringPtr("value"),
				}
				_, _ = sm.CreateSecret(createReq)
			},
			secretId:    "test-invalid-max2",
			maxResults:  types.Int32Ptr(101),
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name: "Versions sorted by CreatedDate descending",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-sort",
					SecretString: types.StringPtr("v1"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add versions with slight delays to ensure different timestamps
				time.Sleep(10 * time.Millisecond)
				putReq := &types.PutSecretValueRequest{
					SecretId:     "test-sort",
					SecretString: types.StringPtr("v2"),
				}
				_, _ = sm.PutSecretValue(putReq)

				time.Sleep(10 * time.Millisecond)
				putReq2 := &types.PutSecretValueRequest{
					SecretId:     "test-sort",
					SecretString: types.StringPtr("v3"),
				}
				_, _ = sm.PutSecretValue(putReq2)
			},
			secretId:             "test-sort",
			includeDeprecated:    types.BoolPtr(true),
			expectError:          false,
			expectedVersionCount: 3,
		},
		{
			name: "Version with custom staging labels",
			setupSecrets: func(sm *SecretManager) {
				createReq := &types.CreateSecretRequest{
					Name:         "test-custom-stages",
					SecretString: types.StringPtr("value1"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add version with custom staging label
				customStage := "CUSTOM_STAGE"
				putReq := &types.PutSecretValueRequest{
					SecretId:      "test-custom-stages",
					SecretString:  types.StringPtr("value2"),
					VersionStages: []*string{&customStage},
				}
				_, _ = sm.PutSecretValue(putReq)
			},
			secretId:             "test-custom-stages",
			includeDeprecated:    types.BoolPtr(true),
			expectError:          false,
			expectedVersionCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh storage and manager for each test
			store := storage.NewMemoryStorage("")
			sm := NewSecretManager(store)

			// Setup secrets
			if tt.setupSecrets != nil {
				tt.setupSecrets(sm)
			}

			// Execute ListSecretVersionIds
			req := &types.ListSecretVersionIdsRequest{
				SecretId:          tt.secretId,
				MaxResults:        tt.maxResults,
				IncludeDeprecated: tt.includeDeprecated,
			}

			resp, err := sm.ListSecretVersionIds(req)

			// Check error expectations
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				} else {
					t.Errorf("Expected APIError but got %T", err)
				}
				return
			}

			// Check success expectations
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Errorf("Expected response but got nil")
				return
			}

			// Verify version count
			if len(resp.Versions) != tt.expectedVersionCount {
				t.Errorf("Expected %d versions, got %d", tt.expectedVersionCount, len(resp.Versions))
			}

			// Verify ARN and Name are present
			if resp.ARN == nil || *resp.ARN == "" {
				t.Errorf("Expected ARN to be present")
			}
			if resp.Name == nil || *resp.Name == "" {
				t.Errorf("Expected Name to be present")
			}

			// Verify versions have required fields
			for i, version := range resp.Versions {
				if version.VersionId == nil {
					t.Errorf("Version %d missing VersionId", i)
				}
				if version.CreatedDate == nil {
					t.Errorf("Version %d missing CreatedDate", i)
				}
			}

			// Verify versions are sorted by CreatedDate descending (newest first)
			if tt.name == "Versions sorted by CreatedDate descending" && len(resp.Versions) > 1 {
				for i := 0; i < len(resp.Versions)-1; i++ {
					if resp.Versions[i].CreatedDate.Before(resp.Versions[i+1].CreatedDate.Time) {
						t.Errorf("Versions not sorted correctly: version %d is older than version %d", i, i+1)
					}
				}
			}

			// Verify custom staging labels are present
			if tt.name == "Version with custom staging labels" {
				foundCustomStage := false
				for _, version := range resp.Versions {
					for _, stage := range version.VersionStages {
						if stage != nil && *stage == "CUSTOM_STAGE" {
							foundCustomStage = true
							break
						}
					}
				}
				if !foundCustomStage {
					t.Errorf("Expected to find custom staging label CUSTOM_STAGE")
				}
			}
		})
	}
}

func TestListSecretVersionIdsResponse(t *testing.T) {
	// Test that response structure matches AWS format
	store := storage.NewMemoryStorage("")
	sm := NewSecretManager(store)

	// Create a secret with multiple versions
	createReq := &types.CreateSecretRequest{
		Name:         "response-test",
		SecretString: types.StringPtr("value1"),
	}
	_, _ = sm.CreateSecret(createReq)

	putReq := &types.PutSecretValueRequest{
		SecretId:     "response-test",
		SecretString: types.StringPtr("value2"),
	}
	_, _ = sm.PutSecretValue(putReq)

	// List versions
	req := &types.ListSecretVersionIdsRequest{
		SecretId:          "response-test",
		IncludeDeprecated: types.BoolPtr(true),
	}

	resp, err := sm.ListSecretVersionIds(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify response structure
	if resp.ARN == nil {
		t.Errorf("Expected ARN field")
	}
	if resp.Name == nil {
		t.Errorf("Expected Name field")
	}
	if resp.Versions == nil {
		t.Errorf("Expected Versions field")
	}

	// Verify version entries have correct structure
	if len(resp.Versions) < 2 {
		t.Errorf("Expected at least 2 versions, got %d", len(resp.Versions))
	}

	for _, version := range resp.Versions {
		if version.VersionId == nil {
			t.Errorf("Version missing VersionId")
		}
		if version.CreatedDate == nil {
			t.Errorf("Version missing CreatedDate")
		}
		// VersionStages can be nil for deprecated versions
		// LastAccessedDate is optional
		// KmsKeyIds is optional
	}
}

func TestCancelRotateSecret(t *testing.T) {
	tests := []struct {
		setupSecret func(*SecretManager) string
		name        string
		secretId    string
		errorType   string
		expectError bool
	}{
		{
			name: "Cancel rotation in progress",
			setupSecret: func(sm *SecretManager) string {
				// Create secret
				createReq := &types.CreateSecretRequest{
					Name:         "test-cancel-rotation",
					SecretString: types.StringPtr("value1"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Start rotation (creates AWSPENDING version)
				rotateReq := &types.RotateSecretRequest{
					SecretId: "test-cancel-rotation",
				}
				_, _ = sm.RotateSecret(rotateReq)

				return "test-cancel-rotation"
			},
			expectError: false,
		},
		{
			name: "Cancel when no rotation in progress",
			setupSecret: func(sm *SecretManager) string {
				// Create secret without rotation
				createReq := &types.CreateSecretRequest{
					Name:         "test-no-rotation",
					SecretString: types.StringPtr("value1"),
				}
				_, _ = sm.CreateSecret(createReq)

				return "test-no-rotation"
			},
			expectError: true,
			errorType:   "InvalidRequestException",
		},
		{
			name: "Cancel for non-existent secret",
			setupSecret: func(sm *SecretManager) string {
				return "non-existent" //nolint:goconst // Test-specific string
			},
			expectError: true,
			errorType:   "ResourceNotFoundException",
		},
		{
			name: "Cancel for force-deleted secret",
			setupSecret: func(sm *SecretManager) string {
				// Create and force delete secret (completely removes it)
				createReq := &types.CreateSecretRequest{
					Name:         "test-force-deleted",
					SecretString: types.StringPtr("value1"),
				}
				_, _ = sm.CreateSecret(createReq)

				deleteReq := &types.DeleteSecretRequest{
					SecretId:                   "test-force-deleted",
					ForceDeleteWithoutRecovery: types.BoolPtr(true),
				}
				_, _ = sm.DeleteSecret(deleteReq)

				return "test-force-deleted"
			},
			expectError: true,
			errorType:   "ResourceNotFoundException",
		},
		{
			name: "Cancel for soft-deleted secret",
			setupSecret: func(sm *SecretManager) string {
				// Create and soft delete secret (still exists with DeletedDate)
				createReq := &types.CreateSecretRequest{
					Name:         "test-soft-deleted",
					SecretString: types.StringPtr("value1"),
				}
				_, _ = sm.CreateSecret(createReq)

				deleteReq := &types.DeleteSecretRequest{
					SecretId:             "test-soft-deleted",
					RecoveryWindowInDays: types.Int64Ptr(7),
				}
				_, _ = sm.DeleteSecret(deleteReq)

				return "test-soft-deleted"
			},
			expectError: true,
			errorType:   "InvalidRequestException",
		},
		{
			name: "Cancel with empty SecretId",
			setupSecret: func(sm *SecretManager) string {
				return ""
			},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh storage and manager
			store := storage.NewMemoryStorage("")
			sm := NewSecretManager(store)

			// Setup secret
			secretId := ""
			if tt.setupSecret != nil {
				secretId = tt.setupSecret(sm)
			}
			if tt.secretId != "" {
				secretId = tt.secretId
			}

			// Execute CancelRotateSecret
			req := &types.CancelRotateSecretRequest{
				SecretId: secretId,
			}

			resp, err := sm.CancelRotateSecret(req)

			// Check error expectations
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				} else {
					t.Errorf("Expected APIError but got %T", err)
				}
				return
			}

			// Check success expectations
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Errorf("Expected response but got nil")
				return
			}

			// Verify response fields
			if resp.ARN == nil || *resp.ARN == "" {
				t.Errorf("Expected ARN to be present")
			}
			if resp.Name == nil || *resp.Name == "" {
				t.Errorf("Expected Name to be present")
			}
			if resp.VersionId == nil || *resp.VersionId == "" {
				t.Errorf("Expected VersionId to be present")
			}

			// Verify AWSPENDING version was removed
			secret, _ := sm.storage.GetSecret(secretId)
			for _, stages := range secret.VersionIdsToStages {
				for _, stage := range stages {
					if stage == VersionStageAWSPending {
						t.Errorf("AWSPENDING stage should have been removed")
					}
				}
			}

			// Verify rotation is disabled
			if secret.RotationEnabled {
				t.Errorf("RotationEnabled should be false after cancellation")
			}
		})
	}
}

func TestCancelRotateSecretWorkflow(t *testing.T) {
	// Test the complete rotation cancellation workflow
	store := storage.NewMemoryStorage("")
	sm := NewSecretManager(store)

	// 1. Create a secret
	createReq := &types.CreateSecretRequest{
		Name:         "workflow-test",
		SecretString: types.StringPtr("initial-value"),
	}
	createResp, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	initialVersionId := *createResp.VersionId

	// 2. Start rotation
	rotateReq := &types.RotateSecretRequest{
		SecretId: "workflow-test",
	}
	rotateResp, err := sm.RotateSecret(rotateReq)
	if err != nil {
		t.Fatalf("Failed to start rotation: %v", err)
	}
	pendingVersionId := *rotateResp.VersionId

	// Verify AWSPENDING version was created
	secret, _ := sm.storage.GetSecret("workflow-test")
	hasPending := false
	for _, stages := range secret.VersionIdsToStages {
		for _, stage := range stages {
			if stage == VersionStageAWSPending {
				hasPending = true
				break
			}
		}
	}
	if !hasPending {
		t.Errorf("Expected AWSPENDING version after rotation")
	}

	// 3. Cancel rotation
	cancelReq := &types.CancelRotateSecretRequest{
		SecretId: "workflow-test",
	}
	cancelResp, err := sm.CancelRotateSecret(cancelReq)
	if err != nil {
		t.Fatalf("Failed to cancel rotation: %v", err)
	}

	// Verify the canceled version ID matches pending version
	if *cancelResp.VersionId != pendingVersionId {
		t.Errorf("Expected canceled version %s, got %s", pendingVersionId, *cancelResp.VersionId)
	}

	// 4. Verify AWSPENDING was removed
	secret, _ = sm.storage.GetSecret("workflow-test")
	hasPending = false
	for _, stages := range secret.VersionIdsToStages {
		for _, stage := range stages {
			if stage == VersionStageAWSPending {
				hasPending = true
				break
			}
		}
	}
	if hasPending {
		t.Errorf("AWSPENDING should be removed after cancellation")
	}

	// 5. Verify initial version still has AWSCURRENT
	hasCurrent := false
	for versionId, stages := range secret.VersionIdsToStages {
		if versionId == initialVersionId {
			for _, stage := range stages {
				if stage == "AWSCURRENT" {
					hasCurrent = true
					break
				}
			}
		}
	}
	if !hasCurrent {
		t.Errorf("Initial version should still have AWSCURRENT")
	}

	// 6. Verify rotation is disabled
	if secret.RotationEnabled {
		t.Errorf("Rotation should be disabled after cancellation")
	}

	// 7. Try to cancel again - should fail
	_, err = sm.CancelRotateSecret(cancelReq)
	if err == nil {
		t.Errorf("Expected error when canceling twice")
	}
	if apiErr, ok := err.(*types.APIError); ok {
		if apiErr.Type != "InvalidRequestException" {
			t.Errorf("Expected InvalidRequestException, got %s", apiErr.Type)
		}
	}
}

// TestBatchGetSecretValue tests the BatchGetSecretValue operation
func TestBatchGetSecretValue(t *testing.T) {
	tests := []struct {
		setupSecrets   func(*SecretManager)
		maxResults     *int32
		name           string
		errorType      string
		secretIdList   []*string
		filters        []types.Filter
		expectedCount  int
		expectedErrors int
		expectError    bool
	}{
		{
			name: "Batch get by secret ID list",
			setupSecrets: func(sm *SecretManager) {
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "secret1",
					SecretString: types.StringPtr("value1"),
				})
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "secret2",
					SecretString: types.StringPtr("value2"),
				})
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "secret3",
					SecretString: types.StringPtr("value3"),
				})
			},
			secretIdList: []*string{
				types.StringPtr("secret1"),
				types.StringPtr("secret2"),
				types.StringPtr("secret3"),
			},
			expectError:    false,
			expectedCount:  3,
			expectedErrors: 0,
		},
		{
			name: "Batch get with some non-existent secrets",
			setupSecrets: func(sm *SecretManager) {
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "existing-secret",
					SecretString: types.StringPtr("value"),
				})
			},
			secretIdList: []*string{
				types.StringPtr("existing-secret"),
				types.StringPtr("non-existent-secret"),
			},
			expectError:    false,
			expectedCount:  1,
			expectedErrors: 1,
		},
		{
			name: "Batch get with deleted secret",
			setupSecrets: func(sm *SecretManager) {
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "active-secret",
					SecretString: types.StringPtr("value1"),
				})
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "deleted-secret",
					SecretString: types.StringPtr("value2"),
				})
				_, _ = sm.DeleteSecret(&types.DeleteSecretRequest{
					SecretId:             "deleted-secret",
					RecoveryWindowInDays: types.Int64Ptr(7),
				})
			},
			secretIdList: []*string{
				types.StringPtr("active-secret"),
				types.StringPtr("deleted-secret"),
			},
			expectError:    false,
			expectedCount:  1,
			expectedErrors: 1,
		},
		{
			name: "Batch get with max results limit",
			setupSecrets: func(sm *SecretManager) {
				for i := 1; i <= 5; i++ {
					name := fmt.Sprintf("secret%d", i)
					value := fmt.Sprintf("value%d", i)
					_, _ = sm.CreateSecret(&types.CreateSecretRequest{
						Name:         name,
						SecretString: types.StringPtr(value),
					})
				}
			},
			secretIdList: []*string{
				types.StringPtr("secret1"),
				types.StringPtr("secret2"),
				types.StringPtr("secret3"),
				types.StringPtr("secret4"),
				types.StringPtr("secret5"),
			},
			maxResults:     types.Int32Ptr(3),
			expectError:    false,
			expectedCount:  3,
			expectedErrors: 0,
		},
		{
			name: "Batch get by filters - by name",
			setupSecrets: func(sm *SecretManager) {
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "prod-db-password",
					SecretString: types.StringPtr("prod-value"),
				})
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "dev-db-password",
					SecretString: types.StringPtr("dev-value"),
				})
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "prod-api-key",
					SecretString: types.StringPtr("api-value"),
				})
			},
			filters: []types.Filter{
				{
					Key:    types.StringPtr("name"),
					Values: []*string{types.StringPtr("prod-db-password")},
				},
			},
			expectError:    false,
			expectedCount:  1,
			expectedErrors: 0,
		},
		{
			name: "Batch get by filters - by tag",
			setupSecrets: func(sm *SecretManager) {
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "tagged-secret1",
					SecretString: types.StringPtr("value1"),
					Tags: []types.Tag{
						{Key: types.StringPtr("Environment"), Value: types.StringPtr("Production")},
					},
				})
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "tagged-secret2",
					SecretString: types.StringPtr("value2"),
					Tags: []types.Tag{
						{Key: types.StringPtr("Environment"), Value: types.StringPtr("Development")},
					},
				})
			},
			filters: []types.Filter{
				{
					Key:    types.StringPtr("tag-key"),
					Values: []*string{types.StringPtr("Environment")},
				},
			},
			expectError:    false,
			expectedCount:  2,
			expectedErrors: 0,
		},
		{
			name: "Empty secret ID list",
			setupSecrets: func(sm *SecretManager) {
				_, _ = sm.CreateSecret(&types.CreateSecretRequest{
					Name:         "some-secret",
					SecretString: types.StringPtr("value"),
				})
			},
			secretIdList:   []*string{},
			expectError:    false,
			expectedCount:  0,
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewMemoryStorage("")
			sm := NewSecretManager(store)

			if tt.setupSecrets != nil {
				tt.setupSecrets(sm)
			}

			req := &types.BatchGetSecretValueRequest{
				SecretIdList: tt.secretIdList,
				Filters:      tt.filters,
				MaxResults:   tt.maxResults,
			}

			resp, err := sm.BatchGetSecretValue(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(resp.SecretValues) != tt.expectedCount {
				t.Errorf("Expected %d secrets, got %d", tt.expectedCount, len(resp.SecretValues))
			}

			if len(resp.Errors) != tt.expectedErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectedErrors, len(resp.Errors))
			}

			// Verify each secret has required fields
			for i, secret := range resp.SecretValues {
				if secret.ARN == nil {
					t.Errorf("Secret %d missing ARN", i)
				}
				if secret.Name == nil {
					t.Errorf("Secret %d missing Name", i)
				}
				if secret.VersionId == nil {
					t.Errorf("Secret %d missing VersionId", i)
				}
				if secret.CreatedDate == nil {
					t.Errorf("Secret %d missing CreatedDate", i)
				}
				if secret.SecretString == nil && secret.SecretBinary == nil {
					t.Errorf("Secret %d missing both SecretString and SecretBinary", i)
				}
			}
		})
	}
}

// TestBatchGetSecretValueWorkflow tests complete workflow
func TestBatchGetSecretValueWorkflow(t *testing.T) {
	store := storage.NewMemoryStorage("")
	sm := NewSecretManager(store)

	// 1. Create multiple secrets
	secrets := []string{"app-db-creds", "app-api-key", "app-jwt-secret"}
	for _, name := range secrets {
		_, err := sm.CreateSecret(&types.CreateSecretRequest{
			Name:         name,
			SecretString: types.StringPtr(fmt.Sprintf("secret-value-for-%s", name)),
			Tags: []types.Tag{
				{Key: types.StringPtr("Application"), Value: types.StringPtr("MyApp")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to create secret %s: %v", name, err)
		}
	}

	// 2. Batch get by secret ID list
	req := &types.BatchGetSecretValueRequest{
		SecretIdList: []*string{
			types.StringPtr("app-db-creds"),
			types.StringPtr("app-api-key"),
			types.StringPtr("app-jwt-secret"),
		},
	}

	resp, err := sm.BatchGetSecretValue(req)
	if err != nil {
		t.Fatalf("BatchGetSecretValue failed: %v", err)
	}

	if len(resp.SecretValues) != 3 {
		t.Errorf("Expected 3 secrets, got %d", len(resp.SecretValues))
	}

	// 3. Verify all secrets returned correctly
	for _, secret := range resp.SecretValues {
		if secret.SecretString == nil {
			t.Errorf("Secret %s missing SecretString", *secret.Name)
			continue
		}
		expectedValue := fmt.Sprintf("secret-value-for-%s", *secret.Name)
		if *secret.SecretString != expectedValue {
			t.Errorf("Secret %s has wrong value: expected %s, got %s",
				*secret.Name, expectedValue, *secret.SecretString)
		}
	}

	// 4. Delete one secret and batch get again
	_, err = sm.DeleteSecret(&types.DeleteSecretRequest{
		SecretId:             "app-api-key",
		RecoveryWindowInDays: types.Int64Ptr(7),
	})
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	resp2, err := sm.BatchGetSecretValue(req)
	if err != nil {
		t.Fatalf("BatchGetSecretValue failed: %v", err)
	}

	if len(resp2.SecretValues) != 2 {
		t.Errorf("Expected 2 secrets after deletion, got %d", len(resp2.SecretValues))
	}

	if len(resp2.Errors) != 1 {
		t.Errorf("Expected 1 error for deleted secret, got %d", len(resp2.Errors))
	}

	// 5. Batch get using filters
	filterReq := &types.BatchGetSecretValueRequest{
		Filters: []types.Filter{
			{
				Key:    types.StringPtr("tag-key"),
				Values: []*string{types.StringPtr("Application")},
			},
		},
	}

	resp3, err := sm.BatchGetSecretValue(filterReq)
	if err != nil {
		t.Fatalf("BatchGetSecretValue with filters failed: %v", err)
	}

	// Should get 2 active secrets (one was deleted)
	if len(resp3.SecretValues) != 2 {
		t.Errorf("Expected 2 secrets from filter, got %d", len(resp3.SecretValues))
	}
}

// TestReplicateSecretToRegions tests the ReplicateSecretToRegions operation
func TestReplicateSecretToRegions(t *testing.T) {
	tests := []struct {
		setupSecret       func(*SecretManager) string
		name              string
		secretId          string
		errorType         string
		addReplicaRegions []types.ReplicaRegionType
		expectedRegions   int
		expectError       bool
	}{
		{
			name: "Replicate to single region",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "replicate-test",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)
				return "replicate-test"
			},
			secretId: "replicate-test",
			addReplicaRegions: []types.ReplicaRegionType{
				{Region: types.StringPtr("us-west-2")},
			},
			expectError:     false,
			expectedRegions: 1,
		},
		{
			name: "Replicate to multiple regions",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "multi-region-test",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)
				return "multi-region-test"
			},
			secretId: "multi-region-test",
			addReplicaRegions: []types.ReplicaRegionType{
				{Region: types.StringPtr("us-west-2")},
				{Region: types.StringPtr("eu-west-1")},
				{Region: types.StringPtr("ap-southeast-1")},
			},
			expectError:     false,
			expectedRegions: 3,
		},
		{
			name: "Replicate with KMS key",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "kms-replicate-test",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)
				return "kms-replicate-test"
			},
			secretId: "kms-replicate-test",
			addReplicaRegions: []types.ReplicaRegionType{
				{
					Region:   types.StringPtr("us-west-2"),
					KmsKeyId: types.StringPtr("arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"),
				},
			},
			expectError:     false,
			expectedRegions: 1,
		},
		{
			name: "Replicate non-existent secret",
			setupSecret: func(sm *SecretManager) string {
				return "non-existent"
			},
			secretId: "non-existent",
			addReplicaRegions: []types.ReplicaRegionType{
				{Region: types.StringPtr("us-west-2")},
			},
			expectError: true,
			errorType:   "ResourceNotFoundException",
		},
		{
			name: "Replicate with empty SecretId",
			setupSecret: func(sm *SecretManager) string {
				return ""
			},
			secretId: "",
			addReplicaRegions: []types.ReplicaRegionType{
				{Region: types.StringPtr("us-west-2")},
			},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name: "Replicate with no regions",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "no-regions-test",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)
				return "no-regions-test"
			},
			secretId:          "no-regions-test",
			addReplicaRegions: []types.ReplicaRegionType{},
			expectError:       false,
			expectedRegions:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewMemoryStorage("")
			sm := NewSecretManager(store)

			if tt.setupSecret != nil {
				tt.setupSecret(sm)
			}

			req := &types.ReplicateSecretToRegionsRequest{
				SecretId:          tt.secretId,
				AddReplicaRegions: tt.addReplicaRegions,
			}

			resp, err := sm.ReplicateSecretToRegions(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if resp.ARN == nil {
				t.Error("Response missing ARN")
			}

			if len(resp.ReplicationStatus) != tt.expectedRegions {
				t.Errorf("Expected %d replicated regions, got %d", tt.expectedRegions, len(resp.ReplicationStatus))
			}

			// Verify each region has expected fields
			for i, replica := range resp.ReplicationStatus {
				if replica.Region == nil {
					t.Errorf("Replica %d missing Region", i)
				}
				if replica.Status == nil {
					t.Errorf("Replica %d missing Status", i)
				} else if *replica.Status != "InSync" {
					t.Errorf("Replica %d has status %s, expected InSync", i, *replica.Status)
				}
			}
		})
	}
}

// TestRemoveRegionsFromReplication tests the RemoveRegionsFromReplication operation
func TestRemoveRegionsFromReplication(t *testing.T) {
	tests := []struct {
		setupSecret          func(*SecretManager) string
		name                 string
		secretId             string
		errorType            string
		removeReplicaRegions []*string
		expectedRemaining    int
		expectError          bool
	}{
		{
			name: "Remove single region from replication",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "remove-test",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add replication to multiple regions
				replicateReq := &types.ReplicateSecretToRegionsRequest{
					SecretId: "remove-test",
					AddReplicaRegions: []types.ReplicaRegionType{
						{Region: types.StringPtr("us-west-2")},
						{Region: types.StringPtr("eu-west-1")},
					},
				}
				_, _ = sm.ReplicateSecretToRegions(replicateReq)
				return "remove-test"
			},
			secretId: "remove-test",
			removeReplicaRegions: []*string{
				types.StringPtr("us-west-2"),
			},
			expectError:       false,
			expectedRemaining: 1,
		},
		{
			name: "Remove multiple regions from replication",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "remove-multi-test",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add replication to multiple regions
				replicateReq := &types.ReplicateSecretToRegionsRequest{
					SecretId: "remove-multi-test",
					AddReplicaRegions: []types.ReplicaRegionType{
						{Region: types.StringPtr("us-west-2")},
						{Region: types.StringPtr("eu-west-1")},
						{Region: types.StringPtr("ap-southeast-1")},
					},
				}
				_, _ = sm.ReplicateSecretToRegions(replicateReq)
				return "remove-multi-test"
			},
			secretId: "remove-multi-test",
			removeReplicaRegions: []*string{
				types.StringPtr("us-west-2"),
				types.StringPtr("eu-west-1"),
			},
			expectError:       false,
			expectedRemaining: 1,
		},
		{
			name: "Remove all regions from replication",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "remove-all-test",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add replication
				replicateReq := &types.ReplicateSecretToRegionsRequest{
					SecretId: "remove-all-test",
					AddReplicaRegions: []types.ReplicaRegionType{
						{Region: types.StringPtr("us-west-2")},
					},
				}
				_, _ = sm.ReplicateSecretToRegions(replicateReq)
				return "remove-all-test"
			},
			secretId: "remove-all-test",
			removeReplicaRegions: []*string{
				types.StringPtr("us-west-2"),
			},
			expectError:       false,
			expectedRemaining: 0,
		},
		{
			name: "Remove non-existent region (no error)",
			setupSecret: func(sm *SecretManager) string {
				createReq := &types.CreateSecretRequest{
					Name:         "remove-nonexist-region",
					SecretString: types.StringPtr("test-value"),
				}
				_, _ = sm.CreateSecret(createReq)

				// Add replication
				replicateReq := &types.ReplicateSecretToRegionsRequest{
					SecretId: "remove-nonexist-region",
					AddReplicaRegions: []types.ReplicaRegionType{
						{Region: types.StringPtr("us-west-2")},
					},
				}
				_, _ = sm.ReplicateSecretToRegions(replicateReq)
				return "remove-nonexist-region"
			},
			secretId: "remove-nonexist-region",
			removeReplicaRegions: []*string{
				types.StringPtr("non-existent-region"),
			},
			expectError:       false,
			expectedRemaining: 1, // Original region remains
		},
		{
			name: "Remove from non-existent secret",
			setupSecret: func(sm *SecretManager) string {
				return "non-existent"
			},
			secretId: "non-existent",
			removeReplicaRegions: []*string{
				types.StringPtr("us-west-2"),
			},
			expectError: true,
			errorType:   "ResourceNotFoundException",
		},
		{
			name: "Remove with empty SecretId",
			setupSecret: func(sm *SecretManager) string {
				return ""
			},
			secretId: "",
			removeReplicaRegions: []*string{
				types.StringPtr("us-west-2"),
			},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewMemoryStorage("")
			sm := NewSecretManager(store)

			if tt.setupSecret != nil {
				tt.setupSecret(sm)
			}

			req := &types.RemoveRegionsFromReplicationRequest{
				SecretId:             tt.secretId,
				RemoveReplicaRegions: tt.removeReplicaRegions,
			}

			resp, err := sm.RemoveRegionsFromReplication(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if resp.ARN == nil {
				t.Error("Response missing ARN")
			}

			if len(resp.ReplicationStatus) != tt.expectedRemaining {
				t.Errorf("Expected %d remaining regions, got %d", tt.expectedRemaining, len(resp.ReplicationStatus))
			}
		})
	}
}

// TestReplicationWorkflow tests complete replication workflow
func TestReplicationWorkflow(t *testing.T) {
	store := storage.NewMemoryStorage("")
	sm := NewSecretManager(store)

	// 1. Create a secret
	createReq := &types.CreateSecretRequest{
		Name:         "replication-workflow-secret",
		SecretString: types.StringPtr("my-secret-value"),
	}
	createResp, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// 2. Replicate to multiple regions
	replicateReq := &types.ReplicateSecretToRegionsRequest{
		SecretId: "replication-workflow-secret",
		AddReplicaRegions: []types.ReplicaRegionType{
			{Region: types.StringPtr("us-west-2")},
			{Region: types.StringPtr("eu-west-1")},
			{Region: types.StringPtr("ap-southeast-1")},
		},
	}
	replicateResp, err := sm.ReplicateSecretToRegions(replicateReq)
	if err != nil {
		t.Fatalf("Failed to replicate secret: %v", err)
	}

	if len(replicateResp.ReplicationStatus) != 3 {
		t.Errorf("Expected 3 replicated regions, got %d", len(replicateResp.ReplicationStatus))
	}

	// 3. Verify replication status in DescribeSecret
	describeReq := &types.DescribeSecretRequest{
		SecretId: "replication-workflow-secret",
	}
	describeResp, err := sm.DescribeSecret(describeReq)
	if err != nil {
		t.Fatalf("Failed to describe secret: %v", err)
	}

	if len(describeResp.ReplicationStatus) != 3 {
		t.Errorf("DescribeSecret shows %d replicas, expected 3", len(describeResp.ReplicationStatus))
	}

	// 4. Remove one region
	removeReq := &types.RemoveRegionsFromReplicationRequest{
		SecretId: "replication-workflow-secret",
		RemoveReplicaRegions: []*string{
			types.StringPtr("eu-west-1"),
		},
	}
	removeResp, err := sm.RemoveRegionsFromReplication(removeReq)
	if err != nil {
		t.Fatalf("Failed to remove region: %v", err)
	}

	if len(removeResp.ReplicationStatus) != 2 {
		t.Errorf("Expected 2 remaining regions after removal, got %d", len(removeResp.ReplicationStatus))
	}

	// 5. Verify region was removed
	describeResp2, err := sm.DescribeSecret(describeReq)
	if err != nil {
		t.Fatalf("Failed to describe secret after removal: %v", err)
	}

	if len(describeResp2.ReplicationStatus) != 2 {
		t.Errorf("DescribeSecret shows %d replicas after removal, expected 2", len(describeResp2.ReplicationStatus))
	}

	// Verify eu-west-1 is not in the list
	for _, replica := range describeResp2.ReplicationStatus {
		if replica.Region != nil && *replica.Region == "eu-west-1" {
			t.Error("eu-west-1 should have been removed but is still present")
		}
	}

	// 6. Add more regions
	replicateReq2 := &types.ReplicateSecretToRegionsRequest{
		SecretId: "replication-workflow-secret",
		AddReplicaRegions: []types.ReplicaRegionType{
			{Region: types.StringPtr("ca-central-1")},
		},
	}
	replicateResp2, err := sm.ReplicateSecretToRegions(replicateReq2)
	if err != nil {
		t.Fatalf("Failed to add new region: %v", err)
	}

	if len(replicateResp2.ReplicationStatus) != 3 {
		t.Errorf("Expected 3 regions after adding new one, got %d", len(replicateResp2.ReplicationStatus))
	}

	// Verify ARN consistency
	if *createResp.ARN != *replicateResp.ARN || *replicateResp.ARN != *removeResp.ARN {
		t.Error("ARN should be consistent across all operations")
	}
}
