//nolint:funlen,gocyclo // Test file
package core

import (
	"testing"

	"github.com/eunmann/secretstash/internal/storage"
	"github.com/eunmann/secretstash/internal/types"
)

func setupTestManager() *SecretManager {
	store := storage.NewMemoryStorage("")
	return NewSecretManager(store)
}

func TestCreateSecret(t *testing.T) {
	tests := []struct {
		request     *types.CreateSecretRequest
		name        string
		errorType   string
		expectError bool
	}{
		{
			name: "Create secret with string value",
			request: &types.CreateSecretRequest{
				Name:         "test-secret",
				SecretString: types.StringPtr("my-secret-value"),
				Description:  types.StringPtr("Test secret"),
			},
			expectError: false,
		},
		{
			name: "Create secret with binary value",
			request: &types.CreateSecretRequest{
				Name:         "test-binary-secret",
				SecretBinary: []byte("binary-data"),
			},
			expectError: false,
		},
		{
			name: "Create secret without name",
			request: &types.CreateSecretRequest{
				SecretString: types.StringPtr("value"),
			},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name: "Create secret without value",
			request: &types.CreateSecretRequest{
				Name: "no-value-secret",
			},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := setupTestManager()
			resp, err := sm.CreateSecret(tt.request)

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
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if resp.ARN == nil || *resp.ARN == "" {
					t.Error("Expected ARN in response")
				}
				if resp.VersionId == nil || *resp.VersionId == "" {
					t.Error("Expected VersionId in response")
				}
			}
		})
	}
}

func TestCreateSecretDuplicate(t *testing.T) {
	sm := setupTestManager()

	req := &types.CreateSecretRequest{
		Name:         "duplicate-test",
		SecretString: types.StringPtr("value"),
	}

	// First creation should succeed
	_, err := sm.CreateSecret(req)
	if err != nil {
		t.Fatalf("First creation failed: %v", err)
	}

	// Second creation should fail
	_, err = sm.CreateSecret(req)
	if err == nil {
		t.Error("Expected error for duplicate secret")
		return
	}

	apiErr, ok := err.(*types.APIError)
	if !ok {
		t.Errorf("Expected APIError, got %T", err)
		return
	}
	if apiErr.Type != "ResourceExistsException" {
		t.Errorf("Expected ResourceExistsException, got %s", apiErr.Type)
	}
}

func TestGetSecretValue(t *testing.T) {
	sm := setupTestManager()

	// Create a secret first
	secretName := "test-get-secret"
	secretValue := "secret-value"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr(secretValue),
	}

	createResp, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	tests := []struct {
		request     *types.GetSecretValueRequest
		name        string
		expectError bool
		checkValue  bool
	}{
		{
			name: "Get secret by name",
			request: &types.GetSecretValueRequest{
				SecretId: secretName,
			},
			expectError: false,
			checkValue:  true,
		},
		{
			name: "Get secret by ARN",
			request: &types.GetSecretValueRequest{
				SecretId: *createResp.ARN,
			},
			expectError: false,
			checkValue:  true,
		},
		{
			name: "Get secret by version ID",
			request: &types.GetSecretValueRequest{
				SecretId:  secretName,
				VersionId: createResp.VersionId,
			},
			expectError: false,
			checkValue:  true,
		},
		{
			name: "Get non-existent secret",
			request: &types.GetSecretValueRequest{
				SecretId: "non-existent-secret",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := sm.GetSecretValue(tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if tt.checkValue && (resp.SecretString == nil || *resp.SecretString != secretValue) {
					t.Errorf("Expected secret value %s, got %v", secretValue, resp.SecretString)
				}
			}
		})
	}
}

func TestPutSecretValue(t *testing.T) {
	sm := setupTestManager()

	// Create a secret
	secretName := "test-put-secret"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("initial-value"),
	}

	_, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Put a new version
	newValue := "new-value"
	putReq := &types.PutSecretValueRequest{
		SecretId:     secretName,
		SecretString: types.StringPtr(newValue),
	}

	putResp, err := sm.PutSecretValue(putReq)
	if err != nil {
		t.Fatalf("Failed to put secret value: %v", err)
	}

	if putResp.VersionId == nil {
		t.Error("Expected VersionId in response")
	}

	// Get the new value
	getReq := &types.GetSecretValueRequest{
		SecretId: secretName,
	}

	getResp, err := sm.GetSecretValue(getReq)
	if err != nil {
		t.Fatalf("Failed to get secret value: %v", err)
	}

	if getResp.SecretString == nil || *getResp.SecretString != newValue {
		t.Errorf("Expected new value %s, got %v", newValue, getResp.SecretString)
	}

	// Verify AWSCURRENT moved to new version
	if !containsStagePtr(getResp.VersionStages, VersionStageAWSCurrent) {
		t.Error("Expected AWSCURRENT stage on new version")
	}
}

func TestDeleteSecret(t *testing.T) {
	sm := setupTestManager()

	// Create a secret
	secretName := "test-delete-secret"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("value"),
	}

	_, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Delete with recovery window
	deleteReq := &types.DeleteSecretRequest{
		SecretId:             secretName,
		RecoveryWindowInDays: types.Int64Ptr(7),
	}

	deleteResp, err := sm.DeleteSecret(deleteReq)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	if deleteResp.DeletionDate == nil {
		t.Error("Expected DeletionDate in response")
	}

	// Verify secret is marked for deletion
	describeReq := &types.DescribeSecretRequest{
		SecretId: secretName,
	}

	describeResp, err := sm.DescribeSecret(describeReq)
	if err != nil {
		t.Fatalf("Failed to describe secret: %v", err)
	}

	if describeResp.DeletedDate == nil {
		t.Error("Expected DeletedDate on secret")
	}
}

func TestRestoreSecret(t *testing.T) {
	sm := setupTestManager()

	// Create and delete a secret
	secretName := "test-restore-secret"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("value"),
	}

	_, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	deleteReq := &types.DeleteSecretRequest{
		SecretId:             secretName,
		RecoveryWindowInDays: types.Int64Ptr(7),
	}

	_, err = sm.DeleteSecret(deleteReq)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	// Restore the secret
	restoreReq := &types.RestoreSecretRequest{
		SecretId: secretName,
	}

	_, err = sm.RestoreSecret(restoreReq)
	if err != nil {
		t.Fatalf("Failed to restore secret: %v", err)
	}

	// Verify secret is restored
	describeReq := &types.DescribeSecretRequest{
		SecretId: secretName,
	}

	describeResp, err := sm.DescribeSecret(describeReq)
	if err != nil {
		t.Fatalf("Failed to describe secret: %v", err)
	}

	if describeResp.DeletedDate != nil {
		t.Error("Expected DeletedDate to be nil after restore")
	}
}

func TestUpdateSecretVersionStage(t *testing.T) {
	sm := setupTestManager()

	// Create a secret
	secretName := "test-version-stage"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("v1"),
	}

	createResp, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	version1 := *createResp.VersionId

	// Add a second version
	putReq := &types.PutSecretValueRequest{
		SecretId:     secretName,
		SecretString: types.StringPtr("v2"),
	}

	putResp, err := sm.PutSecretValue(putReq)
	if err != nil {
		t.Fatalf("Failed to put secret value: %v", err)
	}

	version2 := *putResp.VersionId

	// Move AWSCURRENT back to version1
	updateReq := &types.UpdateSecretVersionStageRequest{
		SecretId:        secretName,
		VersionStage:    VersionStageAWSCurrent,
		MoveToVersionId: &version1,
	}

	_, err = sm.UpdateSecretVersionStage(updateReq)
	if err != nil {
		t.Fatalf("Failed to update version stage: %v", err)
	}

	// Verify version1 has AWSCURRENT
	getReq := &types.GetSecretValueRequest{
		SecretId:  secretName,
		VersionId: &version1,
	}

	getResp, err := sm.GetSecretValue(getReq)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if !containsStagePtr(getResp.VersionStages, VersionStageAWSCurrent) {
		t.Error("Expected AWSCURRENT on version1")
	}

	// Verify version2 doesn't have AWSCURRENT
	getReq2 := &types.GetSecretValueRequest{
		SecretId:  secretName,
		VersionId: &version2,
	}

	getResp2, err := sm.GetSecretValue(getReq2)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if containsStagePtr(getResp2.VersionStages, VersionStageAWSCurrent) {
		t.Error("Did not expect AWSCURRENT on version2")
	}
}

func TestListSecrets(t *testing.T) {
	sm := setupTestManager()

	// Create multiple secrets
	for i := 1; i <= 3; i++ {
		req := &types.CreateSecretRequest{
			Name:         "list-test-secret-" + string(rune('0'+i)),
			SecretString: types.StringPtr("value"),
		}
		_, err := sm.CreateSecret(req)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}
	}

	// List secrets
	listReq := &types.ListSecretsRequest{}
	listResp, err := sm.ListSecrets(listReq)
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	if len(listResp.SecretList) < 3 {
		t.Errorf("Expected at least 3 secrets, got %d", len(listResp.SecretList))
	}
}

func TestGetRandomPassword(t *testing.T) {
	sm := setupTestManager()

	tests := []struct {
		request     *types.GetRandomPasswordRequest
		name        string
		minLength   int
		expectError bool
	}{
		{
			name:        "Default password",
			request:     &types.GetRandomPasswordRequest{},
			expectError: false,
			minLength:   32,
		},
		{
			name: "Custom length",
			request: &types.GetRandomPasswordRequest{
				PasswordLength: types.Int64Ptr(16),
			},
			expectError: false,
			minLength:   16,
		},
		{
			name: "Exclude uppercase",
			request: &types.GetRandomPasswordRequest{
				PasswordLength:   types.Int64Ptr(20),
				ExcludeUppercase: types.BoolPtr(true),
			},
			expectError: false,
			minLength:   20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := sm.GetRandomPassword(tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if resp.RandomPassword == nil {
					t.Error("Expected RandomPassword in response")
					return
				}
				if len(*resp.RandomPassword) < tt.minLength {
					t.Errorf("Expected password length >= %d, got %d", tt.minLength, len(*resp.RandomPassword))
				}
			}
		})
	}
}

// Helper function to check if version stages contain a specific stage
func containsStagePtr(stages []*string, stage string) bool {
	for _, s := range stages {
		if s != nil && *s == stage {
			return true
		}
	}
	return false
}

func TestUpdateSecret(t *testing.T) {
	sm := setupTestManager()

	// Create a secret first
	secretName := "test-update-secret"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("initial-value"),
		Description:  types.StringPtr("Initial description"),
	}

	_, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	tests := []struct {
		request     *types.UpdateSecretRequest
		name        string
		errorType   string
		expectError bool
		checkNewVer bool
	}{
		{
			name: "Update description only",
			request: &types.UpdateSecretRequest{
				SecretId:    secretName,
				Description: types.StringPtr("Updated description"),
			},
			expectError: false,
			checkNewVer: false,
		},
		{
			name: "Update secret value",
			request: &types.UpdateSecretRequest{
				SecretId:     secretName,
				SecretString: types.StringPtr("updated-value"),
			},
			expectError: false,
			checkNewVer: true,
		},
		{
			name: "Update both description and value",
			request: &types.UpdateSecretRequest{
				SecretId:     secretName,
				SecretString: types.StringPtr("new-value"),
				Description:  types.StringPtr("New description"),
			},
			expectError: false,
			checkNewVer: true,
		},
		{
			name: "Update binary value",
			request: &types.UpdateSecretRequest{
				SecretId:     secretName,
				SecretBinary: []byte("binary-data"),
			},
			expectError: false,
			checkNewVer: true,
		},
		{
			name: "Update with custom client request token",
			request: &types.UpdateSecretRequest{
				SecretId:           secretName,
				SecretString:       types.StringPtr("value-with-token"),
				ClientRequestToken: types.StringPtr("my-custom-token"),
			},
			expectError: false,
			checkNewVer: true,
		},
		{
			name: "Update non-existent secret",
			request: &types.UpdateSecretRequest{
				SecretId:    "non-existent-secret",
				Description: types.StringPtr("desc"),
			},
			expectError: true,
			errorType:   "ResourceNotFoundException",
		},
		{
			name: "Update with empty SecretId",
			request: &types.UpdateSecretRequest{
				SecretId:    "",
				Description: types.StringPtr("desc"),
			},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := sm.UpdateSecret(tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				} else {
					t.Errorf("Expected APIError but got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if resp.ARN == nil || *resp.ARN == "" {
					t.Error("Expected ARN in response")
				}
				if resp.Name == nil || *resp.Name == "" {
					t.Error("Expected Name in response")
				}
				if tt.checkNewVer {
					if resp.VersionId == nil {
						t.Error("Expected VersionId when updating value")
					}
				}
			}
		})
	}
}

func TestUpdateSecretDeleted(t *testing.T) {
	sm := setupTestManager()

	// Create and delete a secret
	secretName := "test-update-deleted"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("value"),
	}

	_, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	deleteReq := &types.DeleteSecretRequest{
		SecretId:             secretName,
		RecoveryWindowInDays: types.Int64Ptr(7),
	}

	_, err = sm.DeleteSecret(deleteReq)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	// Try to update deleted secret
	updateReq := &types.UpdateSecretRequest{
		SecretId:    secretName,
		Description: types.StringPtr("new desc"),
	}

	_, err = sm.UpdateSecret(updateReq)
	if err == nil {
		t.Error("Expected error when updating deleted secret")
		return
	}

	apiErr, ok := err.(*types.APIError)
	if !ok {
		t.Errorf("Expected APIError, got %T", err)
		return
	}
	if apiErr.Type != "InvalidRequestException" {
		t.Errorf("Expected InvalidRequestException, got %s", apiErr.Type)
	}
}

func TestTagResource(t *testing.T) {
	sm := setupTestManager()

	// Create a secret first
	secretName := "test-tag-secret"
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("value"),
	}

	createResp, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	tests := []struct {
		name        string
		secretId    string
		errorType   string
		tags        []types.Tag
		expectError bool
	}{
		{
			name:     "Add tags to secret",
			secretId: secretName,
			tags: []types.Tag{
				{Key: types.StringPtr("Environment"), Value: types.StringPtr("Production")},
				{Key: types.StringPtr("Owner"), Value: types.StringPtr("TeamA")},
			},
			expectError: false,
		},
		{
			name:     "Add tags using ARN",
			secretId: *createResp.ARN,
			tags: []types.Tag{
				{Key: types.StringPtr("Application"), Value: types.StringPtr("MyApp")},
			},
			expectError: false,
		},
		{
			name:     "Add single tag",
			secretId: secretName,
			tags: []types.Tag{
				{Key: types.StringPtr("CostCenter"), Value: types.StringPtr("12345")},
			},
			expectError: false,
		},
		{
			name:        "Tag non-existent secret",
			secretId:    "non-existent-secret",
			tags:        []types.Tag{{Key: types.StringPtr("key"), Value: types.StringPtr("value")}},
			expectError: true,
			errorType:   "ResourceNotFoundException",
		},
		{
			name:        "Empty SecretId",
			secretId:    "",
			tags:        []types.Tag{{Key: types.StringPtr("key"), Value: types.StringPtr("value")}},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.TagResourceRequest{
				SecretId: tt.secretId,
				Tags:     tt.tags,
			}

			resp, err := sm.TagResource(req)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				} else {
					t.Errorf("Expected APIError but got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if resp == nil {
					t.Error("Expected response but got nil")
					return
				}

				// Verify tags were added by describing the secret
				descReq := &types.DescribeSecretRequest{
					SecretId: secretName,
				}
				descResp, err := sm.DescribeSecret(descReq)
				if err != nil {
					t.Fatalf("Failed to describe secret: %v", err)
				}

				// Check that tags were added
				for _, expectedTag := range tt.tags {
					found := false
					for _, actualTag := range descResp.Tags {
						if actualTag.Key != nil && expectedTag.Key != nil &&
							*actualTag.Key == *expectedTag.Key &&
							actualTag.Value != nil && expectedTag.Value != nil &&
							*actualTag.Value == *expectedTag.Value {
							found = true
							break
						}
					}
					if !found && tt.secretId == secretName {
						t.Errorf("Expected tag %s:%s not found", *expectedTag.Key, *expectedTag.Value)
					}
				}
			}
		})
	}
}

func TestUntagResource(t *testing.T) {
	sm := setupTestManager()

	// Create a secret with tags
	secretName := "test-untag-secret" //nolint:gosec // G101: False positive - variable name
	createReq := &types.CreateSecretRequest{
		Name:         secretName,
		SecretString: types.StringPtr("value"),
		Tags: []types.Tag{
			{Key: types.StringPtr("Environment"), Value: types.StringPtr("Production")},
			{Key: types.StringPtr("Owner"), Value: types.StringPtr("TeamA")},
			{Key: types.StringPtr("Application"), Value: types.StringPtr("MyApp")},
		},
	}

	_, err := sm.CreateSecret(createReq)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	tests := []struct {
		name        string
		secretId    string
		errorType   string
		tagKeys     []*string
		expectError bool
	}{
		{
			name:     "Remove single tag",
			secretId: secretName,
			tagKeys: []*string{
				types.StringPtr("Environment"),
			},
			expectError: false,
		},
		{
			name:     "Remove multiple tags",
			secretId: secretName,
			tagKeys: []*string{
				types.StringPtr("Owner"),
				types.StringPtr("Application"),
			},
			expectError: false,
		},
		{
			name:     "Remove non-existent tag (should not error)",
			secretId: secretName,
			tagKeys: []*string{
				types.StringPtr("NonExistentTag"),
			},
			expectError: false,
		},
		{
			name:        "Untag non-existent secret",
			secretId:    "non-existent-secret",
			tagKeys:     []*string{types.StringPtr("key")},
			expectError: true,
			errorType:   "ResourceNotFoundException",
		},
		{
			name:        "Empty SecretId",
			secretId:    "",
			tagKeys:     []*string{types.StringPtr("key")},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.UntagResourceRequest{
				SecretId: tt.secretId,
				TagKeys:  tt.tagKeys,
			}

			resp, err := sm.UntagResource(req)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				} else {
					t.Errorf("Expected APIError but got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if resp == nil {
					t.Error("Expected response but got nil")
				}
			}
		})
	}
}

func TestListSecretsWithFilters(t *testing.T) {
	sm := setupTestManager()

	// Create secrets with different properties
	_, err := sm.CreateSecret(&types.CreateSecretRequest{
		Name:         "prod-db-password",
		SecretString: types.StringPtr("value1"),
		Tags: []types.Tag{
			{Key: types.StringPtr("Environment"), Value: types.StringPtr("Production")},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	_, err = sm.CreateSecret(&types.CreateSecretRequest{
		Name:         "dev-db-password",
		SecretString: types.StringPtr("value2"),
		Tags: []types.Tag{
			{Key: types.StringPtr("Environment"), Value: types.StringPtr("Development")},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Delete one secret
	_, err = sm.CreateSecret(&types.CreateSecretRequest{
		Name:         "deleted-secret",
		SecretString: types.StringPtr("value3"),
	})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	_, err = sm.DeleteSecret(&types.DeleteSecretRequest{
		SecretId:             "deleted-secret",
		RecoveryWindowInDays: types.Int64Ptr(7),
	})
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	tests := []struct {
		request     *types.ListSecretsRequest
		name        string
		minCount    int
		expectError bool
	}{
		{
			name:     "List all secrets",
			request:  &types.ListSecretsRequest{},
			minCount: 2,
		},
		{
			name: "List with max results",
			request: &types.ListSecretsRequest{
				MaxResults: types.Int32Ptr(1),
			},
			minCount: 1,
		},
		{
			name: "List with name filter",
			request: &types.ListSecretsRequest{
				Filters: []types.Filter{
					{
						Key:    types.StringPtr("name"),
						Values: []*string{types.StringPtr("prod-db-password")},
					},
				},
			},
			minCount: 1,
		},
		{
			name: "List with tag filter",
			request: &types.ListSecretsRequest{
				Filters: []types.Filter{
					{
						Key:    types.StringPtr("tag-key"),
						Values: []*string{types.StringPtr("Environment")},
					},
				},
			},
			minCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := sm.ListSecrets(tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if len(resp.SecretList) < tt.minCount {
					t.Errorf("Expected at least %d secrets, got %d", tt.minCount, len(resp.SecretList))
				}
			}
		})
	}
}
