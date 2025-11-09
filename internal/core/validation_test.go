//nolint:funlen,gocyclo // Test file
package core

import (
	"strings"
	"testing"

	"github.com/eunmann/secretstash/internal/types"
)

func TestValidateSecretName(t *testing.T) {
	tests := []struct {
		name        string
		secretName  string
		errorType   string
		expectError bool
	}{
		{
			name:        "Valid name with alphanumeric",
			secretName:  "MySecret123",
			expectError: false,
		},
		{
			name:        "Valid name with allowed special chars",
			secretName:  "my/secret_path+=.@-test",
			expectError: false,
		},
		{
			name:        "Empty name",
			secretName:  "",
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name:        "Name too long",
			secretName:  strings.Repeat("a", 513),
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name:        "Name with invalid characters",
			secretName:  "my-secret!@#$",
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name:        "Name ending with -XXXXXX pattern (allowed in local mock)",
			secretName:  "my-secret-ABC123",
			expectError: false, // We relaxed this validation to avoid false positives
		},
		{
			name:        "Name with hyphen but not reserved pattern",
			secretName:  "my-secret-long",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretName(tt.secretName)

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
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSecretValue(t *testing.T) {
	tests := []struct {
		secretString *string
		name         string
		errorType    string
		secretBinary []byte
		expectError  bool
	}{
		{
			name:         "Valid SecretString",
			secretString: types.StringPtr("my-secret-value"),
			expectError:  false,
		},
		{
			name:         "Valid SecretBinary",
			secretBinary: []byte("binary-data"),
			expectError:  false,
		},
		{
			name:        "Neither SecretString nor SecretBinary",
			expectError: true,
			errorType:   "InvalidParameterException",
		},
		{
			name:         "Both SecretString and SecretBinary",
			secretString: types.StringPtr("value"),
			secretBinary: []byte("data"),
			expectError:  true,
			errorType:    "InvalidParameterException",
		},
		{
			name:         "SecretString too long",
			secretString: types.StringPtr(strings.Repeat("a", 65537)),
			expectError:  true,
			errorType:    "InvalidParameterException",
		},
		{
			name:         "SecretBinary too long",
			secretBinary: make([]byte, 65537),
			expectError:  true,
			errorType:    "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretValue(tt.secretString, tt.secretBinary)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateClientRequestToken(t *testing.T) {
	tests := []struct {
		token       *string
		name        string
		expectError bool
	}{
		{
			name:        "Nil token (auto-generated)",
			token:       nil,
			expectError: false,
		},
		{
			name:        "Valid 32-char token",
			token:       types.StringPtr(strings.Repeat("a", 32)),
			expectError: false,
		},
		{
			name:        "Valid 64-char token",
			token:       types.StringPtr(strings.Repeat("a", 64)),
			expectError: false,
		},
		{
			name:        "Token too short",
			token:       types.StringPtr(strings.Repeat("a", 31)),
			expectError: true,
		},
		{
			name:        "Token too long",
			token:       types.StringPtr(strings.Repeat("a", 65)),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientRequestToken(tt.token)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateRotationToken(t *testing.T) {
	tests := []struct {
		token       *string
		name        string
		expectError bool
	}{
		{
			name:        "Nil token",
			token:       nil,
			expectError: false,
		},
		{
			name:        "Valid rotation token",
			token:       types.StringPtr("rotation-token-123456-abcdef-ghijklm"),
			expectError: false,
		},
		{
			name:        "Token with invalid characters",
			token:       types.StringPtr("rotation_token"),
			expectError: true,
		},
		{
			name:        "Token too short",
			token:       types.StringPtr(strings.Repeat("a", 35)),
			expectError: true,
		},
		{
			name:        "Token too long",
			token:       types.StringPtr(strings.Repeat("a", 257)),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRotationToken(tt.token)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateVersionStages(t *testing.T) {
	tests := []struct {
		name        string
		errorType   string
		stages      []*string
		expectError bool
	}{
		{
			name: "Valid stages",
			stages: []*string{
				types.StringPtr("AWSCURRENT"),
				types.StringPtr("CUSTOM1"),
			},
			expectError: false,
		},
		{
			name:        "Too many stages (>20)",
			stages:      make([]*string, 21),
			expectError: true,
			errorType:   "LimitExceededException",
		},
		{
			name: "Stage name too long",
			stages: []*string{
				types.StringPtr(strings.Repeat("a", 257)),
			},
			expectError: true,
			errorType:   "InvalidParameterException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize nil stages for "Too many stages" test
			if tt.name == "Too many stages (>20)" {
				for i := range tt.stages {
					tt.stages[i] = types.StringPtr("STAGE" + string(rune('A'+i)))
				}
			}

			err := ValidateVersionStages(tt.stages)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != tt.errorType {
						t.Errorf("Expected error type %s, got %s", tt.errorType, apiErr.Type)
					}
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePasswordLength(t *testing.T) {
	tests := []struct {
		length      *int64
		name        string
		expectError bool
	}{
		{
			name:        "Nil (use default)",
			length:      nil,
			expectError: false,
		},
		{
			name:        "Valid minimum (4)",
			length:      types.Int64Ptr(4),
			expectError: false,
		},
		{
			name:        "Valid maximum (4096)",
			length:      types.Int64Ptr(4096),
			expectError: false,
		},
		{
			name:        "Too short (3)",
			length:      types.Int64Ptr(3),
			expectError: true,
		},
		{
			name:        "Too long (4097)",
			length:      types.Int64Ptr(4097),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordLength(tt.length)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePasswordRequirements(t *testing.T) {
	tests := []struct {
		excludeNumbers     *bool
		excludePunctuation *bool
		excludeUppercase   *bool
		excludeLowercase   *bool
		name               string
		expectError        bool
	}{
		{
			name:        "All types included (default)",
			expectError: false,
		},
		{
			name:           "Exclude only numbers",
			excludeNumbers: types.BoolPtr(true),
			expectError:    false,
		},
		{
			name:               "Exclude all character types",
			excludeNumbers:     types.BoolPtr(true),
			excludePunctuation: types.BoolPtr(true),
			excludeUppercase:   types.BoolPtr(true),
			excludeLowercase:   types.BoolPtr(true),
			expectError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordRequirements(tt.excludeNumbers, tt.excludePunctuation, tt.excludeUppercase, tt.excludeLowercase)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateRecoveryWindow(t *testing.T) {
	tests := []struct {
		recoveryWindow *int64
		forceDelete    *bool
		name           string
		expectError    bool
	}{
		{
			name:           "Valid recovery window",
			recoveryWindow: types.Int64Ptr(7),
			expectError:    false,
		},
		{
			name:        "Force delete only",
			forceDelete: types.BoolPtr(true),
			expectError: false,
		},
		{
			name:           "Both recovery window and force delete",
			recoveryWindow: types.Int64Ptr(7),
			forceDelete:    types.BoolPtr(true),
			expectError:    true,
		},
		{
			name:           "Recovery window too short",
			recoveryWindow: types.Int64Ptr(6),
			expectError:    true,
		},
		{
			name:           "Recovery window too long",
			recoveryWindow: types.Int64Ptr(31),
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecoveryWindow(tt.recoveryWindow, tt.forceDelete)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCheckVersionQuota(t *testing.T) {
	tests := []struct {
		name         string
		versionCount int
		expectError  bool
	}{
		{
			name:         "No versions",
			versionCount: 0,
			expectError:  false,
		},
		{
			name:         "Under quota (50 versions)",
			versionCount: 50,
			expectError:  false,
		},
		{
			name:         "At quota limit (99 versions)",
			versionCount: 99,
			expectError:  false,
		},
		{
			name:         "At quota (100 versions)",
			versionCount: 100,
			expectError:  true,
		},
		{
			name:         "Over quota (150 versions)",
			versionCount: 150,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckVersionQuota(tt.versionCount)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != "LimitExceededException" {
						t.Errorf("Expected LimitExceededException, got %s", apiErr.Type)
					}
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCheckStagingLabelQuota(t *testing.T) {
	tests := []struct {
		name        string
		labelCount  int
		expectError bool
	}{
		{
			name:        "No labels",
			labelCount:  0,
			expectError: false,
		},
		{
			name:        "Under quota (10 labels)",
			labelCount:  10,
			expectError: false,
		},
		{
			name:        "At quota (20 labels)",
			labelCount:  20,
			expectError: false,
		},
		{
			name:        "Over quota (21 labels)",
			labelCount:  21,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckStagingLabelQuota(tt.labelCount)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if apiErr, ok := err.(*types.APIError); ok {
					if apiErr.Type != "LimitExceededException" {
						t.Errorf("Expected LimitExceededException, got %s", apiErr.Type)
					}
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
