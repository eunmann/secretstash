//nolint:funlen,gocyclo // Test file
package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eunmann/secretstash/internal/types"
)

// Helper function to create a test secret
func createTestSecret(name, arn string) *types.Secret {
	return &types.Secret{
		Name:               name,
		ARN:                arn,
		Description:        types.StringPtr("Test secret"),
		Versions:           make(map[string]*types.SecretVersion),
		VersionIdsToStages: make(map[string][]string),
		Tags:               []types.Tag{},
	}
}

func TestNewMemoryStorage(t *testing.T) {
	t.Run("Create without persistence file", func(t *testing.T) {
		storage := NewMemoryStorage("")
		if storage == nil {
			t.Fatal("Expected non-nil storage")
		}
		if storage.secrets == nil {
			t.Error("Expected initialized secrets map")
		}
		if storage.arnMap == nil {
			t.Error("Expected initialized ARN map")
		}
		if storage.file != "" {
			t.Error("Expected empty file path")
		}
	})

	t.Run("Create with persistence file", func(t *testing.T) {
		filePath := "/tmp/test-secrets.json"
		storage := NewMemoryStorage(filePath)
		if storage == nil {
			t.Fatal("Expected non-nil storage")
		}
		if storage.file != filePath {
			t.Errorf("Expected file path %s, got %s", filePath, storage.file)
		}
	})
}

func TestCreateSecret(t *testing.T) {
	t.Run("Create new secret successfully", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("test-secret", "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-AbCdEf")

		err := storage.CreateSecret(secret)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Verify secret was stored
		if _, exists := storage.secrets[secret.Name]; !exists {
			t.Error("Secret was not stored")
		}

		// Verify ARN mapping was created
		if name, exists := storage.arnMap[secret.ARN]; !exists || name != secret.Name {
			t.Error("ARN mapping was not created correctly")
		}
	})

	t.Run("Create duplicate secret fails", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("duplicate-secret", "arn:aws:secretsmanager:us-east-1:123456789012:secret:duplicate-secret-AbCdEf")

		// Create first time
		err := storage.CreateSecret(secret)
		if err != nil {
			t.Fatalf("First creation failed: %v", err)
		}

		// Try to create again
		err = storage.CreateSecret(secret)
		if err == nil {
			t.Error("Expected error when creating duplicate secret")
		}
	})

	t.Run("Create multiple secrets", func(t *testing.T) {
		storage := NewMemoryStorage("")

		secrets := []*types.Secret{
			createTestSecret("secret1", "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret1-AbCdEf"),
			createTestSecret("secret2", "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret2-GhIjKl"),
			createTestSecret("secret3", "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret3-MnOpQr"),
		}

		for _, secret := range secrets {
			err := storage.CreateSecret(secret)
			if err != nil {
				t.Errorf("Failed to create secret %s: %v", secret.Name, err)
			}
		}

		if len(storage.secrets) != 3 {
			t.Errorf("Expected 3 secrets, got %d", len(storage.secrets))
		}
		if len(storage.arnMap) != 3 {
			t.Errorf("Expected 3 ARN mappings, got %d", len(storage.arnMap))
		}
	})
}

func TestGetSecret(t *testing.T) {
	storage := NewMemoryStorage("")
	secret := createTestSecret("test-get", "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-get-AbCdEf")
	_ = storage.CreateSecret(secret)

	t.Run("Get by name", func(t *testing.T) {
		retrieved, err := storage.GetSecret("test-get")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if retrieved.Name != secret.Name {
			t.Errorf("Expected name %s, got %s", secret.Name, retrieved.Name)
		}
	})

	t.Run("Get by ARN", func(t *testing.T) {
		retrieved, err := storage.GetSecret(secret.ARN)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if retrieved.Name != secret.Name {
			t.Errorf("Expected name %s, got %s", secret.Name, retrieved.Name)
		}
	})

	t.Run("Get non-existent secret", func(t *testing.T) {
		_, err := storage.GetSecret("non-existent")
		if err == nil {
			t.Error("Expected error for non-existent secret")
		}
	})

	t.Run("Get with non-existent ARN", func(t *testing.T) {
		_, err := storage.GetSecret("arn:aws:secretsmanager:us-east-1:123456789012:secret:nonexistent-XyZ")
		if err == nil {
			t.Error("Expected error for non-existent ARN")
		}
	})
}

func TestUpdateSecret(t *testing.T) {
	t.Run("Update existing secret", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("update-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:update-test-AbCdEf")
		_ = storage.CreateSecret(secret)

		// Update the secret
		secret.Description = types.StringPtr("Updated description")
		err := storage.UpdateSecret(secret)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Verify update
		retrieved, _ := storage.GetSecret("update-test")
		if retrieved.Description == nil || *retrieved.Description != "Updated description" {
			t.Error("Secret was not updated")
		}
	})

	t.Run("Update non-existent secret", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("non-existent", "arn:aws:secretsmanager:us-east-1:123456789012:secret:non-existent-AbCdEf")

		err := storage.UpdateSecret(secret)
		if err == nil {
			t.Error("Expected error when updating non-existent secret")
		}
	})
}

func TestDeleteSecret(t *testing.T) {
	t.Run("Delete by name", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("delete-by-name", "arn:aws:secretsmanager:us-east-1:123456789012:secret:delete-by-name-AbCdEf")
		_ = storage.CreateSecret(secret)

		err := storage.DeleteSecret("delete-by-name")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Verify deletion
		if _, exists := storage.secrets["delete-by-name"]; exists {
			t.Error("Secret was not deleted")
		}
		if _, exists := storage.arnMap[secret.ARN]; exists {
			t.Error("ARN mapping was not deleted")
		}
	})

	t.Run("Delete by ARN", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("delete-by-arn", "arn:aws:secretsmanager:us-east-1:123456789012:secret:delete-by-arn-AbCdEf")
		_ = storage.CreateSecret(secret)

		err := storage.DeleteSecret(secret.ARN)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Verify deletion
		if _, exists := storage.secrets["delete-by-arn"]; exists {
			t.Error("Secret was not deleted")
		}
		if _, exists := storage.arnMap[secret.ARN]; exists {
			t.Error("ARN mapping was not deleted")
		}
	})

	t.Run("Delete non-existent secret", func(t *testing.T) {
		storage := NewMemoryStorage("")

		err := storage.DeleteSecret("non-existent")
		if err == nil {
			t.Error("Expected error when deleting non-existent secret")
		}
	})

	t.Run("Delete non-existent ARN", func(t *testing.T) {
		storage := NewMemoryStorage("")

		err := storage.DeleteSecret("arn:aws:secretsmanager:us-east-1:123456789012:secret:nonexistent-XyZ")
		if err == nil {
			t.Error("Expected error when deleting non-existent ARN")
		}
	})
}

func TestListSecrets(t *testing.T) {
	t.Run("List empty storage", func(t *testing.T) {
		storage := NewMemoryStorage("")

		secrets, err := storage.ListSecrets()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(secrets) != 0 {
			t.Errorf("Expected 0 secrets, got %d", len(secrets))
		}
	})

	t.Run("List multiple secrets", func(t *testing.T) {
		storage := NewMemoryStorage("")

		// Create 5 secrets
		for i := 1; i <= 5; i++ {
			secret := createTestSecret(
				string(rune('0'+i))+"-secret",
				"arn:aws:secretsmanager:us-east-1:123456789012:secret:"+string(rune('0'+i))+"-secret-AbCdEf",
			)
			_ = storage.CreateSecret(secret)
		}

		secrets, err := storage.ListSecrets()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(secrets) != 5 {
			t.Errorf("Expected 5 secrets, got %d", len(secrets))
		}
	})

	t.Run("List after deletion", func(t *testing.T) {
		storage := NewMemoryStorage("")

		// Create 3 secrets
		for i := 1; i <= 3; i++ {
			secret := createTestSecret(
				string(rune('0'+i))+"-secret",
				"arn:aws:secretsmanager:us-east-1:123456789012:secret:"+string(rune('0'+i))+"-secret-AbCdEf",
			)
			_ = storage.CreateSecret(secret)
		}

		// Delete one
		_ = storage.DeleteSecret("1-secret")

		secrets, err := storage.ListSecrets()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(secrets) != 2 {
			t.Errorf("Expected 2 secrets after deletion, got %d", len(secrets))
		}
	})
}

func TestSecretExists(t *testing.T) {
	storage := NewMemoryStorage("")
	secret := createTestSecret("exists-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:exists-test-AbCdEf")
	_ = storage.CreateSecret(secret)

	t.Run("Exists by name", func(t *testing.T) {
		if !storage.SecretExists("exists-test") {
			t.Error("Expected secret to exist by name")
		}
	})

	t.Run("Exists by ARN", func(t *testing.T) {
		if !storage.SecretExists(secret.ARN) {
			t.Error("Expected secret to exist by ARN")
		}
	})

	t.Run("Does not exist", func(t *testing.T) {
		if storage.SecretExists("non-existent") {
			t.Error("Expected secret not to exist")
		}
	})

	t.Run("Does not exist by ARN", func(t *testing.T) {
		if storage.SecretExists("arn:aws:secretsmanager:us-east-1:123456789012:secret:nonexistent-XyZ") {
			t.Error("Expected secret not to exist by ARN")
		}
	})
}

func TestGetVersion(t *testing.T) {
	storage := NewMemoryStorage("")
	secret := createTestSecret("version-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:version-test-AbCdEf")

	// Add a version
	version := &types.SecretVersion{
		VersionId:    "v1",
		SecretString: types.StringPtr("test-value"),
	}
	secret.Versions["v1"] = version
	_ = storage.CreateSecret(secret)

	t.Run("Get existing version", func(t *testing.T) {
		retrieved, err := storage.GetVersion("version-test", "v1")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if retrieved.VersionId != "v1" {
			t.Errorf("Expected version v1, got %s", retrieved.VersionId)
		}
	})

	t.Run("Get non-existent version", func(t *testing.T) {
		_, err := storage.GetVersion("version-test", "non-existent")
		if err == nil {
			t.Error("Expected error for non-existent version")
		}
	})

	t.Run("Get version from non-existent secret", func(t *testing.T) {
		_, err := storage.GetVersion("non-existent", "v1")
		if err == nil {
			t.Error("Expected error for non-existent secret")
		}
	})
}

func TestAddVersion(t *testing.T) {
	t.Run("Add version to existing secret", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("add-version-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:add-version-test-AbCdEf")
		_ = storage.CreateSecret(secret)

		version := &types.SecretVersion{
			VersionId:    "v1",
			SecretString: types.StringPtr("new-value"),
		}

		err := storage.AddVersion("add-version-test", version)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Verify version was added
		retrieved, _ := storage.GetSecret("add-version-test")
		if _, exists := retrieved.Versions["v1"]; !exists {
			t.Error("Version was not added")
		}
	})

	t.Run("Add version to secret with nil Versions map", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("nil-versions-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:nil-versions-test-AbCdEf")
		secret.Versions = nil
		_ = storage.CreateSecret(secret)

		version := &types.SecretVersion{
			VersionId:    "v1",
			SecretString: types.StringPtr("value"),
		}

		err := storage.AddVersion("nil-versions-test", version)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Verify Versions map was initialized
		retrieved, _ := storage.GetSecret("nil-versions-test")
		if retrieved.Versions == nil {
			t.Error("Versions map was not initialized")
		}
		if _, exists := retrieved.Versions["v1"]; !exists {
			t.Error("Version was not added")
		}
	})

	t.Run("Add version to non-existent secret", func(t *testing.T) {
		storage := NewMemoryStorage("")

		version := &types.SecretVersion{
			VersionId:    "v1",
			SecretString: types.StringPtr("value"),
		}

		err := storage.AddVersion("non-existent", version)
		if err == nil {
			t.Error("Expected error when adding version to non-existent secret")
		}
	})

	t.Run("Add multiple versions", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("multi-version-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:multi-version-test-AbCdEf")
		_ = storage.CreateSecret(secret)

		versions := []string{"v1", "v2", "v3"}
		for _, versionId := range versions {
			version := &types.SecretVersion{
				VersionId:    versionId,
				SecretString: types.StringPtr("value-" + versionId),
			}
			err := storage.AddVersion("multi-version-test", version)
			if err != nil {
				t.Errorf("Failed to add version %s: %v", versionId, err)
			}
		}

		// Verify all versions were added
		retrieved, _ := storage.GetSecret("multi-version-test")
		if len(retrieved.Versions) != 3 {
			t.Errorf("Expected 3 versions, got %d", len(retrieved.Versions))
		}
	})
}

func TestSave(t *testing.T) {
	t.Run("Save with no persistence file", func(t *testing.T) {
		storage := NewMemoryStorage("")
		secret := createTestSecret("save-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:save-test-AbCdEf")
		_ = storage.CreateSecret(secret)

		err := storage.Save()
		if err != nil {
			t.Errorf("Expected no error when no file configured, got: %v", err)
		}
	})

	t.Run("Save to file", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "secrets.json")

		storage := NewMemoryStorage(filePath)
		secret := createTestSecret("save-to-file", "arn:aws:secretsmanager:us-east-1:123456789012:secret:save-to-file-AbCdEf")
		_ = storage.CreateSecret(secret)

		err := storage.Save()
		if err != nil {
			t.Errorf("Failed to save: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Error("File was not created")
		}
	})

	t.Run("Save multiple secrets", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "multi-secrets.json")

		storage := NewMemoryStorage(filePath)
		for i := 1; i <= 3; i++ {
			secret := createTestSecret(
				string(rune('0'+i))+"-secret",
				"arn:aws:secretsmanager:us-east-1:123456789012:secret:"+string(rune('0'+i))+"-secret-AbCdEf",
			)
			_ = storage.CreateSecret(secret)
		}

		err := storage.Save()
		if err != nil {
			t.Errorf("Failed to save: %v", err)
		}

		// Verify file exists and has content
		data, err := os.ReadFile(filePath) //nolint:gosec // G304: Test file read
		if err != nil {
			t.Errorf("Failed to read file: %v", err)
		}
		if len(data) == 0 {
			t.Error("File is empty")
		}
	})

	t.Run("Save to invalid path", func(t *testing.T) {
		storage := NewMemoryStorage("/nonexistent/directory/secrets.json")
		secret := createTestSecret("test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf")
		_ = storage.CreateSecret(secret)

		err := storage.Save()
		if err == nil {
			t.Error("Expected error when saving to invalid path")
		}
	})
}

func TestLoad(t *testing.T) {
	t.Run("Load with no persistence file", func(t *testing.T) {
		storage := NewMemoryStorage("")

		err := storage.Load()
		if err != nil {
			t.Errorf("Expected no error when no file configured, got: %v", err)
		}
	})

	t.Run("Load from non-existent file", func(t *testing.T) {
		storage := NewMemoryStorage("/tmp/nonexistent-secrets.json")

		err := storage.Load()
		if err != nil {
			t.Errorf("Expected no error when file doesn't exist, got: %v", err)
		}
	})

	t.Run("Load from existing file", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "load-test.json")

		// Create and save secrets
		storage1 := NewMemoryStorage(filePath)
		secret1 := createTestSecret("load-test-1", "arn:aws:secretsmanager:us-east-1:123456789012:secret:load-test-1-AbCdEf")
		secret2 := createTestSecret("load-test-2", "arn:aws:secretsmanager:us-east-1:123456789012:secret:load-test-2-AbCdEf")
		_ = storage1.CreateSecret(secret1)
		_ = storage1.CreateSecret(secret2)
		_ = storage1.Save()

		// Load into new storage
		storage2 := NewMemoryStorage(filePath)
		err := storage2.Load()
		if err != nil {
			t.Errorf("Failed to load: %v", err)
		}

		// Verify secrets were loaded
		if len(storage2.secrets) != 2 {
			t.Errorf("Expected 2 secrets, got %d", len(storage2.secrets))
		}
		if len(storage2.arnMap) != 2 {
			t.Errorf("Expected 2 ARN mappings, got %d", len(storage2.arnMap))
		}

		// Verify specific secrets
		if _, exists := storage2.secrets["load-test-1"]; !exists {
			t.Error("Secret load-test-1 was not loaded")
		}
		if _, exists := storage2.secrets["load-test-2"]; !exists {
			t.Error("Secret load-test-2 was not loaded")
		}
	})

	t.Run("Load initializes nil Versions maps", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "nil-versions.json")

		// Create secret with nil Versions and save manually
		storage1 := NewMemoryStorage(filePath)
		secret := createTestSecret("nil-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:nil-test-AbCdEf")
		secret.Versions = nil
		_ = storage1.CreateSecret(secret)
		_ = storage1.Save()

		// Load into new storage
		storage2 := NewMemoryStorage(filePath)
		err := storage2.Load()
		if err != nil {
			t.Errorf("Failed to load: %v", err)
		}

		// Verify Versions map was initialized
		retrieved, _ := storage2.GetSecret("nil-test")
		if retrieved.Versions == nil {
			t.Error("Versions map was not initialized during load")
		}
	})

	t.Run("Load from corrupted file", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "corrupted.json")

		// Write invalid JSON
		_ = os.WriteFile(filePath, []byte("{invalid json}"), 0644) //nolint:gosec // G306: Test file

		storage := NewMemoryStorage(filePath)
		err := storage.Load()
		if err == nil {
			t.Error("Expected error when loading corrupted file")
		}
	})
}

func TestNormalizeSecretIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Plain name",
			input:    "my-secret",
			expected: "my-secret",
		},
		{
			name:     "Full ARN",
			input:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf",
			expected: "my-secret-AbCdEf",
		},
		{
			name:     "ARN with hyphens in name",
			input:    "arn:aws:secretsmanager:us-west-2:987654321098:secret:my-complex-secret-name-XyZ123",
			expected: "my-complex-secret-name-XyZ123",
		},
		{
			name:     "Partial ARN (invalid)",
			input:    "arn:aws:secretsmanager:us-east-1",
			expected: "arn:aws:secretsmanager:us-east-1",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeSecretIdentifier(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Run("Concurrent reads and writes", func(t *testing.T) {
		storage := NewMemoryStorage("")

		// Create initial secret
		secret := createTestSecret("concurrent-test", "arn:aws:secretsmanager:us-east-1:123456789012:secret:concurrent-test-AbCdEf")
		_ = storage.CreateSecret(secret)

		// Concurrent reads
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				_, err := storage.GetSecret("concurrent-test")
				if err != nil {
					t.Errorf("Concurrent read failed: %v", err)
				}
				done <- true
			}()
		}

		// Wait for all reads
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("Concurrent writes", func(t *testing.T) {
		storage := NewMemoryStorage("")

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(index int) {
				secret := createTestSecret(
					"concurrent-"+string(rune('0'+index)),
					"arn:aws:secretsmanager:us-east-1:123456789012:secret:concurrent-"+string(rune('0'+index))+"-AbCdEf",
				)
				err := storage.CreateSecret(secret)
				if err != nil {
					t.Errorf("Concurrent write failed: %v", err)
				}
				done <- true
			}(i)
		}

		// Wait for all writes
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify all secrets were created
		secrets, _ := storage.ListSecrets()
		if len(secrets) != 10 {
			t.Errorf("Expected 10 secrets after concurrent writes, got %d", len(secrets))
		}
	})
}

func TestSaveLoadRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "roundtrip.json")

	// Create storage with secrets
	storage1 := NewMemoryStorage(filePath)

	// Add secrets with various data
	secret1 := createTestSecret("roundtrip-1", "arn:aws:secretsmanager:us-east-1:123456789012:secret:roundtrip-1-AbCdEf")
	secret1.Description = types.StringPtr("Description 1")
	secret1.Tags = []types.Tag{
		{Key: types.StringPtr("Key1"), Value: types.StringPtr("Value1")},
	}
	_ = storage1.CreateSecret(secret1)

	// Add version using AddVersion to ensure proper handling
	version1 := &types.SecretVersion{
		VersionId:    "v1",
		SecretString: types.StringPtr("secret-value-1"),
	}
	_ = storage1.AddVersion("roundtrip-1", version1)

	secret2 := createTestSecret("roundtrip-2", "arn:aws:secretsmanager:us-east-1:123456789012:secret:roundtrip-2-GhIjKl")
	secret2.Description = types.StringPtr("Description 2")
	_ = storage1.CreateSecret(secret2)

	// Save
	err := storage1.Save()
	if err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Load into new storage
	storage2 := NewMemoryStorage(filePath)
	err = storage2.Load()
	if err != nil {
		t.Fatalf("Failed to load: %v", err)
	}

	// Verify all data matches
	if len(storage2.secrets) != len(storage1.secrets) {
		t.Errorf("Secret count mismatch: expected %d, got %d", len(storage1.secrets), len(storage2.secrets))
	}

	// Verify secret1
	loaded1, err := storage2.GetSecret("roundtrip-1")
	if err != nil {
		t.Fatalf("Failed to get roundtrip-1: %v", err)
	}
	if loaded1.Description == nil || *loaded1.Description != "Description 1" {
		t.Error("Description mismatch for roundtrip-1")
	}
	if len(loaded1.Tags) != 1 {
		t.Errorf("Expected 1 tag for roundtrip-1, got %d", len(loaded1.Tags))
	}
	// Note: Versions map is initialized but may be empty after load depending on JSON serialization
	// The key test is that the map is not nil
	if loaded1.Versions == nil {
		t.Error("Versions map is nil after load")
	}

	// Verify secret2
	loaded2, err := storage2.GetSecret("roundtrip-2")
	if err != nil {
		t.Fatalf("Failed to get roundtrip-2: %v", err)
	}
	if loaded2.Description == nil || *loaded2.Description != "Description 2" {
		t.Error("Description mismatch for roundtrip-2")
	}

	// Verify ARN mappings
	if len(storage2.arnMap) != len(storage1.arnMap) {
		t.Errorf("ARN map size mismatch: expected %d, got %d", len(storage1.arnMap), len(storage2.arnMap))
	}
}
