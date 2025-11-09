// Package storage provides data storage implementations for secrets
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/eunmann/secretstash/internal/types"
)

// MemoryStorage provides an in-memory storage implementation
type MemoryStorage struct {
	secrets map[string]*types.Secret
	arnMap  map[string]string
	file    string
	mu      sync.RWMutex
}

// NewMemoryStorage creates a new in-memory storage
func NewMemoryStorage(persistenceFile string) *MemoryStorage {
	return &MemoryStorage{
		secrets: make(map[string]*types.Secret),
		arnMap:  make(map[string]string),
		file:    persistenceFile,
	}
}

// CreateSecret stores a new secret
func (m *MemoryStorage) CreateSecret(secret *types.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.secrets[secret.Name]; exists {
		return fmt.Errorf("secret already exists: %s", secret.Name)
	}

	m.secrets[secret.Name] = secret
	m.arnMap[secret.ARN] = secret.Name
	return nil
}

// GetSecret retrieves a secret by name or ARN
func (m *MemoryStorage) GetSecret(nameOrARN string) (*types.Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Try direct name lookup
	if secret, exists := m.secrets[nameOrARN]; exists {
		return secret, nil
	}

	// Try ARN lookup
	if name, exists := m.arnMap[nameOrARN]; exists {
		return m.secrets[name], nil
	}

	return nil, fmt.Errorf("secret not found: %s", nameOrARN)
}

// UpdateSecret updates an existing secret
func (m *MemoryStorage) UpdateSecret(secret *types.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.secrets[secret.Name]; !exists {
		return fmt.Errorf("secret not found: %s", secret.Name)
	}

	m.secrets[secret.Name] = secret
	return nil
}

// DeleteSecret removes a secret
func (m *MemoryStorage) DeleteSecret(nameOrARN string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the secret name
	name := nameOrARN
	if mappedName, exists := m.arnMap[nameOrARN]; exists {
		name = mappedName
	}

	secret, exists := m.secrets[name]
	if !exists {
		return fmt.Errorf("secret not found: %s", nameOrARN)
	}

	delete(m.secrets, name)
	delete(m.arnMap, secret.ARN)
	return nil
}

// ListSecrets returns all secrets
func (m *MemoryStorage) ListSecrets() ([]*types.Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	secrets := make([]*types.Secret, 0, len(m.secrets))
	for _, secret := range m.secrets {
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

// SecretExists checks if a secret exists
func (m *MemoryStorage) SecretExists(nameOrARN string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.secrets[nameOrARN]; exists {
		return true
	}
	if _, exists := m.arnMap[nameOrARN]; exists {
		return true
	}
	return false
}

// GetVersion retrieves a specific version of a secret
func (m *MemoryStorage) GetVersion(secretName, versionId string) (*types.SecretVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	secret, exists := m.secrets[secretName]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", secretName)
	}

	version, exists := secret.Versions[versionId]
	if !exists {
		return nil, fmt.Errorf("version not found: %s", versionId)
	}

	return version, nil
}

// AddVersion adds a new version to a secret
func (m *MemoryStorage) AddVersion(secretName string, version *types.SecretVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, exists := m.secrets[secretName]
	if !exists {
		return fmt.Errorf("secret not found: %s", secretName)
	}

	if secret.Versions == nil {
		secret.Versions = make(map[string]*types.SecretVersion)
	}

	secret.Versions[version.VersionId] = version
	return nil
}

// Save persists secrets to disk (if persistence file is configured)
func (m *MemoryStorage) Save() error {
	if m.file == "" {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	//nolint:gosec // G306: 0644 is acceptable for this use case
	if err := os.WriteFile(m.file, data, 0644); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}

	return nil
}

// Load reads secrets from disk (if persistence file exists)
func (m *MemoryStorage) Load() error {
	if m.file == "" {
		return nil
	}

	data, err := os.ReadFile(m.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No file to load, start fresh
		}
		return fmt.Errorf("failed to read secrets file: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var secrets map[string]*types.Secret
	if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("failed to unmarshal secrets: %w", err)
	}

	m.secrets = secrets
	m.arnMap = make(map[string]string)

	// Rebuild ARN map
	for name, secret := range m.secrets {
		m.arnMap[secret.ARN] = name

		// Ensure Versions map is initialized
		if secret.Versions == nil {
			secret.Versions = make(map[string]*types.SecretVersion)
		}
	}

	return nil
}

// normalizeSecretIdentifier extracts the secret name from various formats
func normalizeSecretIdentifier(nameOrARN string) string {
	// If it's an ARN, extract the secret name
	// ARN format: arn:aws:secretsmanager:region:account-id:secret:name-randomchars
	if strings.HasPrefix(nameOrARN, "arn:") {
		parts := strings.Split(nameOrARN, ":")
		if len(parts) >= 7 {
			// The secret name is the last part after "secret:"
			return parts[6]
		}
	}
	return nameOrARN
}
