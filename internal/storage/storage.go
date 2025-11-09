package storage

import (
	"github.com/eunmann/secretstash/internal/types"
)

// Storage defines the interface for secret storage backends
type Storage interface {
	// Secret operations
	CreateSecret(secret *types.Secret) error
	GetSecret(nameOrARN string) (*types.Secret, error)
	UpdateSecret(secret *types.Secret) error
	DeleteSecret(nameOrARN string) error
	ListSecrets() ([]*types.Secret, error)
	SecretExists(nameOrARN string) bool

	// Version operations
	GetVersion(secretName, versionId string) (*types.SecretVersion, error)
	AddVersion(secretName string, version *types.SecretVersion) error

	// Persistence (optional, for file-based backends)
	Save() error
	Load() error
}
