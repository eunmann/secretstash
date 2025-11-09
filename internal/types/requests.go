//nolint:revive // AWS SDK compatibility requires specific naming
package types

// Request types for AWS Secrets Manager API actions
// Based on AWS Secrets Manager API Reference (2017-10-17)

// CreateSecretRequest corresponds to CreateSecret API
type CreateSecretRequest struct {
	ClientRequestToken          *string             `json:"ClientRequestToken,omitempty"`
	Description                 *string             `json:"Description,omitempty"`
	KmsKeyId                    *string             `json:"KmsKeyId,omitempty"`
	SecretString                *string             `json:"SecretString,omitempty"`
	ForceOverwriteReplicaSecret *bool               `json:"ForceOverwriteReplicaSecret,omitempty"`
	Name                        string              `json:"Name"`
	SecretBinary                []byte              `json:"SecretBinary,omitempty"`
	Tags                        []Tag               `json:"Tags,omitempty"`
	AddReplicaRegions           []ReplicaRegionType `json:"AddReplicaRegions,omitempty"`
}

// ReplicaRegionType for replication configuration
type ReplicaRegionType struct {
	Region   *string `json:"Region,omitempty"`
	KmsKeyId *string `json:"KmsKeyId,omitempty"`
}

// GetSecretValueRequest corresponds to GetSecretValue API
type GetSecretValueRequest struct {
	VersionId    *string `json:"VersionId,omitempty"`
	VersionStage *string `json:"VersionStage,omitempty"`
	SecretId     string  `json:"SecretId"`
}

// PutSecretValueRequest corresponds to PutSecretValue API
type PutSecretValueRequest struct {
	SecretId           string    `json:"SecretId"`
	ClientRequestToken *string   `json:"ClientRequestToken,omitempty"`
	RotationToken      *string   `json:"RotationToken,omitempty"`
	SecretBinary       []byte    `json:"SecretBinary,omitempty"`
	SecretString       *string   `json:"SecretString,omitempty"`
	VersionStages      []*string `json:"VersionStages,omitempty"`
}

// UpdateSecretRequest corresponds to UpdateSecret API
type UpdateSecretRequest struct {
	ClientRequestToken *string `json:"ClientRequestToken,omitempty"`
	Description        *string `json:"Description,omitempty"`
	KmsKeyId           *string `json:"KmsKeyId,omitempty"`
	SecretString       *string `json:"SecretString,omitempty"`
	SecretId           string  `json:"SecretId"`
	SecretBinary       []byte  `json:"SecretBinary,omitempty"`
}

// DeleteSecretRequest corresponds to DeleteSecret API
type DeleteSecretRequest struct {
	RecoveryWindowInDays       *int64 `json:"RecoveryWindowInDays,omitempty"`
	ForceDeleteWithoutRecovery *bool  `json:"ForceDeleteWithoutRecovery,omitempty"`
	SecretId                   string `json:"SecretId"`
}

// DescribeSecretRequest corresponds to DescribeSecret API
type DescribeSecretRequest struct {
	SecretId string `json:"SecretId"`
}

// ListSecretsRequest corresponds to ListSecrets API
type ListSecretsRequest struct {
	MaxResults             *int32   `json:"MaxResults,omitempty"`
	NextToken              *string  `json:"NextToken,omitempty"`
	SortOrder              *string  `json:"SortOrder,omitempty"`
	IncludePlannedDeletion *bool    `json:"IncludePlannedDeletion,omitempty"`
	Filters                []Filter `json:"Filters,omitempty"`
}

// TagResourceRequest corresponds to TagResource API
type TagResourceRequest struct {
	SecretId string `json:"SecretId"`
	Tags     []Tag  `json:"Tags"`
}

// UntagResourceRequest corresponds to UntagResource API
type UntagResourceRequest struct {
	SecretId string    `json:"SecretId"`
	TagKeys  []*string `json:"TagKeys"`
}

// UpdateSecretVersionStageRequest corresponds to UpdateSecretVersionStage API
type UpdateSecretVersionStageRequest struct {
	RemoveFromVersionId *string `json:"RemoveFromVersionId,omitempty"`
	MoveToVersionId     *string `json:"MoveToVersionId,omitempty"`
	SecretId            string  `json:"SecretId"`
	VersionStage        string  `json:"VersionStage"`
}

// RotateSecretRequest corresponds to RotateSecret API
type RotateSecretRequest struct {
	ClientRequestToken *string            `json:"ClientRequestToken,omitempty"`
	RotationLambdaARN  *string            `json:"RotationLambdaARN,omitempty"`
	RotationRules      *RotationRulesType `json:"RotationRules,omitempty"`
	RotateImmediately  *bool              `json:"RotateImmediately,omitempty"`
	SecretId           string             `json:"SecretId"`
}

// RestoreSecretRequest corresponds to RestoreSecret API
type RestoreSecretRequest struct {
	SecretId string `json:"SecretId"`
}

// GetRandomPasswordRequest corresponds to GetRandomPassword API
type GetRandomPasswordRequest struct {
	PasswordLength          *int64  `json:"PasswordLength,omitempty"`
	ExcludeCharacters       *string `json:"ExcludeCharacters,omitempty"`
	ExcludeNumbers          *bool   `json:"ExcludeNumbers,omitempty"`
	ExcludePunctuation      *bool   `json:"ExcludePunctuation,omitempty"`
	ExcludeUppercase        *bool   `json:"ExcludeUppercase,omitempty"`
	ExcludeLowercase        *bool   `json:"ExcludeLowercase,omitempty"`
	IncludeSpace            *bool   `json:"IncludeSpace,omitempty"`
	RequireEachIncludedType *bool   `json:"RequireEachIncludedType,omitempty"`
}

// BatchGetSecretValueRequest corresponds to BatchGetSecretValue API
type BatchGetSecretValueRequest struct {
	MaxResults   *int32    `json:"MaxResults,omitempty"`
	NextToken    *string   `json:"NextToken,omitempty"`
	SecretIdList []*string `json:"SecretIdList,omitempty"`
	Filters      []Filter  `json:"Filters,omitempty"`
}

// ReplicateSecretToRegionsRequest corresponds to ReplicateSecretToRegions API
type ReplicateSecretToRegionsRequest struct {
	ForceOverwriteReplicaSecret *bool               `json:"ForceOverwriteReplicaSecret,omitempty"`
	SecretId                    string              `json:"SecretId"`
	AddReplicaRegions           []ReplicaRegionType `json:"AddReplicaRegions"`
}

// RemoveRegionsFromReplicationRequest corresponds to RemoveRegionsFromReplication API
type RemoveRegionsFromReplicationRequest struct {
	SecretId             string    `json:"SecretId"`
	RemoveReplicaRegions []*string `json:"RemoveReplicaRegions"`
}

// CancelRotateSecretRequest corresponds to CancelRotateSecret API
type CancelRotateSecretRequest struct {
	SecretId string `json:"SecretId"`
}

// ValidateResourcePolicyRequest corresponds to ValidateResourcePolicy API
type ValidateResourcePolicyRequest struct {
	ResourcePolicy *string `json:"ResourcePolicy,omitempty"`
	SecretId       *string `json:"SecretId,omitempty"`
}

// StopReplicationToReplicaRequest corresponds to StopReplicationToReplica API
type StopReplicationToReplicaRequest struct {
	SecretId string `json:"SecretId"`
}

// ListSecretVersionIdsRequest corresponds to ListSecretVersionIds API
type ListSecretVersionIdsRequest struct {
	MaxResults        *int32  `json:"MaxResults,omitempty"`
	NextToken         *string `json:"NextToken,omitempty"`
	IncludeDeprecated *bool   `json:"IncludeDeprecated,omitempty"`
	SecretId          string  `json:"SecretId"`
}
