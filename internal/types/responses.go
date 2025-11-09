//nolint:revive // AWS SDK compatibility requires specific naming
package types

// Response types for AWS Secrets Manager API actions
// Based on AWS Secrets Manager API Reference (2017-10-17)

// CreateSecretResponse corresponds to CreateSecret API response
type CreateSecretResponse struct {
	ARN               *string                 `json:"ARN,omitempty"`
	Name              *string                 `json:"Name,omitempty"`
	VersionId         *string                 `json:"VersionId,omitempty"`
	ReplicationStatus []ReplicationStatusType `json:"ReplicationStatus,omitempty"`
}

// GetSecretValueResponse corresponds to GetSecretValue API response
type GetSecretValueResponse struct {
	ARN           *string   `json:"ARN,omitempty"`
	Name          *string   `json:"Name,omitempty"`
	VersionId     *string   `json:"VersionId,omitempty"`
	SecretString  *string   `json:"SecretString,omitempty"`
	CreatedDate   *UnixTime `json:"CreatedDate,omitempty"`
	SecretBinary  []byte    `json:"SecretBinary,omitempty"`
	VersionStages []*string `json:"VersionStages,omitempty"`
}

// PutSecretValueResponse corresponds to PutSecretValue API response
type PutSecretValueResponse struct {
	ARN           *string   `json:"ARN,omitempty"`
	Name          *string   `json:"Name,omitempty"`
	VersionId     *string   `json:"VersionId,omitempty"`
	VersionStages []*string `json:"VersionStages,omitempty"`
}

// UpdateSecretResponse corresponds to UpdateSecret API response
type UpdateSecretResponse struct {
	ARN       *string `json:"ARN,omitempty"`
	Name      *string `json:"Name,omitempty"`
	VersionId *string `json:"VersionId,omitempty"`
}

// DeleteSecretResponse corresponds to DeleteSecret API response
type DeleteSecretResponse struct {
	ARN          *string   `json:"ARN,omitempty"`
	Name         *string   `json:"Name,omitempty"`
	DeletionDate *UnixTime `json:"DeletionDate,omitempty"`
}

// DescribeSecretResponse corresponds to DescribeSecret API response
type DescribeSecretResponse struct {
	ARN                *string                 `json:"ARN,omitempty"`
	Name               *string                 `json:"Name,omitempty"`
	Description        *string                 `json:"Description,omitempty"`
	KmsKeyId           *string                 `json:"KmsKeyId,omitempty"`
	RotationEnabled    *bool                   `json:"RotationEnabled,omitempty"`
	RotationLambdaARN  *string                 `json:"RotationLambdaARN,omitempty"`
	RotationRules      *RotationRulesType      `json:"RotationRules,omitempty"`
	LastRotatedDate    *UnixTime               `json:"LastRotatedDate,omitempty"`
	LastChangedDate    *UnixTime               `json:"LastChangedDate,omitempty"`
	LastAccessedDate   *UnixTime               `json:"LastAccessedDate,omitempty"`
	DeletedDate        *UnixTime               `json:"DeletedDate,omitempty"`
	NextRotationDate   *UnixTime               `json:"NextRotationDate,omitempty"`
	Tags               []Tag                   `json:"Tags,omitempty"`
	VersionIdsToStages map[string][]string     `json:"VersionIdsToStages,omitempty"`
	OwningService      *string                 `json:"OwningService,omitempty"`
	CreatedDate        *UnixTime               `json:"CreatedDate,omitempty"`
	PrimaryRegion      *string                 `json:"PrimaryRegion,omitempty"`
	ReplicationStatus  []ReplicationStatusType `json:"ReplicationStatus,omitempty"`
}

// ListSecretsResponse corresponds to ListSecrets API response
type ListSecretsResponse struct {
	NextToken  *string           `json:"NextToken,omitempty"`
	SecretList []SecretListEntry `json:"SecretList,omitempty"`
}

// TagResourceResponse corresponds to TagResource API response
type TagResourceResponse struct {
	// TagResource has an empty response on success
}

// UntagResourceResponse corresponds to UntagResource API response
type UntagResourceResponse struct {
	// UntagResource has an empty response on success
}

// UpdateSecretVersionStageResponse corresponds to UpdateSecretVersionStage API response
type UpdateSecretVersionStageResponse struct {
	ARN  *string `json:"ARN,omitempty"`
	Name *string `json:"Name,omitempty"`
}

// RotateSecretResponse corresponds to RotateSecret API response
type RotateSecretResponse struct {
	ARN       *string `json:"ARN,omitempty"`
	Name      *string `json:"Name,omitempty"`
	VersionId *string `json:"VersionId,omitempty"`
}

// RestoreSecretResponse corresponds to RestoreSecret API response
type RestoreSecretResponse struct {
	ARN  *string `json:"ARN,omitempty"`
	Name *string `json:"Name,omitempty"`
}

// GetRandomPasswordResponse corresponds to GetRandomPassword API response
type GetRandomPasswordResponse struct {
	RandomPassword *string `json:"RandomPassword,omitempty"`
}

// BatchGetSecretValueResponse corresponds to BatchGetSecretValue API response
type BatchGetSecretValueResponse struct {
	SecretValues []SecretValueEntry `json:"SecretValues,omitempty"`
	NextToken    *string            `json:"NextToken,omitempty"`
	Errors       []APIError         `json:"Errors,omitempty"`
}

// ReplicateSecretToRegionsResponse corresponds to ReplicateSecretToRegions API response
type ReplicateSecretToRegionsResponse struct {
	ARN               *string                 `json:"ARN,omitempty"`
	ReplicationStatus []ReplicationStatusType `json:"ReplicationStatus,omitempty"`
}

// RemoveRegionsFromReplicationResponse corresponds to RemoveRegionsFromReplication API response
type RemoveRegionsFromReplicationResponse struct {
	ARN               *string                 `json:"ARN,omitempty"`
	ReplicationStatus []ReplicationStatusType `json:"ReplicationStatus,omitempty"`
}

// CancelRotateSecretResponse corresponds to CancelRotateSecret API response
type CancelRotateSecretResponse struct {
	ARN       *string `json:"ARN,omitempty"`
	Name      *string `json:"Name,omitempty"`
	VersionId *string `json:"VersionId,omitempty"`
}

// ValidationErrorsEntry for ValidateResourcePolicy
type ValidationErrorsEntry struct {
	CheckName    *string `json:"CheckName,omitempty"`
	ErrorMessage *string `json:"ErrorMessage,omitempty"`
}

// ValidateResourcePolicyResponse corresponds to ValidateResourcePolicy API response
type ValidateResourcePolicyResponse struct {
	PolicyValidationPassed *bool                   `json:"PolicyValidationPassed,omitempty"`
	ValidationErrors       []ValidationErrorsEntry `json:"ValidationErrors,omitempty"`
}

// StopReplicationToReplicaResponse corresponds to StopReplicationToReplica API response
type StopReplicationToReplicaResponse struct {
	ARN *string `json:"ARN,omitempty"`
}

// ListSecretVersionIdsResponse corresponds to ListSecretVersionIds API response
type ListSecretVersionIdsResponse struct {
	NextToken *string                   `json:"NextToken,omitempty"`
	ARN       *string                   `json:"ARN,omitempty"`
	Name      *string                   `json:"Name,omitempty"`
	Versions  []SecretVersionsListEntry `json:"Versions,omitempty"`
}
