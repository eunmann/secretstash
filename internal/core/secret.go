package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/eunmann/secretstash/internal/storage"
	"github.com/eunmann/secretstash/internal/types"
)

const (
	// Version stages as defined by AWS Secrets Manager
	VersionStageAWSCurrent  = "AWSCURRENT"
	VersionStageAWSPending  = "AWSPENDING"
	VersionStageAWSPrevious = "AWSPREVIOUS"

	// Default region for ARN generation
	DefaultRegion    = "us-east-1"
	DefaultAccountID = "000000000000"
)

// SecretManager handles core business logic for secrets
type SecretManager struct {
	storage storage.Storage
}

// NewSecretManager creates a new secret manager
func NewSecretManager(storage storage.Storage) *SecretManager {
	return &SecretManager{
		storage: storage,
	}
}

// CreateSecret creates a new secret
// Implements CreateSecret API - see AWS API Reference § CreateSecret
//
//nolint:funlen // Complex AWS API implementation
func (sm *SecretManager) CreateSecret(req *types.CreateSecretRequest) (*types.CreateSecretResponse, error) {
	// Validate name
	if req.Name == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "Secret name is required",
		}
	}

	if err := ValidateSecretName(req.Name); err != nil {
		return nil, err
	}

	// Validate description
	if err := ValidateDescription(req.Description); err != nil {
		return nil, err
	}

	// Validate KmsKeyId
	if err := ValidateKmsKeyId(req.KmsKeyId); err != nil {
		return nil, err
	}

	// Validate secret value
	if err := ValidateSecretValue(req.SecretString, req.SecretBinary); err != nil {
		return nil, err
	}

	// Validate ClientRequestToken
	if err := ValidateClientRequestToken(req.ClientRequestToken); err != nil {
		return nil, err
	}

	// Validate tags
	if err := ValidateTags(req.Tags); err != nil {
		return nil, err
	}

	// Check if secret already exists
	if existingSecret, err := sm.storage.GetSecret(req.Name); err == nil {
		// Secret exists - check for idempotency
		if req.ClientRequestToken != nil {
			// Find version with matching ClientRequestToken
			for _, version := range existingSecret.Versions {
				if version.VersionId == *req.ClientRequestToken {
					// Check if secret values match (idempotent case)
					if secretValuesMatch(version, req.SecretString, req.SecretBinary) {
						// Idempotent request - return existing version
						return &types.CreateSecretResponse{
							ARN:               &existingSecret.ARN,
							Name:              &existingSecret.Name,
							VersionId:         &version.VersionId,
							ReplicationStatus: existingSecret.ReplicationStatus,
						}, nil
					}
					// Token matches but values differ - error
					return nil, &types.APIError{
						Type:    "ResourceExistsException",
						Message: "A version with the specified ClientRequestToken already exists but with different secret data",
					}
				}
			}
		}

		// Secret exists but no matching token
		return nil, &types.APIError{
			Type:    "ResourceExistsException",
			Message: fmt.Sprintf("The operation failed because the secret %s already exists.", req.Name),
		}
	}

	// Generate ARN
	arn := generateARN(req.Name)

	now := types.NewUnixTime(time.Now())

	// Generate or use provided client request token as version ID
	versionId := generateVersionID(req.ClientRequestToken)

	// Create the secret
	secret := &types.Secret{
		ARN:                arn,
		Name:               req.Name,
		Description:        req.Description,
		KmsKeyId:           req.KmsKeyId,
		RotationEnabled:    false,
		Tags:               req.Tags,
		VersionIdsToStages: make(map[string][]string),
		CreatedDate:        now,
		LastChangedDate:    now,
		Versions:           make(map[string]*types.SecretVersion),
	}

	// Create initial version
	version := &types.SecretVersion{
		VersionId:     versionId,
		SecretString:  req.SecretString,
		SecretBinary:  req.SecretBinary,
		VersionStages: []string{VersionStageAWSCurrent},
		CreatedDate:   *now,
	}

	secret.Versions[versionId] = version
	secret.VersionIdsToStages[versionId] = []string{VersionStageAWSCurrent}

	// Handle replication (stub for local mock)
	var replicationStatus []types.ReplicationStatusType
	if len(req.AddReplicaRegions) > 0 {
		replicationStatus = make([]types.ReplicationStatusType, len(req.AddReplicaRegions))
		for i, region := range req.AddReplicaRegions {
			status := "InSync"
			replicationStatus[i] = types.ReplicationStatusType{
				Region:   region.Region,
				KmsKeyId: region.KmsKeyId,
				Status:   &status,
			}
		}
		secret.ReplicationStatus = replicationStatus
	}

	// Store the secret
	if err := sm.storage.CreateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to create secret: %v", err),
		}
	}

	return &types.CreateSecretResponse{
		ARN:               &arn,
		Name:              &req.Name,
		VersionId:         &versionId,
		ReplicationStatus: replicationStatus,
	}, nil
}

// GetSecretValue retrieves the value of a secret
// Implements GetSecretValue API - see AWS API Reference § GetSecretValue
//
//nolint:funlen // Complex version resolution logic
func (sm *SecretManager) GetSecretValue(req *types.GetSecretValueRequest) (*types.GetSecretValueResponse, error) {
	// Validate input
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	// Get the secret
	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	// Check if secret is deleted
	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	// Determine which version to retrieve
	var version *types.SecretVersion
	if req.VersionId != nil {
		// Specific version requested
		version = secret.Versions[*req.VersionId]
		if version == nil {
			return nil, &types.APIError{
				Type:    "ResourceNotFoundException",
				Message: fmt.Sprintf("Secrets Manager can't find the specified secret version: %s", *req.VersionId),
			}
		}
	} else {
		// Get version by stage (default: AWSCURRENT)
		versionStage := VersionStageAWSCurrent
		if req.VersionStage != nil {
			versionStage = *req.VersionStage
		}

		// Find version with the specified stage
		for versionId, stages := range secret.VersionIdsToStages {
			for _, stage := range stages {
				if stage == versionStage {
					version = secret.Versions[versionId]
					break
				}
			}
			if version != nil {
				break
			}
		}

		if version == nil {
			return nil, &types.APIError{
				Type:    "ResourceNotFoundException",
				Message: fmt.Sprintf("Secrets Manager can't find the specified secret version with stage: %s", versionStage),
			}
		}
	}

	// Update last accessed date
	now := types.NewUnixTime(time.Now())
	secret.LastAccessedDate = now
	version.LastAccessedDate = now
	_ = sm.storage.UpdateSecret(secret) // Best effort update

	// Convert version stages to response format
	versionStagesPtr := make([]*string, len(version.VersionStages))
	for i, stage := range version.VersionStages {
		s := stage
		versionStagesPtr[i] = &s
	}

	return &types.GetSecretValueResponse{
		ARN:           &secret.ARN,
		Name:          &secret.Name,
		VersionId:     &version.VersionId,
		SecretBinary:  version.SecretBinary,
		SecretString:  version.SecretString,
		VersionStages: versionStagesPtr,
		CreatedDate:   &version.CreatedDate,
	}, nil
}

// PutSecretValue creates a new version of a secret
// Implements PutSecretValue API - see AWS API Reference § PutSecretValue
//
//nolint:funlen // Complex version management
func (sm *SecretManager) PutSecretValue(req *types.PutSecretValueRequest) (*types.PutSecretValueResponse, error) {
	// Validate SecretId
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	if err := ValidateSecretId(req.SecretId); err != nil {
		return nil, err
	}

	// Validate secret value
	if err := ValidateSecretValue(req.SecretString, req.SecretBinary); err != nil {
		return nil, err
	}

	// Validate ClientRequestToken
	if err := ValidateClientRequestToken(req.ClientRequestToken); err != nil {
		return nil, err
	}

	// Validate RotationToken
	if err := ValidateRotationToken(req.RotationToken); err != nil {
		return nil, err
	}

	// Validate VersionStages
	if err := ValidateVersionStages(req.VersionStages); err != nil {
		return nil, err
	}

	// Get the secret
	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	// Check if secret is deleted
	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	// Check version quota
	if err := CheckVersionQuota(len(secret.Versions)); err != nil {
		return nil, err
	}

	// Generate version ID
	versionId := generateVersionID(req.ClientRequestToken)

	// Check for idempotency - if version with this ID already exists
	if existingVersion, exists := secret.Versions[versionId]; exists {
		// Check if secret values match (idempotent case)
		if secretValuesMatch(existingVersion, req.SecretString, req.SecretBinary) {
			// Idempotent request - return existing version
			versionStagesPtr := make([]*string, len(existingVersion.VersionStages))
			for i, stage := range existingVersion.VersionStages {
				s := stage
				versionStagesPtr[i] = &s
			}
			return &types.PutSecretValueResponse{
				ARN:           &secret.ARN,
				Name:          &secret.Name,
				VersionId:     &versionId,
				VersionStages: versionStagesPtr,
			}, nil
		}
		// Token matches but values differ - error
		return nil, &types.APIError{
			Type:    "ResourceExistsException",
			Message: "A version with the specified ClientRequestToken already exists but with different secret data",
		}
	}

	// Determine version stages for the new version
	versionStages := []string{VersionStageAWSCurrent}
	if len(req.VersionStages) > 0 {
		versionStages = make([]string, len(req.VersionStages))
		for i, stage := range req.VersionStages {
			versionStages[i] = *stage
		}
	}

	// Check staging label quota for new version
	if err := CheckStagingLabelQuota(len(versionStages)); err != nil {
		return nil, err
	}

	// Move AWSCURRENT from old version to new version
	if containsStage(versionStages, VersionStageAWSCurrent) {
		// Find the current version and move it to AWSPREVIOUS
		for oldVersionId, stages := range secret.VersionIdsToStages {
			if containsStage(stages, VersionStageAWSCurrent) && oldVersionId != versionId {
				// Remove AWSCURRENT from old version
				secret.VersionIdsToStages[oldVersionId] = removeStage(stages, VersionStageAWSCurrent)
				// Add AWSPREVIOUS to old version if not already present
				if !containsStage(secret.VersionIdsToStages[oldVersionId], VersionStageAWSPrevious) {
					secret.VersionIdsToStages[oldVersionId] = append(secret.VersionIdsToStages[oldVersionId], VersionStageAWSPrevious)
				}
				// Update the version object
				if oldVersion := secret.Versions[oldVersionId]; oldVersion != nil {
					oldVersion.VersionStages = secret.VersionIdsToStages[oldVersionId]
				}
			}
		}
	}

	// Create the new version
	now := types.NewUnixTime(time.Now())
	version := &types.SecretVersion{
		VersionId:     versionId,
		SecretString:  req.SecretString,
		SecretBinary:  req.SecretBinary,
		VersionStages: versionStages,
		CreatedDate:   *now,
	}

	secret.Versions[versionId] = version
	secret.VersionIdsToStages[versionId] = versionStages
	secret.LastChangedDate = now

	// Update the secret
	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to update secret: %v", err),
		}
	}

	// Convert version stages to response format
	versionStagesPtr := make([]*string, len(versionStages))
	for i, stage := range versionStages {
		s := stage
		versionStagesPtr[i] = &s
	}

	return &types.PutSecretValueResponse{
		ARN:           &secret.ARN,
		Name:          &secret.Name,
		VersionId:     &versionId,
		VersionStages: versionStagesPtr,
	}, nil
}

// UpdateSecret updates secret metadata or creates a new version
// Implements UpdateSecret API - see AWS API Reference § UpdateSecret
//
//nolint:funlen // Update with validation and versioning
func (sm *SecretManager) UpdateSecret(req *types.UpdateSecretRequest) (*types.UpdateSecretResponse, error) {
	// Validate input
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	// Get the secret
	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	// Check if secret is deleted
	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	now := types.NewUnixTime(time.Now())
	var newVersionId *string

	// Update metadata
	if req.Description != nil {
		secret.Description = req.Description
	}
	if req.KmsKeyId != nil {
		secret.KmsKeyId = req.KmsKeyId
	}

	// If secret value is provided, create a new version
	if req.SecretString != nil || req.SecretBinary != nil {
		versionId := generateVersionID(req.ClientRequestToken)
		newVersionId = &versionId

		// Move AWSCURRENT to AWSPREVIOUS
		for oldVersionId, stages := range secret.VersionIdsToStages {
			if containsStage(stages, VersionStageAWSCurrent) {
				secret.VersionIdsToStages[oldVersionId] = removeStage(stages, VersionStageAWSCurrent)
				if !containsStage(secret.VersionIdsToStages[oldVersionId], VersionStageAWSPrevious) {
					secret.VersionIdsToStages[oldVersionId] = append(secret.VersionIdsToStages[oldVersionId], VersionStageAWSPrevious)
				}
				if oldVersion := secret.Versions[oldVersionId]; oldVersion != nil {
					oldVersion.VersionStages = secret.VersionIdsToStages[oldVersionId]
				}
			}
		}

		// Create new version
		version := &types.SecretVersion{
			VersionId:     versionId,
			SecretString:  req.SecretString,
			SecretBinary:  req.SecretBinary,
			VersionStages: []string{VersionStageAWSCurrent},
			CreatedDate:   *now,
		}

		secret.Versions[versionId] = version
		secret.VersionIdsToStages[versionId] = []string{VersionStageAWSCurrent}
	}

	secret.LastChangedDate = now

	// Update the secret
	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to update secret: %v", err),
		}
	}

	return &types.UpdateSecretResponse{
		ARN:       &secret.ARN,
		Name:      &secret.Name,
		VersionId: newVersionId,
	}, nil
}

// DeleteSecret marks a secret for deletion
// Implements DeleteSecret API - see AWS API Reference § DeleteSecret
//
//nolint:funlen // Delete with recovery window logic
func (sm *SecretManager) DeleteSecret(req *types.DeleteSecretRequest) (*types.DeleteSecretResponse, error) {
	// Validate input
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	// Validate deletion parameters
	if req.RecoveryWindowInDays != nil && req.ForceDeleteWithoutRecovery != nil && *req.ForceDeleteWithoutRecovery {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "You can't use ForceDeleteWithoutRecovery in conjunction with RecoveryWindowInDays",
		}
	}

	if req.RecoveryWindowInDays != nil && (*req.RecoveryWindowInDays < 7 || *req.RecoveryWindowInDays > 30) {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "RecoveryWindowInDays must be between 7 and 30",
		}
	}

	// Get the secret
	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	// Check if already deleted
	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	var deletionDate time.Time

	// Force delete immediately
	if req.ForceDeleteWithoutRecovery != nil && *req.ForceDeleteWithoutRecovery {
		if err := sm.storage.DeleteSecret(secret.Name); err != nil {
			return nil, &types.APIError{
				Type:    "InternalServiceError",
				Message: fmt.Sprintf("Failed to delete secret: %v", err),
			}
		}
		deletionDate = time.Now()
	} else {
		// Schedule deletion with recovery window
		recoveryWindow := int64(30) // default
		if req.RecoveryWindowInDays != nil {
			recoveryWindow = *req.RecoveryWindowInDays
		}

		deletionDate = time.Now().Add(time.Duration(recoveryWindow) * 24 * time.Hour)
		secret.DeletedDate = types.NewUnixTime(deletionDate)

		if err := sm.storage.UpdateSecret(secret); err != nil {
			return nil, &types.APIError{
				Type:    "InternalServiceError",
				Message: fmt.Sprintf("Failed to mark secret for deletion: %v", err),
			}
		}
	}

	return &types.DeleteSecretResponse{
		ARN:          &secret.ARN,
		Name:         &secret.Name,
		DeletionDate: types.NewUnixTime(deletionDate),
	}, nil
}

// DescribeSecret returns metadata about a secret
// Implements DescribeSecret API - see AWS API Reference § DescribeSecret
func (sm *SecretManager) DescribeSecret(req *types.DescribeSecretRequest) (*types.DescribeSecretResponse, error) {
	// Validate input
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	// Get the secret
	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	return &types.DescribeSecretResponse{
		ARN:                &secret.ARN,
		Name:               &secret.Name,
		Description:        secret.Description,
		KmsKeyId:           secret.KmsKeyId,
		RotationEnabled:    &secret.RotationEnabled,
		RotationLambdaARN:  secret.RotationLambdaARN,
		RotationRules:      secret.RotationRules,
		LastRotatedDate:    secret.LastRotatedDate,
		LastChangedDate:    secret.LastChangedDate,
		LastAccessedDate:   secret.LastAccessedDate,
		DeletedDate:        secret.DeletedDate,
		NextRotationDate:   secret.NextRotationDate,
		Tags:               secret.Tags,
		VersionIdsToStages: secret.VersionIdsToStages,
		OwningService:      secret.OwningService,
		CreatedDate:        secret.CreatedDate,
		PrimaryRegion:      secret.PrimaryRegion,
		ReplicationStatus:  secret.ReplicationStatus,
	}, nil
}

// ListSecrets returns a list of secrets
// Implements ListSecrets API - see AWS API Reference § ListSecrets
//
//nolint:funlen // List with pagination and filtering
func (sm *SecretManager) ListSecrets(req *types.ListSecretsRequest) (*types.ListSecretsResponse, error) {
	secrets, err := sm.storage.ListSecrets()
	if err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to list secrets: %v", err),
		}
	}

	// Filter secrets
	filteredSecrets := secrets

	// Apply IncludePlannedDeletion filter
	includePlannedDeletion := false
	if req.IncludePlannedDeletion != nil {
		includePlannedDeletion = *req.IncludePlannedDeletion
	}

	if !includePlannedDeletion {
		// Filter out deleted secrets
		var nonDeleted []*types.Secret
		for _, s := range filteredSecrets {
			if s.DeletedDate == nil {
				nonDeleted = append(nonDeleted, s)
			}
		}
		filteredSecrets = nonDeleted
	}

	// Apply custom filters
	if len(req.Filters) > 0 {
		filteredSecrets = applyFilters(filteredSecrets, req.Filters)
	}

	// Convert to list entry format
	secretList := make([]types.SecretListEntry, len(filteredSecrets))
	for i, secret := range filteredSecrets {
		secretList[i] = types.SecretListEntry{
			ARN:                    &secret.ARN,
			Name:                   &secret.Name,
			Description:            secret.Description,
			KmsKeyId:               secret.KmsKeyId,
			RotationEnabled:        &secret.RotationEnabled,
			RotationLambdaARN:      secret.RotationLambdaARN,
			RotationRules:          secret.RotationRules,
			LastRotatedDate:        secret.LastRotatedDate,
			LastChangedDate:        secret.LastChangedDate,
			LastAccessedDate:       secret.LastAccessedDate,
			DeletedDate:            secret.DeletedDate,
			NextRotationDate:       secret.NextRotationDate,
			Tags:                   secret.Tags,
			SecretVersionsToStages: secret.VersionIdsToStages,
			OwningService:          secret.OwningService,
			CreatedDate:            secret.CreatedDate,
			PrimaryRegion:          secret.PrimaryRegion,
		}
	}

	// Apply pagination (simple implementation)
	maxResults := 100
	if req.MaxResults != nil {
		maxResults = int(*req.MaxResults)
	}

	if len(secretList) > maxResults {
		secretList = secretList[:maxResults]
		// In a real implementation, we would generate a NextToken here
	}

	return &types.ListSecretsResponse{
		SecretList: secretList,
		NextToken:  nil, // Simplified: not implementing pagination tokens
	}, nil
}

// Helper functions

func generateARN(secretName string) string {
	// Generate a random suffix for the ARN (AWS adds a 6-character random string)
	suffix := uuid.New().String()[:6]
	return fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:%s-%s",
		DefaultRegion, DefaultAccountID, secretName, suffix)
}

func generateVersionID(clientRequestToken *string) string {
	if clientRequestToken != nil && *clientRequestToken != "" {
		return *clientRequestToken
	}
	return uuid.New().String()
}

func containsStage(stages []string, stage string) bool {
	for _, s := range stages {
		if s == stage {
			return true
		}
	}
	return false
}

func removeStage(stages []string, stage string) []string {
	result := make([]string, 0, len(stages))
	for _, s := range stages {
		if s != stage {
			result = append(result, s)
		}
	}
	return result
}

//nolint:funlen // Filter logic for multiple criteria
func applyFilters(secrets []*types.Secret, filters []types.Filter) []*types.Secret {
	var result []*types.Secret

	for _, secret := range secrets {
		matches := true
		for _, filter := range filters {
			if filter.Key == nil || len(filter.Values) == 0 {
				continue
			}

			filterMatches := false
			switch *filter.Key {
			case "name":
				for _, value := range filter.Values {
					if value != nil && strings.Contains(secret.Name, *value) {
						filterMatches = true
						break
					}
				}
			case "description":
				if secret.Description != nil {
					for _, value := range filter.Values {
						if value != nil && strings.Contains(*secret.Description, *value) {
							filterMatches = true
							break
						}
					}
				}
			case "tag-key":
				for _, tag := range secret.Tags {
					for _, value := range filter.Values {
						if value != nil && tag.Key != nil && *tag.Key == *value {
							filterMatches = true
							break
						}
					}
					if filterMatches {
						break
					}
				}
			case "tag-value":
				for _, tag := range secret.Tags {
					for _, value := range filter.Values {
						if value != nil && tag.Value != nil && *tag.Value == *value {
							filterMatches = true
							break
						}
					}
					if filterMatches {
						break
					}
				}
			default:
				// Unknown filter key, skip
				filterMatches = true
			}

			if !filterMatches {
				matches = false
				break
			}
		}

		if matches {
			result = append(result, secret)
		}
	}

	return result
}

// secretValuesMatch compares a version's secret value with provided values
func secretValuesMatch(version *types.SecretVersion, secretString *string, secretBinary []byte) bool {
	// Compare SecretString if provided
	if secretString != nil {
		if version.SecretString == nil {
			return false
		}
		return *version.SecretString == *secretString
	}

	// Compare SecretBinary if provided
	if secretBinary != nil {
		if version.SecretBinary == nil {
			return false
		}
		if len(version.SecretBinary) != len(secretBinary) {
			return false
		}
		for i := range secretBinary {
			if version.SecretBinary[i] != secretBinary[i] {
				return false
			}
		}
		return true
	}

	return false
}
