// Package core implements the core business logic for AWS Secrets Manager operations
package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/eunmann/secretstash/internal/types"
)

const (
	// ReplicationStatusInSync indicates replication is in sync
	ReplicationStatusInSync = "InSync"
)

// TagResource adds tags to a secret
// Implements TagResource API - see AWS API Reference § TagResource
func (sm *SecretManager) TagResource(req *types.TagResourceRequest) (*types.TagResourceResponse, error) {
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	if len(req.Tags) == 0 {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "At least one tag is required",
		}
	}

	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	// Initialize tags if nil
	if secret.Tags == nil {
		secret.Tags = []types.Tag{}
	}

	// Add or update tags
	for _, newTag := range req.Tags {
		found := false
		for i, existingTag := range secret.Tags {
			if existingTag.Key != nil && newTag.Key != nil && *existingTag.Key == *newTag.Key {
				// Update existing tag
				secret.Tags[i] = newTag
				found = true
				break
			}
		}
		if !found {
			// Add new tag
			secret.Tags = append(secret.Tags, newTag)
		}
	}

	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to update secret tags: %v", err),
		}
	}

	return &types.TagResourceResponse{}, nil
}

// UntagResource removes tags from a secret
// Implements UntagResource API - see AWS API Reference § UntagResource
func (sm *SecretManager) UntagResource(req *types.UntagResourceRequest) (*types.UntagResourceResponse, error) {
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	if len(req.TagKeys) == 0 {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "At least one tag key is required",
		}
	}

	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	// Remove tags
	var remainingTags []types.Tag
	for _, tag := range secret.Tags {
		shouldKeep := true
		for _, keyToRemove := range req.TagKeys {
			if tag.Key != nil && keyToRemove != nil && *tag.Key == *keyToRemove {
				shouldKeep = false
				break
			}
		}
		if shouldKeep {
			remainingTags = append(remainingTags, tag)
		}
	}

	secret.Tags = remainingTags

	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to update secret tags: %v", err),
		}
	}

	return &types.UntagResourceResponse{}, nil
}

// UpdateSecretVersionStage modifies the staging labels attached to a version
// Implements UpdateSecretVersionStage API - see AWS API Reference § UpdateSecretVersionStage
//
//nolint:funlen // Complex AWS API implementation
func (sm *SecretManager) UpdateSecretVersionStage(req *types.UpdateSecretVersionStageRequest) (*types.UpdateSecretVersionStageResponse, error) {
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	if req.VersionStage == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "VersionStage is required",
		}
	}

	// Validate that at least one of MoveToVersionId or RemoveFromVersionId is provided
	if req.MoveToVersionId == nil && req.RemoveFromVersionId == nil {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "You must specify either MoveToVersionId or RemoveFromVersionId",
		}
	}

	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	// Remove stage from version if specified
	if req.RemoveFromVersionId != nil {
		versionId := *req.RemoveFromVersionId
		if stages, exists := secret.VersionIdsToStages[versionId]; exists {
			secret.VersionIdsToStages[versionId] = removeStage(stages, req.VersionStage)
			if version := secret.Versions[versionId]; version != nil {
				version.VersionStages = secret.VersionIdsToStages[versionId]
			}
		}
	}

	// Move stage to version if specified
	if req.MoveToVersionId != nil {
		versionId := *req.MoveToVersionId

		// Check if version exists
		if _, exists := secret.Versions[versionId]; !exists {
			return nil, &types.APIError{
				Type:    "ResourceNotFoundException",
				Message: fmt.Sprintf("Version %s not found", versionId),
			}
		}

		// Remove stage from all versions first (if it's a unique stage like AWSCURRENT)
		for vid, stages := range secret.VersionIdsToStages {
			if containsStage(stages, req.VersionStage) {
				secret.VersionIdsToStages[vid] = removeStage(stages, req.VersionStage)
				if version := secret.Versions[vid]; version != nil {
					version.VersionStages = secret.VersionIdsToStages[vid]
				}
			}
		}

		// Add stage to target version
		if !containsStage(secret.VersionIdsToStages[versionId], req.VersionStage) {
			secret.VersionIdsToStages[versionId] = append(secret.VersionIdsToStages[versionId], req.VersionStage)
			if version := secret.Versions[versionId]; version != nil {
				version.VersionStages = secret.VersionIdsToStages[versionId]
			}
		}
	}

	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to update version stages: %v", err),
		}
	}

	return &types.UpdateSecretVersionStageResponse{
		ARN:  &secret.ARN,
		Name: &secret.Name,
	}, nil
}

// RotateSecret initiates rotation of a secret
// Implements RotateSecret API - see AWS API Reference § RotateSecret
//
//nolint:funlen // Complex AWS API implementation
func (sm *SecretManager) RotateSecret(req *types.RotateSecretRequest) (*types.RotateSecretResponse, error) {
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	if secret.DeletedDate != nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("You can't perform this operation on secret %s because it was marked for deletion.", secret.Name),
		}
	}

	// Update rotation configuration
	if req.RotationLambdaARN != nil {
		secret.RotationLambdaARN = req.RotationLambdaARN
		secret.RotationEnabled = true
	}

	if req.RotationRules != nil {
		secret.RotationRules = req.RotationRules
	}

	// Create a new AWSPENDING version (stubbed - no actual rotation logic)
	versionId := generateVersionID(req.ClientRequestToken)
	now := types.NewUnixTime(time.Now())

	// Find current version to duplicate
	var currentVersion *types.SecretVersion
	for vid, stages := range secret.VersionIdsToStages {
		if containsStage(stages, VersionStageAWSCurrent) {
			currentVersion = secret.Versions[vid]
			break
		}
	}

	if currentVersion != nil {
		// Create pending version (in real AWS, Lambda would populate this)
		pendingVersion := &types.SecretVersion{
			VersionId:     versionId,
			SecretString:  currentVersion.SecretString,
			SecretBinary:  currentVersion.SecretBinary,
			VersionStages: []string{VersionStageAWSPending},
			CreatedDate:   *now,
		}

		secret.Versions[versionId] = pendingVersion
		secret.VersionIdsToStages[versionId] = []string{VersionStageAWSPending}
	}

	secret.LastRotatedDate = now

	// Calculate next rotation date if rules are set
	if secret.RotationRules != nil && secret.RotationRules.AutomaticallyAfterDays != nil {
		nextRotation := types.NewUnixTime(now.Add(time.Duration(*secret.RotationRules.AutomaticallyAfterDays) * 24 * time.Hour))
		secret.NextRotationDate = nextRotation
	}

	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to rotate secret: %v", err),
		}
	}

	return &types.RotateSecretResponse{
		ARN:       &secret.ARN,
		Name:      &secret.Name,
		VersionId: &versionId,
	}, nil
}

// RestoreSecret restores a deleted secret
// Implements RestoreSecret API - see AWS API Reference § RestoreSecret
func (sm *SecretManager) RestoreSecret(req *types.RestoreSecretRequest) (*types.RestoreSecretResponse, error) {
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	if secret.DeletedDate == nil {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("Secret %s is not scheduled for deletion.", secret.Name),
		}
	}

	// Restore the secret
	secret.DeletedDate = nil

	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to restore secret: %v", err),
		}
	}

	return &types.RestoreSecretResponse{
		ARN:  &secret.ARN,
		Name: &secret.Name,
	}, nil
}

// GetRandomPassword generates a random password
// Implements GetRandomPassword API - see AWS API Reference § GetRandomPassword
//
//nolint:funlen // Password generation with multiple requirements
func (sm *SecretManager) GetRandomPassword(req *types.GetRandomPasswordRequest) (*types.GetRandomPasswordResponse, error) {
	// Validate PasswordLength
	if err := ValidatePasswordLength(req.PasswordLength); err != nil {
		return nil, err
	}

	// Validate ExcludeCharacters
	if err := ValidateExcludeCharacters(req.ExcludeCharacters); err != nil {
		return nil, err
	}

	// Validate password requirements aren't contradictory
	if err := ValidatePasswordRequirements(req.ExcludeNumbers, req.ExcludePunctuation, req.ExcludeUppercase, req.ExcludeLowercase); err != nil {
		return nil, err
	}

	// Default password length
	length := int64(32)
	if req.PasswordLength != nil {
		length = *req.PasswordLength
	}

	// Build character set
	var charset string
	includeUpper := req.ExcludeUppercase == nil || !*req.ExcludeUppercase
	includeLower := req.ExcludeLowercase == nil || !*req.ExcludeLowercase
	includeNumbers := req.ExcludeNumbers == nil || !*req.ExcludeNumbers
	includePunctuation := req.ExcludePunctuation == nil || !*req.ExcludePunctuation
	includeSpace := req.IncludeSpace != nil && *req.IncludeSpace

	if includeUpper {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if includeLower {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if includeNumbers {
		charset += "0123456789"
	}
	if includePunctuation {
		charset += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	}
	if includeSpace {
		charset += " "
	}

	// Remove excluded characters
	if req.ExcludeCharacters != nil && *req.ExcludeCharacters != "" {
		excludeMap := make(map[rune]bool)
		for _, ch := range *req.ExcludeCharacters {
			excludeMap[ch] = true
		}
		var filtered string
		for _, ch := range charset {
			if !excludeMap[ch] {
				filtered += string(ch)
			}
		}
		charset = filtered
	}

	if len(charset) == 0 {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "No valid characters available for password generation",
		}
	}

	// Generate password
	password := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range password {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return nil, &types.APIError{
				Type:    "InternalServiceError",
				Message: "Failed to generate random password",
			}
		}
		password[i] = charset[idx.Int64()]
	}

	// RequireEachIncludedType validation (simplified)
	// In a real implementation, we would ensure at least one character from each type
	// For simplicity, we'll just return the generated password without enforcement
	_ = req.RequireEachIncludedType // Note: Not enforced in this implementation

	passwordStr := string(password)
	return &types.GetRandomPasswordResponse{
		RandomPassword: &passwordStr,
	}, nil
}

// BatchGetSecretValue retrieves multiple secrets in a single call
// Implements BatchGetSecretValue API - see AWS API Reference § BatchGetSecretValue
//
//nolint:funlen // Batch operation with filtering logic
func (sm *SecretManager) BatchGetSecretValue(req *types.BatchGetSecretValueRequest) (*types.BatchGetSecretValueResponse, error) {
	var secretValues []types.SecretValueEntry
	var errors []types.APIError

	// Get secrets by ID list
	if req.SecretIdList != nil {
		for _, secretIdPtr := range req.SecretIdList {
			if secretIdPtr == nil {
				continue
			}
			secretId := *secretIdPtr

			// Try to get the secret value
			getReq := &types.GetSecretValueRequest{
				SecretId: secretId,
			}

			resp, err := sm.GetSecretValue(getReq)
			if err != nil {
				if apiErr, ok := err.(*types.APIError); ok {
					errors = append(errors, *apiErr)
				}
				continue
			}

			// Convert to SecretValueEntry
			entry := types.SecretValueEntry{
				ARN:          resp.ARN,
				Name:         resp.Name,
				VersionId:    resp.VersionId,
				SecretBinary: resp.SecretBinary,
				SecretString: resp.SecretString,
				CreatedDate:  resp.CreatedDate,
			}

			if resp.VersionStages != nil {
				entry.VersionStages = resp.VersionStages
			}

			secretValues = append(secretValues, entry)
		}
	}

	// Apply filters if provided
	if len(req.Filters) > 0 {
		secrets, err := sm.storage.ListSecrets()
		if err != nil {
			return nil, &types.APIError{
				Type:    "InternalServiceError",
				Message: fmt.Sprintf("Failed to list secrets: %v", err),
			}
		}

		filteredSecrets := applyFilters(secrets, req.Filters)

		for _, secret := range filteredSecrets {
			if secret.DeletedDate != nil {
				continue
			}

			// Get AWSCURRENT version
			var currentVersionId string
			for vid, stages := range secret.VersionIdsToStages {
				if containsStage(stages, VersionStageAWSCurrent) {
					currentVersionId = vid
					break
				}
			}

			if currentVersionId == "" {
				continue
			}

			version := secret.Versions[currentVersionId]
			if version == nil {
				continue
			}

			versionStages := make([]*string, len(version.VersionStages))
			for i, stage := range version.VersionStages {
				s := stage
				versionStages[i] = &s
			}

			entry := types.SecretValueEntry{
				ARN:           &secret.ARN,
				Name:          &secret.Name,
				VersionId:     &currentVersionId,
				SecretBinary:  version.SecretBinary,
				SecretString:  version.SecretString,
				VersionStages: versionStages,
				CreatedDate:   &version.CreatedDate,
			}

			secretValues = append(secretValues, entry)
		}
	}

	// Apply max results
	maxResults := 20
	if req.MaxResults != nil {
		maxResults = int(*req.MaxResults)
	}

	if len(secretValues) > maxResults {
		secretValues = secretValues[:maxResults]
	}

	return &types.BatchGetSecretValueResponse{
		SecretValues: secretValues,
		NextToken:    nil, // Simplified: not implementing pagination
		Errors:       errors,
	}, nil
}

// ReplicateSecretToRegions replicates a secret to additional regions (stubbed)
// Implements ReplicateSecretToRegions API - see AWS API Reference § ReplicateSecretToRegions
func (sm *SecretManager) ReplicateSecretToRegions(req *types.ReplicateSecretToRegionsRequest) (*types.ReplicateSecretToRegionsResponse, error) {
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	// Add replication status (stubbed)
	if secret.ReplicationStatus == nil {
		secret.ReplicationStatus = []types.ReplicationStatusType{}
	}

	for _, region := range req.AddReplicaRegions {
		status := ReplicationStatusInSync
		replicationEntry := types.ReplicationStatusType{
			Region:   region.Region,
			KmsKeyId: region.KmsKeyId,
			Status:   &status,
		}
		secret.ReplicationStatus = append(secret.ReplicationStatus, replicationEntry)
	}

	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to update replication status: %v", err),
		}
	}

	return &types.ReplicateSecretToRegionsResponse{
		ARN:               &secret.ARN,
		ReplicationStatus: secret.ReplicationStatus,
	}, nil
}

// RemoveRegionsFromReplication removes regions from replication (stubbed)
// Implements RemoveRegionsFromReplication API - see AWS API Reference § RemoveRegionsFromReplication
func (sm *SecretManager) RemoveRegionsFromReplication(req *types.RemoveRegionsFromReplicationRequest) (*types.RemoveRegionsFromReplicationResponse, error) {
	if req.SecretId == "" {
		return nil, &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SecretId is required",
		}
	}

	secret, err := sm.storage.GetSecret(req.SecretId)
	if err != nil {
		return nil, &types.APIError{
			Type:    "ResourceNotFoundException",
			Message: fmt.Sprintf("Secrets Manager can't find the specified secret: %s", req.SecretId),
		}
	}

	// Remove specified regions
	if secret.ReplicationStatus != nil {
		var remainingReplicas []types.ReplicationStatusType
		for _, replica := range secret.ReplicationStatus {
			shouldRemove := false
			for _, regionToRemove := range req.RemoveReplicaRegions {
				if replica.Region != nil && regionToRemove != nil && *replica.Region == *regionToRemove {
					shouldRemove = true
					break
				}
			}
			if !shouldRemove {
				remainingReplicas = append(remainingReplicas, replica)
			}
		}
		secret.ReplicationStatus = remainingReplicas
	}

	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to update replication status: %v", err),
		}
	}

	return &types.RemoveRegionsFromReplicationResponse{
		ARN:               &secret.ARN,
		ReplicationStatus: secret.ReplicationStatus,
	}, nil
}

// CancelRotateSecret cancels an in-progress rotation
// Implements CancelRotateSecret API - see AWS API Reference § CancelRotateSecret
func (sm *SecretManager) CancelRotateSecret(req *types.CancelRotateSecretRequest) (*types.CancelRotateSecretResponse, error) {
	// Validate SecretId
	if err := ValidateSecretId(req.SecretId); err != nil {
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

	// Find version with AWSPENDING stage
	var pendingVersionId string
	for versionId, stages := range secret.VersionIdsToStages {
		if containsStage(stages, VersionStageAWSPending) {
			pendingVersionId = versionId
			break
		}
	}

	// If no AWSPENDING version found, rotation is not in progress
	if pendingVersionId == "" {
		return nil, &types.APIError{
			Type:    "InvalidRequestException",
			Message: fmt.Sprintf("A rotation is not currently in progress for the specified secret %s", secret.Name),
		}
	}

	// Remove AWSPENDING staging label from the version
	secret.VersionIdsToStages[pendingVersionId] = removeStage(
		secret.VersionIdsToStages[pendingVersionId],
		VersionStageAWSPending,
	)

	// Update version's VersionStages
	if version := secret.Versions[pendingVersionId]; version != nil {
		version.VersionStages = secret.VersionIdsToStages[pendingVersionId]
	}

	// If the version has no more staging labels, it becomes deprecated
	// We don't delete it, just leave it without labels

	// Turn off automatic rotation
	secret.RotationEnabled = false

	// Update the secret
	if err := sm.storage.UpdateSecret(secret); err != nil {
		return nil, &types.APIError{
			Type:    "InternalServiceError",
			Message: fmt.Sprintf("Failed to cancel rotation: %v", err),
		}
	}

	return &types.CancelRotateSecretResponse{
		ARN:       &secret.ARN,
		Name:      &secret.Name,
		VersionId: &pendingVersionId,
	}, nil
}

// ListSecretVersionIds lists all versions of a secret
// Implements ListSecretVersionIds API - see AWS API Reference § ListSecretVersionIds
//
//nolint:funlen // List operation with pagination - reasonable complexity
func (sm *SecretManager) ListSecretVersionIds(req *types.ListSecretVersionIdsRequest) (*types.ListSecretVersionIdsResponse, error) {
	// Validate SecretId
	if err := ValidateSecretId(req.SecretId); err != nil {
		return nil, err
	}

	// Validate MaxResults
	if err := ValidateMaxResults(req.MaxResults); err != nil {
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

	// Build list of versions
	versions := make([]types.SecretVersionsListEntry, 0, len(secret.Versions))

	for versionId, version := range secret.Versions {
		// Check if version has any staging labels (not deprecated)
		stages := secret.VersionIdsToStages[versionId]
		isDeprecated := len(stages) == 0

		// Skip deprecated versions unless IncludeDeprecated is true
		includeDeprecated := req.IncludeDeprecated != nil && *req.IncludeDeprecated
		if isDeprecated && !includeDeprecated {
			continue
		}

		// Convert staging labels to pointer array
		var versionStages []*string
		for _, stage := range stages {
			s := stage
			versionStages = append(versionStages, &s)
		}

		// Convert KmsKeyIds to pointer array
		var kmsKeyIds []*string
		for _, keyId := range version.KmsKeyIds {
			k := keyId
			kmsKeyIds = append(kmsKeyIds, &k)
		}

		entry := types.SecretVersionsListEntry{
			VersionId:        &versionId,
			VersionStages:    versionStages,
			CreatedDate:      &version.CreatedDate,
			LastAccessedDate: version.LastAccessedDate,
			KmsKeyIds:        kmsKeyIds,
		}

		versions = append(versions, entry)
	}

	// Sort versions by CreatedDate (newest first)
	// AWS returns versions in reverse chronological order
	for i := 0; i < len(versions)-1; i++ {
		for j := i + 1; j < len(versions); j++ {
			if versions[i].CreatedDate.Before(versions[j].CreatedDate.Time) {
				versions[i], versions[j] = versions[j], versions[i]
			}
		}
	}

	// Apply pagination
	maxResults := 100 // Default max
	if req.MaxResults != nil {
		maxResults = int(*req.MaxResults)
	}

	// For simplicity, we're not implementing proper NextToken pagination yet
	// This will be enhanced in Phase 1.2
	var nextToken *string
	if len(versions) > maxResults {
		versions = versions[:maxResults]
		// TODO: Implement proper NextToken generation
		token := "simplified-next-token" //nolint:gosec // G101: False positive
		nextToken = &token
	}

	return &types.ListSecretVersionIdsResponse{
		Versions:  versions,
		NextToken: nextToken,
		ARN:       &secret.ARN,
		Name:      &secret.Name,
	}, nil
}
