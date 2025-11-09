package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/eunmann/secretstash/internal/types"
)

// AWS Secrets Manager constraints as per API specification

const (
	// Name constraints
	MinSecretNameLength = 1
	MaxSecretNameLength = 512
	SecretNamePattern   = `^[a-zA-Z0-9/_+=.@-]+$` //nolint:gosec // G101: Pattern not credential

	// Description constraints
	MaxDescriptionLength = 2048

	// KmsKeyId constraints
	MaxKmsKeyIdLength = 2048

	// Secret value constraints
	MinSecretValueLength = 1
	MaxSecretValueLength = 65536

	// ClientRequestToken constraints
	MinClientRequestTokenLength = 32
	MaxClientRequestTokenLength = 64

	// RotationToken constraints
	MinRotationTokenLength = 36
	MaxRotationTokenLength = 256
	RotationTokenPattern   = `^[a-zA-Z0-9\-]+$` //nolint:gosec // G101: Pattern not credential

	// Version constraints
	MaxVersionsPerSecret       = 100
	VersionRetentionHours      = 24
	MaxStagingLabelsPerVersion = 20
	MinVersionStageLength      = 1
	MaxVersionStageLength      = 256

	// VersionId constraints
	MinVersionIdLength = 32
	MaxVersionIdLength = 64

	// SecretId (ARN or name) constraints
	MinSecretIdLength = 1
	MaxSecretIdLength = 2048

	// Password constraints
	MinPasswordLength          = 4
	MaxPasswordLength          = 4096
	MaxExcludeCharactersLength = 4096

	// Pagination constraints
	MinMaxResults      = 1
	MaxMaxResults      = 100
	MaxNextTokenLength = 4096

	// Tag constraints
	MaxTagsPerSecret  = 50
	MaxTagKeyLength   = 128
	MaxTagValueLength = 256

	// Other constraints
	MaxOwningServiceLength = 128
	MaxPrimaryRegionLength = 128
	PrimaryRegionPattern   = `^([a-z]+-)+\d+$`

	// ARN constraints
	MinARNLength = 20
	MaxARNLength = 2048

	// Rotation constraints
	MinAutoMaticallyAfterDays  = 1
	MaxAutomaticallyAfterDays  = 1000
	MaxRotationLambdaARNLength = 2048

	// Recovery window constraints
	MinRecoveryWindowInDays = 7
	MaxRecoveryWindowInDays = 30
)

var (
	secretNameRegex = regexp.MustCompile(SecretNamePattern)
	// AWS reserves the pattern hyphen + exactly 6 alphanumeric characters at the end
	// This is used for AWS-generated suffixes, so we validate the pattern more strictly
	// Note: We're being conservative here - AWS documentation says this pattern is reserved
	// but in practice names like "test-secret" (with a word after hyphen) are typically allowed
	// secretNameSuffixRegex = regexp.MustCompile(`-[A-Za-z0-9]{6}$`) // Reserved for future use
	rotationTokenRegex = regexp.MustCompile(RotationTokenPattern)
	// primaryRegionRegex = regexp.MustCompile(PrimaryRegionPattern) // Reserved for future use
)

// ValidateSecretName validates the secret name according to AWS constraints
func ValidateSecretName(name string) error {
	if len(name) < MinSecretNameLength || len(name) > MaxSecretNameLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("Secret name must be between %d and %d characters", MinSecretNameLength, MaxSecretNameLength),
		}
	}

	if !secretNameRegex.MatchString(name) {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: "Secret name contains invalid characters. Only alphanumeric characters and /_+=.@- are allowed",
		}
	}

	// Note: AWS reserves names ending with hyphen + 6 random-looking characters for their generated suffixes
	// However, this validation is complex (needs to distinguish random suffixes from words like "secret")
	// For this local mock, we'll skip this validation to avoid false positives
	// In production AWS, names like "my-secret-a1b2c3" would be rejected, but "my-secret" is fine

	return nil
}

// ValidateDescription validates the description field
func ValidateDescription(description *string) error {
	if description != nil && len(*description) > MaxDescriptionLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("Description must not exceed %d characters", MaxDescriptionLength),
		}
	}
	return nil
}

// ValidateKmsKeyId validates the KMS key ID
func ValidateKmsKeyId(kmsKeyId *string) error {
	if kmsKeyId != nil && len(*kmsKeyId) > MaxKmsKeyIdLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("KmsKeyId must not exceed %d characters", MaxKmsKeyIdLength),
		}
	}
	return nil
}

// ValidateSecretValue validates secret string or binary
func ValidateSecretValue(secretString *string, secretBinary []byte) error {
	if secretString == nil && secretBinary == nil {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: "You must provide either SecretString or SecretBinary",
		}
	}

	if secretString != nil && secretBinary != nil {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: "You cannot provide both SecretString and SecretBinary",
		}
	}

	if secretString != nil {
		if len(*secretString) < MinSecretValueLength || len(*secretString) > MaxSecretValueLength {
			return &types.APIError{
				Type:    "InvalidParameterException",
				Message: fmt.Sprintf("SecretString must be between %d and %d bytes", MinSecretValueLength, MaxSecretValueLength),
			}
		}
	}

	if secretBinary != nil {
		if len(secretBinary) < MinSecretValueLength || len(secretBinary) > MaxSecretValueLength {
			return &types.APIError{
				Type:    "InvalidParameterException",
				Message: fmt.Sprintf("SecretBinary must be between %d and %d bytes", MinSecretValueLength, MaxSecretValueLength),
			}
		}
	}

	return nil
}

// ValidateClientRequestToken validates the client request token
func ValidateClientRequestToken(token *string) error {
	if token == nil {
		return nil
	}

	tokenLen := len(*token)
	if tokenLen < MinClientRequestTokenLength || tokenLen > MaxClientRequestTokenLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("ClientRequestToken must be between %d and %d characters", MinClientRequestTokenLength, MaxClientRequestTokenLength),
		}
	}

	return nil
}

// ValidateRotationToken validates the rotation token
func ValidateRotationToken(token *string) error {
	if token == nil {
		return nil
	}

	tokenLen := len(*token)
	if tokenLen < MinRotationTokenLength || tokenLen > MaxRotationTokenLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("RotationToken must be between %d and %d characters", MinRotationTokenLength, MaxRotationTokenLength),
		}
	}

	if !rotationTokenRegex.MatchString(*token) {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: "RotationToken must match pattern ^[a-zA-Z0-9\\-]+$",
		}
	}

	return nil
}

// ValidateVersionStages validates version stages array
func ValidateVersionStages(stages []*string) error {
	if len(stages) > MaxStagingLabelsPerVersion {
		return &types.APIError{
			Type:    "LimitExceededException",
			Message: fmt.Sprintf("A version can have at most %d staging labels", MaxStagingLabelsPerVersion),
		}
	}

	for _, stage := range stages {
		if stage == nil {
			continue
		}
		stageLen := len(*stage)
		if stageLen < MinVersionStageLength || stageLen > MaxVersionStageLength {
			return &types.APIError{
				Type:    "InvalidParameterException",
				Message: fmt.Sprintf("Version stage must be between %d and %d characters", MinVersionStageLength, MaxVersionStageLength),
			}
		}
	}

	return nil
}

// ValidateSecretId validates secret ID (name or ARN)
func ValidateSecretId(secretId string) error {
	if len(secretId) < MinSecretIdLength || len(secretId) > MaxSecretIdLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("SecretId must be between %d and %d characters", MinSecretIdLength, MaxSecretIdLength),
		}
	}
	return nil
}

// ValidateVersionId validates version ID
func ValidateVersionId(versionId *string) error {
	if versionId == nil {
		return nil
	}

	versionLen := len(*versionId)
	if versionLen < MinVersionIdLength || versionLen > MaxVersionIdLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("VersionId must be between %d and %d characters", MinVersionIdLength, MaxVersionIdLength),
		}
	}

	return nil
}

// ValidatePasswordLength validates password length for GetRandomPassword
func ValidatePasswordLength(length *int64) error {
	if length == nil {
		return nil
	}

	if *length < MinPasswordLength || *length > MaxPasswordLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("PasswordLength must be between %d and %d", MinPasswordLength, MaxPasswordLength),
		}
	}

	return nil
}

// ValidateExcludeCharacters validates exclude characters for GetRandomPassword
func ValidateExcludeCharacters(excludeChars *string) error {
	if excludeChars != nil && len(*excludeChars) > MaxExcludeCharactersLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("ExcludeCharacters must not exceed %d characters", MaxExcludeCharactersLength),
		}
	}
	return nil
}

// ValidatePasswordRequirements validates that password requirements are not contradictory
func ValidatePasswordRequirements(excludeNumbers, excludePunctuation, excludeUppercase, excludeLowercase *bool) error {
	// Check if all character types are excluded
	allExcluded := (excludeNumbers != nil && *excludeNumbers) &&
		(excludePunctuation != nil && *excludePunctuation) &&
		(excludeUppercase != nil && *excludeUppercase) &&
		(excludeLowercase != nil && *excludeLowercase)

	if allExcluded {
		return &types.APIError{
			Type:    "InvalidRequestException",
			Message: "Cannot exclude all character types. At least one character type must be included",
		}
	}

	return nil
}

// ValidateRecoveryWindow validates recovery window for DeleteSecret
func ValidateRecoveryWindow(recoveryWindow *int64, forceDelete *bool) error {
	if recoveryWindow != nil && forceDelete != nil && *forceDelete {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: "You cannot use ForceDeleteWithoutRecovery in conjunction with RecoveryWindowInDays",
		}
	}

	if recoveryWindow != nil {
		if *recoveryWindow < MinRecoveryWindowInDays || *recoveryWindow > MaxRecoveryWindowInDays {
			return &types.APIError{
				Type:    "InvalidParameterException",
				Message: fmt.Sprintf("RecoveryWindowInDays must be between %d and %d", MinRecoveryWindowInDays, MaxRecoveryWindowInDays),
			}
		}
	}

	return nil
}

// ValidateMaxResults validates max results for pagination
func ValidateMaxResults(maxResults *int32) error {
	if maxResults != nil {
		if *maxResults < MinMaxResults || *maxResults > MaxMaxResults {
			return &types.APIError{
				Type:    "InvalidParameterException",
				Message: fmt.Sprintf("MaxResults must be between %d and %d", MinMaxResults, MaxMaxResults),
			}
		}
	}
	return nil
}

// ValidateSortOrder validates sort order
func ValidateSortOrder(sortOrder *string) error {
	if sortOrder == nil {
		return nil
	}

	order := strings.ToLower(*sortOrder)
	if order != "asc" && order != "desc" {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: "SortOrder must be either 'asc' or 'desc'",
		}
	}

	return nil
}

// ValidateRotationLambdaARN validates rotation lambda ARN
func ValidateRotationLambdaARN(arn *string) error {
	if arn != nil && len(*arn) > MaxRotationLambdaARNLength {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("RotationLambdaARN must not exceed %d characters", MaxRotationLambdaARNLength),
		}
	}
	return nil
}

// ValidateAutomaticallyAfterDays validates rotation period
func ValidateAutomaticallyAfterDays(days *int64) error {
	if days == nil {
		return nil
	}

	if *days < MinAutoMaticallyAfterDays || *days > MaxAutomaticallyAfterDays {
		return &types.APIError{
			Type:    "InvalidParameterException",
			Message: fmt.Sprintf("AutomaticallyAfterDays must be between %d and %d", MinAutoMaticallyAfterDays, MaxAutomaticallyAfterDays),
		}
	}

	return nil
}

// ValidateTags validates tags array
func ValidateTags(tags []types.Tag) error {
	if len(tags) > MaxTagsPerSecret {
		return &types.APIError{
			Type:    "LimitExceededException",
			Message: fmt.Sprintf("A secret can have at most %d tags", MaxTagsPerSecret),
		}
	}

	for _, tag := range tags {
		if tag.Key != nil && len(*tag.Key) > MaxTagKeyLength {
			return &types.APIError{
				Type:    "InvalidParameterException",
				Message: fmt.Sprintf("Tag key must not exceed %d characters", MaxTagKeyLength),
			}
		}
		if tag.Value != nil && len(*tag.Value) > MaxTagValueLength {
			return &types.APIError{
				Type:    "InvalidParameterException",
				Message: fmt.Sprintf("Tag value must not exceed %d characters", MaxTagValueLength),
			}
		}
	}

	return nil
}

// CheckVersionQuota checks if adding a new version would exceed the quota
func CheckVersionQuota(versionCount int) error {
	if versionCount >= MaxVersionsPerSecret {
		return &types.APIError{
			Type:    "LimitExceededException",
			Message: fmt.Sprintf("You have reached the maximum of %d versions for this secret. Delete old versions before creating new ones", MaxVersionsPerSecret),
		}
	}
	return nil
}

// CheckStagingLabelQuota checks if version would exceed staging label limit
func CheckStagingLabelQuota(labelCount int) error {
	if labelCount > MaxStagingLabelsPerVersion {
		return &types.APIError{
			Type:    "LimitExceededException",
			Message: fmt.Sprintf("A version can have at most %d staging labels", MaxStagingLabelsPerVersion),
		}
	}
	return nil
}

// ValidateVersionIdAndStageCompatibility validates that VersionId and VersionStage refer to the same version
func ValidateVersionIdAndStageCompatibility(secret *types.Secret, versionId *string, versionStage *string) error {
	if versionId == nil || versionStage == nil {
		return nil // Only validate if both are provided
	}

	// Check if the specified version has the specified stage
	if stages, exists := secret.VersionIdsToStages[*versionId]; exists {
		for _, stage := range stages {
			if stage == *versionStage {
				return nil // Compatible
			}
		}
	}

	return &types.APIError{
		Type:    "InvalidParameterException",
		Message: "VersionId and VersionStage do not refer to the same version",
	}
}
